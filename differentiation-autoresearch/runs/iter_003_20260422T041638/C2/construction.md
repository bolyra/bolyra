# Construction

## 1. Statement of claim

Same agent accessing different RS instances produces cryptographically unlinkable authorizations even under an adversarial AS that (a) controls enrollment, (b) logs every issuance event, and (c) colludes with any strict subset of RS instances. Formally: no PPT adversary wins the IND-UNL-AS game (defined in §3) with advantage greater than negl(λ).

The baseline (OIDC PPID + RFC 8707 + DPoP + BBS+) fails because the AS observes every token issuance, including the target RS audience claim, enabling trivial cross-scope correlation from the AS issuance log alone.

## 2. Construction (gadgets, circuits, public/private inputs)

### Design principle

Decouple credential enrollment from scope-specific authorization. The AS enrolls an agent's credential commitment into the agent Merkle tree exactly once. All subsequent per-scope authorizations are computed locally by the agent using a new circuit — **ScopeIsolatedAuth** — that produces scope-bound nullifiers unlinkable across scopes. The AS is never contacted at authorization time and therefore learns nothing about which scopes the agent exercises.

### New circuit: ScopeIsolatedAuth (PLONK)

This circuit sits between the existing AgentPolicy (enrollment) and per-RS authorization. It re-proves Merkle membership but derives a scope-specific nullifier and a randomized authorization tag bound to an RS-issued challenge nonce.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentSecret` | F_p (251 bits) | Agent's long-term secret scalar |
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key |
| `permissionBitmask` | uint64 | Agent's enrolled permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiry |
| `merkleProofLength` | uint | Actual depth |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Sibling hashes |
| `epochSecret` | F_p | Per-epoch rotation secret (see §2.5) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., hash of RS URI) |
| `requiredScopeMask` | uint64 | Required permission bits for this RS |
| `currentTimestamp` | uint64 | Verifier-supplied current time |
| `challengeNonce` | F_p | RS-issued fresh challenge nonce (128-bit minimum entropy) |
| `epochRoot` | F_p | Epoch commitment root binding `epochSecret` to `agentSecret` |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history buffer) |
| `scopeNullifier` | F_p | `Poseidon2(scopeId, epochSecret)` — deterministic per (agent, scope, epoch), unlinkable across scopes |
| `authTag` | F_p | `Poseidon2(scopeNullifier, challengeNonce)` — bound to RS-issued challenge, proves liveness and prevents replay |

**Constraints (11 groups):**

1. **Secret range**: `Num2Bits(251)` on `agentSecret`, ensuring `agentSecret ∈ [0, 2^251)`.

2. **Credential commitment reconstruction**: `credCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.

3. **Merkle membership**: `BinaryMerkleRoot(20)` with `credCommitment` as leaf must produce `agentMerkleRoot`.

4. **Scope satisfaction**: For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.

5. **Cumulative bit encoding**:
   - `permBits[4] * (1 - permBits[3]) === 0`
   - `permBits[4] * (1 - permBits[2]) === 0`
   - `permBits[3] * (1 - permBits[2]) === 0`

6. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.

7. **Range checks**: `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.

8. **Epoch binding**: `epochRoot = Poseidon2(agentSecret, epochSecret)`. This constrains the epoch secret to be bound to the long-term agent secret — an adversary cannot fabricate an epoch secret without knowing the agent secret. The `epochRoot` is published at epoch rotation time and stored on-chain (see §2.5).

9. **Scope nullifier derivation**: `scopeNullifier = Poseidon2(scopeId, epochSecret)`. This is the critical unlinkability gadget. Using `epochSecret` rather than `agentSecret` directly enables forward secrecy: compromise of the current epoch secret does not reveal nullifiers from prior epochs.

10. **Auth tag derivation**: `authTag = Poseidon2(scopeNullifier, challengeNonce)`. The `challengeNonce` is RS-issued (see §2.4), binding the proof to a specific RS session and proving liveness. The RS can verify freshness because it generated the challenge.

11. **Epoch secret range**: `Num2Bits(251)` on `epochSecret`, ensuring `epochSecret ∈ [0, 2^251)`.

### Public signal layout (PLONK verifier, 8 signals)

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | `agentMerkleRoot` | Merkle root for enrollment verification |
| 1 | `scopeNullifier` | Per-scope replay detection |
| 2 | `authTag` | RS-challenge-bound presentation tag |
| 3 | `requiredScopeMask` | Required permission bits |
| 4 | `currentTimestamp` | Freshness bound |
| 5 | `scopeId` | Scope identifier |
| 6 | `challengeNonce` | RS-issued challenge (public input) |
| 7 | `epochRoot` | Epoch binding commitment |

### 2.1 Protocol flow (authorization, post-enrollment)

1. Agent has been previously enrolled via the standard AgentPolicy circuit (one-time, AS-visible).
2. Agent wants to access RS-A with `scopeId = Poseidon("https://rs-a.example/")`.
3. Agent sends a session initiation request to RS-A (no identity information included).
4. RS-A responds with `challengeNonce` — a 128-bit CSPRNG-generated value with a TTL of 30 seconds. RS-A stores `(challengeNonce, issuedAt)` in a short-lived cache.
5. Agent locally computes `scopeNullifier_A = Poseidon2(scopeId_A, epochSecret)` and generates a ScopeIsolatedAuth PLONK proof using the RS-issued `challengeNonce`.
6. Agent sends `(proof, publicSignals)` to RS-A. **No AS interaction occurs.**
7. RS-A verifies: (a) `challengeNonce` matches a pending challenge in its cache and has not expired, (b) PLONK proof validity, (c) `agentMerkleRoot` is in the on-chain root history buffer, (d) `scopeNullifier` is not in the scope-local revocation set, (e) `currentTimestamp` is within acceptable clock skew (±60s), (f) `epochRoot` is in the on-chain epoch root set.
8. RS-A accepts and deletes the challenge from its cache (single-use).

### 2.2 Minimum batch enrollment policy

To prevent Merkle root epoch de-anonymization (where a root update following a single enrollment reduces the anonymity set to 1), the on-chain registry MUST enforce a **minimum batch size** for root updates:

- **Batch threshold**: The registry accumulates enrollment insertions in a pending queue. A new Merkle root is published only when the queue contains ≥ `MIN_BATCH_SIZE` insertions (default: 16) OR when `MAX_BATCH_DELAY` (default: 24 hours) has elapsed since the last root update, whichever comes first.
- **Padding insertions**: If `MAX_BATCH_DELAY` elapses with fewer than `MIN_BATCH_SIZE` real enrollments, the registry inserts `MIN_BATCH_SIZE - queueLength` dummy commitments (random F_p elements with no corresponding secret) before computing the new root. Dummy commitments are indistinguishable from real ones in the tree.
- **Root history buffer**: The existing 30-entry circular buffer ensures proofs generated against a pre-update root remain valid during the batch window. Provers SHOULD use the most recent root but MAY use any root in the buffer.
- **Anonymity set guarantee**: Every `agentMerkleRoot` value corresponds to a tree containing at least `MIN_BATCH_SIZE` new insertions since the prior root, providing a minimum k-anonymity of 16 per epoch even in sparse deployments.

### 2.3 Revocation mechanism

Revocation must not create a cross-scope linkage oracle. Two revocation vectors exist:

**Scope-local revocation (RS-initiated):**
Each RS maintains a local set of revoked `scopeNullifier` values for its scope. When an RS revokes an agent, it adds the agent's `scopeNullifier` to its local revocation list. This is scope-contained: RS-A's revocation list for `scopeId_A` reveals nothing about the agent's `scopeNullifier_B` at RS-B.

- RS stores: `revokedNullifiers[scopeId] → Set<F_p>`
- Verification step 7d checks: `scopeNullifier ∉ revokedNullifiers[scopeId]`
- Propagation: Immediate (RS-local, no on-chain transaction required)

**Global revocation (operator-initiated, credential-level):**
When an operator revokes an agent's credential (e.g., compromised key), the operator publishes a **revocation commitment** on-chain:

```
revocationCommitment = Poseidon2(credCommitment, revocationNonce)
```

The `revocationNonce` is a fresh random value. The on-chain registry maintains a `revocationSet: Set<F_p>` of revocation commitments. A second circuit — **RevocationCheck** (PLONK, ~2,000 constraints) — is composed with ScopeIsolatedAuth:

**RevocationCheck additional constraints:**
- Private input: `revocationNonce` (known only to operator and agent)
- The prover computes `myRevCommitment = Poseidon2(credCommitment, revocationNonce)` using the `credCommitment` already constrained in ScopeIsolatedAuth.
- Public output: `revocationProof` — a boolean signal that is 1 if `myRevCommitment` is NOT in the on-chain `revocationSet` (implemented via non-membership proof in a sparse Merkle tree of revocations).

**Propagation latency SLA**: Global revocation takes effect within one Merkle root update cycle (≤ `MAX_BATCH_DELAY` = 24 hours). For emergency revocation, the registry exposes a `forceRevoke(revocationCommitment)` function callable by the operator that immediately adds the commitment to the revocation sparse Merkle tree, bypassing batch delays. RS instances MUST refresh the revocation root at least every 15 minutes.

**Privacy property**: The `revocationCommitment` is a hash of `(credCommitment, revocationNonce)`. The AS can see which commitments are revoked but cannot link a revocation commitment to a specific `scopeNullifier` without the `revocationNonce`. The operator knows both values but is the party initiating revocation — this is by design.

### 2.4 Challenge nonce protocol (blindingNonce replacement)

The prior construction used an agent-generated `blindingNonce` whose freshness was unverifiable by the RS. This is replaced by an RS-issued `challengeNonce`:

**RS challenge issuance:**
1. RS generates `challengeNonce` using a CSPRNG (MUST provide ≥ 128 bits of entropy; implementations SHOULD use the platform's secure random source — `/dev/urandom`, `crypto.getRandomValues`, or equivalent).
2. RS stores `(challengeNonce, issuedAt, TTL=30s)` in a short-lived cache.
3. RS sends `challengeNonce` to agent in the session initiation response.

**Agent proof generation:**
4. Agent uses the RS-issued `challengeNonce` as a public input to ScopeIsolatedAuth.
5. The `authTag = Poseidon2(scopeNullifier, challengeNonce)` is verifiably fresh because the RS knows it generated `challengeNonce` within the last 30 seconds.

**RS verification:**
6. RS checks that `challengeNonce` matches a pending entry in its cache.
7. RS deletes the cache entry after verification (single-use).
8. If no matching `challengeNonce` is found or TTL has expired, RS rejects the proof.

**Liveness guarantee**: Because the RS controls the `challengeNonce`, a pre-computed proof cannot be replayed — the agent must generate a fresh proof per RS session. This eliminates the need to trust the agent's local entropy source for freshness.

### 2.5 Epoch-based secret rotation (forward secrecy)

The agent's long-term `agentSecret` is never used directly in scope nullifier derivation. Instead, a per-epoch `epochSecret` provides forward secrecy and compromise recovery.

**Epoch lifecycle:**

1. **Epoch derivation**: `epochSecret_i = Poseidon2(agentSecret, epochIndex_i)` where `epochIndex_i` is a monotonically increasing counter. The agent stores only `agentSecret` and the current `epochIndex`.

2. **Epoch commitment**: At epoch rotation, the agent publishes `epochRoot_i = Poseidon2(agentSecret, epochSecret_i)` on-chain via a new `registerEpoch(epochRoot)` transaction. This transaction is batched with other agents' epoch rotations (same minimum batch policy as enrollment, §2.2) to prevent timing correlation.

3. **Epoch duration**: Epochs are bounded by `MAX_EPOCH_DURATION = 90 days`. The `expiryTimestamp` in the credential commitment provides the hard upper bound. Agents SHOULD rotate epochs every 30 days.

4. **On-chain epoch root set**: The registry maintains `epochRoots: mapping(F_p => bool)` — a set of valid epoch roots. RS verification (step 7f) checks that the proof's `epochRoot` output is in this set.

**Compromise recovery:**

If `epochSecret_i` is compromised (but `agentSecret` is not):
- The agent rotates to `epochSecret_{i+1}` by incrementing `epochIndex` and publishing a new `epochRoot`.
- The operator revokes the compromised epoch by adding `epochRoot_i` to an `expiredEpochs` set on-chain.
- All scope nullifiers derived from `epochSecret_i` become invalid at RS instances that refresh `expiredEpochs`.
- Scope nullifiers from prior epochs (`epochSecret_{i-1}`, etc.) remain unlinkable to the compromised epoch (Poseidon-PRF: knowing `epochSecret_i` does not help compute `epochSecret_{i-1}` without `agentSecret`).

If `agentSecret` is compromised:
- The operator performs a full re-enrollment: revokes the old credential commitment (§2.3 global revocation), generates a new `agentSecret'`, and enrolls a new credential commitment via AgentPolicy.
- The new agent identity is unlinkable to the old one (different `credCommitment`, different `epochSecret` values).
- This is the nuclear option — it invalidates all existing scope nullifiers across all RS instances.

### 2.6 Privacy-preserving audit mechanism (GLBA Reg P / NCUA Part 748 reconciliation)

GLBA Safeguards Rule and NCUA Part 748 require credit unions to maintain audit trails demonstrating that authorization decisions are traceable. This conflicts with cross-scope unlinkability unless the audit trail is itself privacy-preserving.

**Design: Encrypted per-scope audit logs with dual-control opening.**

1. **Per-authorization audit record**: At proof generation time, the agent computes an encrypted audit record:

   ```
   auditPayload = (scopeId, scopeNullifier, authTag, currentTimestamp, epochIndex)
   auditCiphertext = AES-256-GCM(auditKey, auditPayload)
   ```

   where `auditKey = Poseidon2(agentSecret, "audit")` (a domain-separated key derived from the agent secret). The `auditCiphertext` is stored locally by the agent and optionally escrowed to the credit union's audit vault.

2. **Dual-control opening**: The `auditKey` is split via 2-of-3 Shamir secret sharing among:
   - The agent operator (share 1)
   - The credit union's compliance officer (share 2)
   - An independent auditor or regulator (share 3)

   No single party can open audit records unilaterally. Opening requires cooperation of any 2 of 3 parties, providing:
   - **Routine audit**: Compliance officer + auditor reconstruct `auditKey`, decrypt records, verify authorization history.
   - **Incident response**: Operator + compliance officer reconstruct `auditKey` for rapid investigation.
   - **Regulatory examination**: Compliance officer + regulator reconstruct `auditKey` for examination.

3. **Audit proof of completeness**: The agent maintains a running Poseidon hash chain of all audit records:
   ```
   auditChainHead_n = Poseidon2(auditChainHead_{n-1}, Poseidon(auditPayload_n))
   ```
   The `auditChainHead` is published on-chain periodically (e.g., monthly). This enables auditors to verify that no records were deleted after the fact, without revealing the contents.

4. **Privacy property**: The audit mechanism does not weaken IND-UNL-AS security because:
   - Audit ciphertexts are AES-256-GCM encrypted — they reveal nothing without the `auditKey`.
   - The `auditKey` is derived from `agentSecret`, which is already the trust anchor.
   - Shamir shares are distributed to parties who already have regulatory authority to compel disclosure — the scheme merely formalizes the access control.
   - The on-chain `auditChainHead` is a hash — it reveals no scope or nullifier information.

### 2.7 Integration with existing Bolyra handshake

The ScopeIsolatedAuth circuit is used **after** the mutual handshake for per-RS authorization. The handshake establishes the session and delegation chain seed; ScopeIsolatedAuth proves per-RS authorization without further AS involvement. The `agentSecret` is derived deterministically from the agent's enrolled credential secret (e.g., `agentSecret = Poseidon2(operatorSecret, modelHash)`) and is committed to during enrollment but never revealed. The `epochSecret` (§2.5) is derived from `agentSecret` and binds all per-scope operations to a rotatable key.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- **The Authorization Server (AS)**: A sees the full enrollment log — every `credentialCommitment` inserted into the agent Merkle tree, every `epochRoot` published, including the timing and metadata of all on-chain transactions.
- **A strict subset of Resource Servers**: A colludes with up to `k-1` of `k` RS instances. A receives every `(proof, publicSignals)` tuple presented to the colluding RS instances, including `challengeNonce` values they issued.
- **Network observation**: A sees encrypted traffic metadata (timing, packet sizes) between the agent and all RS instances.
- **On-chain state**: A can read all public on-chain state (Merkle roots, epoch roots, revocation set, used nonces, audit chain heads).

The adversary A does NOT control:
- The agent's local computation environment (the agent's `agentSecret` and `epochSecret` are not leaked).
- At least one RS instance (otherwise the game is trivially won since A sees all scopes).

### IND-UNL-AS game definition (corrected)

The prior formulation was flawed: since `scopeId` is a public signal, an adversary trivially wins by reading which `scopeId` accompanies which proof. The correct game challenges the adversary to distinguish **same-agent vs. different-agent** proofs at **known, fixed scopes**.

```
Game IND-UNL-AS(λ, k):
  Setup:
    1. Challenger generates Bolyra system parameters (Merkle trees,
       verifier contracts, epoch root registry).
    2. Challenger enrolls n ≥ 2 agents into the agent Merkle tree
       in a single batch of size ≥ MIN_BATCH_SIZE.
       A sees all enrollment transactions.
    3. Challenger selects two challenge agents a₀, a₁ uniformly
       at random from the enrolled set.

  Query phase (polynomial-bounded):
    A may adaptively request:
    - Scope authorization proofs for any agent (including a₀, a₁)
      at any scopeId of A's choosing. Challenger returns
      (proof, publicSignals) for the requested (agent, scopeId).
    - Enrollment log queries (full AS view).
    - Epoch root publication events.
    Restriction: A may NOT request proofs for BOTH a₀ AND a₁ at
    the challenge scopeId s* (defined below).

  Challenge phase:
    1. A selects a challenge scope s*.
    2. Challenger picks b ←$ {0,1}.
    3. Challenger generates a ScopeIsolatedAuth proof π* for agent
       a_b at scope s*, using a fresh challengeNonce c* issued by
       a (simulated) honest RS.
    4. Challenger sends (π*, publicSignals*) to A.
       Note: publicSignals* contains scopeId = s*,
       scopeNullifier* = Poseidon2(s*, epochSecret_{a_b}),
       authTag* = Poseidon2(scopeNullifier*, c*), and
       agentMerkleRoot (shared by all agents in the batch).

  More queries:
    A may continue querying, subject to the same restriction.

  Guess:
    A outputs b' ∈ {0,1}.

  Advantage:
    Adv^{IND-UNL-AS}(A) = |Pr[b' = b] - 1/2|
```

**Winning condition**: A wins if `Adv(A) > negl(λ)` — i.e., A can determine whether the challenge proof was generated by a₀ or a₁ with non-negligible advantage.

**Why this formulation is correct**: The adversary knows which scope the proof is for (scopeId is public) and has full AS-side information. The challenge is whether the adversary can determine *which enrolled agent* produced the proof, given that:
- The `scopeNullifier` is pseudorandom (Poseidon-PRF keyed on `epochSecret`).
- The `authTag` is pseudorandom (Poseidon-PRF on the already-random nullifier).
- The `agentMerkleRoot` is shared across all agents in the batch.
- The PLONK proof is zero-knowledge (reveals nothing about private inputs).

**Why the query restriction is necessary**: If A could see proofs from both a₀ and a₁ at s*, A would learn both `scopeNullifier` values and could trivially match. The restriction models the real-world setting where an honest RS does not share its scope-local nullifier set with the AS.

### Side-channel extension

The game is parameterized by a timing oracle T:

- **T-none**: No timing information (pure cryptographic game).
- **T-batch**: Agent batches all scope authorizations into a single timing window (±δ). A sees only the batch, not individual proof generation times.
- **T-real**: A sees per-proof generation timestamps. Security degrades to computational indistinguishability of proof generation times (see §7 mitigation).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon-PRF**: Poseidon2, keyed on its second input, is a pseudorandom function. Formally: for any PPT distinguisher D, `|Pr[D(Poseidon2(x, k)) = 1] - Pr[D(R(x)) = 1]| < negl(λ)` where k is uniform over F_p and R is a truly random function.

2. **Knowledge soundness of PLONK**: The PLONK proving system (with universal SRS) satisfies knowledge soundness — from any accepting proof, a polynomial-time extractor can recover a valid witness.

3. **Collision resistance of Poseidon**: Finding `(x, x')` with `x ≠ x'` and `Poseidon(x) = Poseidon(x')` requires `Ω(2^{128})` work over F_p.

4. **DLP on Baby Jubjub**: Given `(Ax, Ay) = s * G` on Baby Jubjub, recovering `s` is infeasible for PPT adversaries.

5. **PLONK zero-knowledge**: PLONK proofs reveal no information about the witness beyond the truth of the statement. Formally, there exists a PPT simulator that, given only the public inputs/outputs, produces proofs computationally indistinguishable from real proofs.

### Reduction sketch

**Theorem**: If Poseidon-PRF and PLONK zero-knowledge hold, no PPT adversary wins IND-UNL-AS with non-negligible advantage in the T-none model.

**Proof sketch**:

1. **Hybrid 0 (Real game)**: A receives challenge proof π* for agent a_b at scope s*. The `scopeNullifier* = Poseidon2(s*, epochSecret_{a_b})` and `authTag* = Poseidon2(scopeNullifier*, c*)`.

2. **Hybrid 1**: Replace the PLONK proof π* with a simulated proof π̃* produced by the PLONK simulator on the same public inputs/outputs. By PLONK zero-knowledge, Hybrids 0 and 1 are computationally indistinguishable. After this step, A's view contains no information from private inputs except through the public outputs.

3. **Hybrid 2**: Replace `scopeNullifier* = Poseidon2(s*, epochSecret_{a_b})` with a uniformly random value `r* ∈ F_p`. By Poseidon-PRF keyed on `epochSecret_{a_b}`: the adversary has never queried a_b at s* (game restriction), so s* is a fresh input to the PRF. Hybrids 1 and 2 are indistinguishable by an amount bounded by `Adv_PRF(A')` for a PRF adversary A' that simulates the IND-UNL-AS game.

4. **Hybrid 3**: Replace `authTag* = Poseidon2(r*, c*)` with uniform `r'* ∈ F_p`. Since r* is already uniform (from Hybrid 2), this follows from Poseidon-PRF keyed on `r*`. Hybrids 2 and 3 are indistinguishable.

5. **Hybrid 3 analysis**: A's view of the challenge consists of:
   - A simulated PLONK proof (no witness information).
   - A uniformly random `scopeNullifier*`.
   - A uniformly random `authTag*`.
   - Public inputs `(s*, requiredScopeMask, currentTimestamp, c*, epochRoot)` — identical regardless of b.
   - `agentMerkleRoot` — shared by all agents in the batch.
   - `epochRoot_{a_b}` — see below.

6. **Epoch root distinguishability**: The `epochRoot = Poseidon2(agentSecret, epochSecret)` is a public signal. If A has seen `epochRoot_{a_0}` and `epochRoot_{a_1}` from the epoch registration phase, A could match the challenge proof's `epochRoot` to identify b. **Mitigation**: Epoch roots are published in batches (§2.2 policy applies to epoch registrations). The challenge epoch root must be from a batch containing both a₀ and a₁'s epoch roots. In the game, the Challenger ensures both a₀ and a₁ register their epoch roots in the same batch. Under this batching constraint, A sees both epoch roots but the challenge proof's `epochRoot` reveals b. **Resolution**: The circuit is modified so that `epochRoot` is verified via a Merkle inclusion proof against an **epoch Merkle tree** (analogous to the agent Merkle tree), and only the epoch Merkle root is a public output — not the individual `epochRoot`. This adds ~12,000 constraints (one additional `BinaryMerkleRoot(20)`) but makes `epochRoot` a private input, eliminating this distinguisher.

   **Updated constraint 8**: `epochRoot = Poseidon2(agentSecret, epochSecret)` is computed in-circuit. `epochRoot` is then proved to be a leaf in the epoch Merkle tree, and only `epochMerkleRoot` is output publicly. Both a₀ and a₁ are leaves in this tree.

7. With the epoch Merkle tree modification, Hybrid 3 gives A a view consisting entirely of simulated proofs, random public outputs, shared Merkle roots, and identical public inputs. A's advantage is 0.

8. **Total bound**: `Adv^{IND-UNL-AS}(A) ≤ Adv_{ZK}(A₁) + 2 · Adv_{PRF}(A₂) + negl(λ)`.

**Collusion resistance**: An RS receiving `scopeNullifier_A` cannot correlate it with `scopeNullifier_B` held by a colluding RS, even if both share with the AS. The PRF argument applies regardless of which subset of outputs A collects — each `Poseidon2(scopeId_i, epochSecret)` is independently pseudorandom for distinct `scopeId_i` values. The colluding AS contributes only enrollment-time data and epoch Merkle roots (shared among all agents in the batch).

**Forward secrecy**: Compromise of `epochSecret_i` reveals all scope nullifiers for epoch i but not for any other epoch. Epochs j ≠ i use `epochSecret_j = Poseidon2(agentSecret, epochIndex_j)`, which is pseudorandom given `epochSecret_i` alone (Poseidon-PRF keyed on `agentSecret`, and `epochIndex_j ≠ epochIndex_i`).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Agent enrollment | AgentPolicy circuit (PLONK) | §4.2 (Agent Proof Specification) |
| Scope nullifier: `Poseidon2(scopeId, epochSecret)` | Poseidon2 (same as human nullifier pattern) | §2 Terminology: Nullifier |
| Auth tag: `Poseidon2(scopeNullifier, challengeNonce)` | Poseidon2 (same as nonce binding pattern) | §2 Terminology: Nonce Binding |
| Epoch binding: `Poseidon2(agentSecret, epochSecret)` | Poseidon2 | Native Poseidon2 |
| Credential commitment: `Poseidon5(...)` | Poseidon5 | §2 Terminology: Credential Commitment |
| Merkle membership (agent tree) | BinaryMerkleRoot(20) with Poseidon2 node hash | §3.2: Lean Incremental Merkle Tree |
| Merkle membership (epoch tree) | BinaryMerkleRoot(20) with Poseidon2 node hash | §3.2: Lean Incremental Merkle Tree |
| Scope bit satisfaction | Bitwise AND constraint (identical to AgentPolicy §4.2 step 5) | AgentPolicy constraint 5 |
| Cumulative encoding | Tier implication constraints (identical to AgentPolicy §4.2 step 6) | AgentPolicy constraint 6 |
| Expiry enforcement | LessThan(64) (identical to AgentPolicy §4.2 step 7) | AgentPolicy constraint 7 |
| Proof system | PLONK with universal SRS (same as AgentPolicy) | §3.3: Proving Systems |
| Root history verification | 30-entry circular buffer (existing on-chain registry) | §3.1: Root History Buffer |
| Integration with handshake | Session nonce from mutual handshake; ScopeIsolatedAuth runs post-handshake | §4: Mutual Handshake Protocol |
| Revocation non-membership | Sparse Merkle tree with Poseidon2 node hash | Extension of §3.2 pattern |

**One new Merkle tree introduced** (epoch tree) using existing Bolyra Merkle primitives. All other components reuse existing Bolyra primitives. The core novelty remains the circuit topology — applying the human nullifier pattern to agent authorization with epoch-based forward secrecy and RS-issued challenge binding.

## 6. Circuit cost estimate

### Constraint breakdown (with epoch Merkle tree)

| Gadget | Constraints (approximate) |
|--------|--------------------------|
| `Num2Bits(251)` — agentSecret range | 251 |
| `Num2Bits(251)` — epochSecret range | 251 |
| `Poseidon5` — credential commitment | ~1,500 |
| `BinaryMerkleRoot(20)` — agent tree (20 × Poseidon2 + mux) | ~12,000 |
| `Poseidon2` — epoch binding (`epochRoot`) | ~600 |
| `BinaryMerkleRoot(20)` — epoch tree | ~12,000 |
| `Num2Bits(64)` × 3 — range checks (bitmask, expiry, timestamp) | 192 |
| Scope satisfaction — 64 bit multiplications | 64 |
| Cumulative encoding — 3 constraints | 3 |
| `LessThan(64)` — expiry check | ~130 |
| `Poseidon2` — scope nullifier | ~600 |
| `Poseidon2` — auth tag | ~600 |
| **Subtotal: ScopeIsolatedAuth** | **~28,200** |
| **RevocationCheck (optional composition)** | |
| `Poseidon2` — revocation commitment | ~600 |
| Sparse Merkle non-membership (depth 20) | ~13,000 |
| **Subtotal: RevocationCheck** | **~13,600** |
| **Grand total (with revocation)** | **~41,800** |
| **Grand total (without revocation)** | **~28,200** |

### Proving time target

- **PLONK (agent-generated, without revocation)**: ~28,200 constraints → **< 5 seconds** on commodity hardware (PLONK at ~5,000–6,000 constraints/second with WASM prover). Meets the PLONK agent target of < 5 seconds.
- **PLONK (with revocation)**: ~41,800 constraints → **< 8 seconds**. Exceeds the 5-second target. Mitigation: revocation check can be a separate proof verified independently, or the RS caches the revocation sparse Merkle root and checks non-membership off-circuit (at the cost of trusting the RS to perform the check). Recommended: compose only when the RS requires on-chain revocation verification; otherwise the RS checks its local `revokedNullifiers` set (§2.3).
- **Verification**: Single PLONK verification, ~2ms on-chain (one pairing check).
- **Proof size**: ~1 KB (standard PLONK proof).

### Comparison with existing Bolyra circuits

| Circuit | Constraints | Proving system | Target | Status |
|---------|-------------|---------------|--------|--------|
| HumanUniqueness | ~13,000 | Groth16 | < 15s | Existing |
| AgentPolicy | ~16,000 | PLONK | < 5s | Existing |
| Delegation | ~18,000 | PLONK | < 5s | Existing |
| **ScopeIsolatedAuth** | **~28,200** | **PLONK** | **< 5s** | **New** |
| **ScopeIsolatedAuth + RevocationCheck** | **~41,800** | **PLONK** | **< 8s** | **New (composed)** |

ScopeIsolatedAuth is larger than the prior estimate (~15,600) due to the addition of the epoch Merkle tree (~12,000 constraints) required to hide `epochRoot` as a private input. This is the cost of closing the epoch-root distinguishability gap identified in §4. The circuit remains within the PLONK agent target without revocation composition.

## 7. Concrete deployment scenario

### Stakeholder: State Employees' Credit Union (SECU), North Carolina

**Context**: SECU members use AI agents (financial advisors, payment bots) to interact with multiple resource servers — merchant payment processors, loan originators, and insurance providers. SECU operates the Authorization Server. Regulatory constraints:
- **GLBA Reg P**: SECU-as-AS must not learn which merchants a member's agent transacts with.
- **NCUA Part 748 / GLBA Safeguards Rule**: SECU must maintain auditable records demonstrating that authorization decisions are traceable for examination purposes.

**Deployment**:

1. **Enrollment (one-time, AS-visible)**: SECU enrolls each member agent's credential commitment into the agent Merkle tree via the standard AgentPolicy circuit, in batches of ≥ 16 (§2.2). SECU sees that the agent has permission bits `[payments, loans, insurance]` with an expiry of 90 days. This is the last time SECU observes the agent's authorization activity.

2. **Epoch registration (periodic, batched)**: Every 30 days, the agent computes a new `epochSecret` and publishes its `epochRoot` to the epoch Merkle tree, batched with other agents' rotations. SECU sees epoch root insertions but cannot link them to specific agents within the batch.

3. **Per-merchant authorization (AS-invisible)**: When the agent accesses Merchant RS-A (scope: `Poseidon("https://merchant-a.secu.org/")`):
   - Agent sends session initiation request to RS-A.
   - RS-A responds with `challengeNonce` (128-bit, 30s TTL).
   - Agent generates ScopeIsolatedAuth PLONK proof locally.
   - Agent sends `(proof, publicSignals)` to RS-A. SECU is not contacted.

4. **Cross-scope unlinkability**: If the same agent accesses Insurance RS-B (scope: `Poseidon("https://insurance-b.secu.org/")`), the `scopeNullifier_B = Poseidon2(scopeId_B, epochSecret)` is cryptographically independent of `scopeNullifier_A = Poseidon2(scopeId_A, epochSecret)`. Even if SECU colludes with Merchant RS-A:
   - SECU has: enrollment log (credential commitment, permission bits), epoch Merkle roots (shared across batch).
   - Merchant RS-A has: `scopeNullifier_A`, `authTag_A`, and `challengeNonce_A` it issued.
   - Neither party can compute `scopeNullifier_B` without `epochSecret` (Poseidon-PRF).
   - The `agentMerkleRoot` is shared by ≥ 16 agents; the `epochMerkleRoot` is shared similarly.
   - Correlation requires breaking Poseidon-PRF or compromising the agent's local environment.

5. **Replay detection within scope**: Merchant RS-A stores seen `scopeNullifier` values. If the same agent presents twice to RS-A, the nullifier matches (deterministic per epoch). RS-A enforces rate-limiting or replay rejection. This is scope-local.

6. **Timing side-channel mitigation**: The agent batches proof generation for all scopes within a configurable window (default: 500ms jitter + random delay ∈ [0, 2s]). Under the T-batch model, SECU observing network metadata sees a single burst, not individual per-RS proof generation events.

7. **Regulatory audit (GLBA Safeguards compliance)**: SECU's compliance officer holds Shamir share 2 of the agent's audit key (§2.6). During annual NCUA examination:
   - The examiner (share 3) and SECU compliance officer (share 2) reconstruct the audit key.
   - They decrypt the agent's audit log, verifying that all authorizations were for valid scopes with satisfied permission bits and unexpired credentials.
   - The audit chain head on-chain confirms log completeness.
   - At no point does SECU learn the audit contents unilaterally — the examiner's share is required.

8. **Revocation scenario**: If an agent's operator key is compromised, the operator publishes a `revocationCommitment` via `forceRevoke()`. Within 15 minutes (RS refresh interval), all RS instances reject proofs from the compromised credential. The agent re-enrolls with a new secret and credential commitment.

### Healthcare variant

**Stakeholder**: Kaiser Permanente (credential issuer for healthcare agents)

An agent delegated by a patient accesses Provider-A (primary care) and Provider-B (specialist referral). Kaiser-as-AS must not learn the referral network. ScopeIsolatedAuth applies identically — Kaiser enrolls the agent once; per-provider authorizations are local. Provider-A cannot link its interactions with the same agent's visits to Provider-B, even if both report back to Kaiser. HIPAA audit requirements are met via the dual-control audit mechanism (§2.6) with the patient's healthcare proxy holding share 1.

## 8. Why the baseline cannot match

The baseline's fundamental architectural constraint is that **every authorization requires AS participation at issuance time**. This is not a limitation of specific specs — it is structural to the OAuth 2.0 grant model:

| Property | Baseline (OIDC PPID + RFC 8707 + DPoP + BBS+) | ScopeIsolatedAuth |
|----------|------------------------------------------------|-------------------|
| AS sees which RS is accessed | **Yes** — AS signs audience-bound tokens per RS | **No** — agent generates proofs locally post-enrollment |
| AS can correlate cross-RS access | **Yes** — issuance log contains (agent_id, RS, timestamp) tuples | **No** — AS sees only enrollment and batched epoch rotations |
| Colluding AS+RS can de-anonymize | **Yes** — AS reverses PPID; DPoP proofs are AS-visible | **No** — colluding AS+RS sees enrollment + one scope's nullifier; cannot derive other scopes' nullifiers (Poseidon-PRF) |
| Formal IND-UNL-AS security | **No** — no spec defines this game; PPID is prose-level | **Yes** — reduction to Poseidon-PRF + PLONK ZK (§4), with corrected same-agent-vs-different-agent formulation |
| Nullifier separation per scope | **Impossible** — no OAuth primitive supports scope-bound unlinkable identifiers | **Native** — `Poseidon2(scopeId, epochSecret)` per scope |
| Forward secrecy on compromise | **Partial** — DPoP key rotation is per-session but AS-visible | **Yes** — epoch-based rotation; compromised epoch does not reveal prior/future epochs |
| Revocation without linkage oracle | **No** — token revocation requires AS to identify the token, creating a correlation event | **Yes** — revocation via `Poseidon2(credCommitment, revocationNonce)` with sparse Merkle non-membership; no scope information leaked |
| Anonymity set guarantees | **None** — PPID anonymity depends on sector assignment, not enforced | **Enforced** — minimum batch size of 16 per Merkle root epoch, with dummy padding |
| Side-channel treatment | **Silent** — no spec addresses timing correlation | **Parameterized** — T-batch model with configurable jitter |
| Proof of scope separation to RS | **None** — RS trusts AS policy claim | **Cryptographic** — PLONK proof that required bits are satisfied without revealing full bitmask |
| Regulatory audit compatibility | **Trivial** — AS has full logs (but this IS the privacy violation) | **Privacy-preserving** — encrypted audit logs with dual-control opening (§2.6) |
| Freshness verification by RS | **Partial** — DPoP `jti` is self-asserted by agent | **Strong** — RS-issued `challengeNonce` with 30s TTL; RS verifies its own challenge |

The core impossibility remains: in OAuth/OIDC, the AS is the token factory. Every token carries an audience claim the AS computed and signed. Removing the AS from the per-scope authorization path is not possible without abandoning the OAuth grant model. PPID hides the subject from RS-to-RS correlation, but the AS itself is the PPID issuer — it can trivially reverse any PPID it generated.

BBS+ addresses holder-to-verifier unlinkability but does not remove the issuer from the authorization path. The issuer still signs the credential containing the scope.

ScopeIsolatedAuth breaks this structural dependency: the AS enrolls the credential once (broad permission bitmask in Merkle tree), and all subsequent per-scope authorizations are computed locally by the agent. The epoch rotation mechanism provides forward secrecy without AS involvement. The RS-issued challenge nonce provides verifiable freshness without AS involvement. The minimum batch enrollment policy provides enforceable anonymity set guarantees. The dual-control audit mechanism satisfies regulatory obligations without weakening cryptographic unlinkability. The AS is architecturally excluded from the per-scope authorization path, making cross-scope correlation cryptographically infeasible rather than policy-dependent.
