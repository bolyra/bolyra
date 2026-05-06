# Construction

## 1. Statement of claim

Same agent accessing different RS instances produces cryptographically unlinkable authorizations even under an adversarial AS that (a) controls enrollment, (b) logs every issuance event, and (c) colludes with any strict subset of RS instances. Formally: no PPT adversary wins the IND-UNL-AS game (defined in §3) with advantage greater than negl(λ).

The baseline (OIDC PPID + RFC 8707 + DPoP + BBS+) fails because the AS observes every token issuance, including the target RS audience claim, enabling trivial cross-scope correlation from the AS issuance log alone.

## 2. Construction (gadgets, circuits, public/private inputs)

### Design principle

Decouple credential enrollment from scope-specific authorization. The AS enrolls an agent's credential commitment into the agent Merkle tree exactly once. All subsequent per-scope authorizations are computed locally by the agent using a new circuit — **ScopeIsolatedAuth** — that produces scope-bound nullifiers unlinkable across scopes. The AS is never contacted at authorization time and therefore learns nothing about which scopes the agent exercises.

### New circuit: ScopeIsolatedAuth (PLONK)

This circuit sits between the existing AgentPolicy (enrollment) and per-RS authorization. It re-proves Merkle membership but derives a scope-specific nullifier and a randomized authorization tag.

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
| `blindingNonce` | F_p | Fresh random value per proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., hash of RS URI) |
| `requiredScopeMask` | uint64 | Required permission bits for this RS |
| `currentTimestamp` | uint64 | Verifier-supplied current time |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history buffer) |
| `scopeNullifier` | F_p | `Poseidon2(scopeId, agentSecret)` — deterministic per (agent, scope), unlinkable across scopes |
| `authTag` | F_p | `Poseidon2(scopeNullifier, blindingNonce)` — randomized per-presentation, prevents RS-to-RS correlation on the nullifier itself |

**Constraints (9 groups):**

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

8. **Scope nullifier derivation**: `scopeNullifier = Poseidon2(scopeId, agentSecret)`. This is the critical unlinkability gadget — identical in structure to the human nullifier from HumanUniqueness, but keyed on the agent's secret.

9. **Auth tag derivation**: `authTag = Poseidon2(scopeNullifier, blindingNonce)`. The blinding nonce randomizes each presentation so that even within the same scope, two presentations to the same RS are unlinkable unless the RS checks the scope nullifier (which it does for replay detection within scope, but cannot use for cross-scope linkage).

### Public signal layout (PLONK verifier, 6 signals)

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | `agentMerkleRoot` | Merkle root for enrollment verification |
| 1 | `scopeNullifier` | Per-scope replay detection |
| 2 | `authTag` | Randomized per-presentation tag |
| 3 | `requiredScopeMask` | Required permission bits |
| 4 | `currentTimestamp` | Freshness bound |
| 5 | `scopeId` | Scope identifier |

### Protocol flow (authorization, post-enrollment)

1. Agent has been previously enrolled via the standard AgentPolicy circuit (one-time, AS-visible).
2. Agent wants to access RS-A with `scopeId = Poseidon("https://rs-a.example/")`.
3. Agent locally computes `scopeNullifier_A = Poseidon2(scopeId_A, agentSecret)` and generates a ScopeIsolatedAuth PLONK proof with a fresh `blindingNonce`.
4. Agent sends `(proof, publicSignals)` directly to RS-A. **No AS interaction occurs.**
5. RS-A verifies: (a) PLONK proof validity, (b) `agentMerkleRoot` is in the on-chain root history buffer, (c) `scopeNullifier` is not revoked/reused, (d) `currentTimestamp` is fresh.
6. RS-A accepts. It sees `scopeNullifier_A` and `authTag_A` — neither of which is linkable to `scopeNullifier_B` or `authTag_B` that the same agent presents to RS-B.

### Integration with existing Bolyra handshake

The ScopeIsolatedAuth circuit is used **after** the mutual handshake for per-RS authorization. The handshake establishes the session and delegation chain seed; ScopeIsolatedAuth proves per-RS authorization without further AS involvement. The `agentSecret` is derived deterministically from the agent's enrolled credential secret (e.g., `agentSecret = Poseidon2(operatorSecret, modelHash)`) and is committed to during enrollment but never revealed.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- **The Authorization Server (AS)**: A sees the full enrollment log — every `credentialCommitment` inserted into the agent Merkle tree, including the timing and metadata of enrollment transactions.
- **A strict subset of Resource Servers**: A colludes with up to `k-1` of `k` RS instances. A receives every `(proof, publicSignals)` tuple presented to the colluding RS instances.
- **Network observation**: A sees encrypted traffic metadata (timing, packet sizes) between the agent and all RS instances.

The adversary A does NOT control:
- The agent's local computation environment (the agent's secret is not leaked).
- At least one RS instance (otherwise the game is trivially won since A sees all scopes).

### IND-UNL-AS game definition

```
Game IND-UNL-AS(λ):
  Setup:
    1. Challenger generates Bolyra system parameters (Merkle trees, verifier contracts).
    2. Challenger enrolls n agents into the agent Merkle tree.
       A sees all enrollment transactions.
    3. Challenger selects a challenge agent a* uniformly at random.

  Challenge phase:
    1. Challenger picks two distinct scopes (scopeId_0, scopeId_1) and a bit b ←$ {0,1}.
    2. Challenger generates two ScopeIsolatedAuth proofs:
       - π_left  for a* accessing scopeId_b
       - π_right for a* accessing scopeId_(1-b)
    3. Challenger sends (π_left, scopeId_0) and (π_right, scopeId_1) to A.
       A also receives the full AS enrollment log.

  Guess:
    A outputs b' ∈ {0,1}.

  Advantage:
    Adv(A) = |Pr[b' = b] - 1/2|
```

**Winning condition**: A wins if `Adv(A) > negl(λ)` — i.e., A can determine which proof corresponds to which scope with non-negligible advantage.

### Side-channel extension

The game is parameterized by a timing oracle T that A may query:

- **T-none**: No timing information (pure cryptographic game).
- **T-batch**: Agent batches all scope authorizations into a single timing window (±δ). A sees only the batch, not individual proof generation times.
- **T-real**: A sees per-proof generation timestamps. Security degrades to computational indistinguishability of proof generation times (addressed in §7).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon-PRF**: Poseidon2, keyed on its second input, is a pseudorandom function. Formally: for any PPT distinguisher D, `|Pr[D(Poseidon2(x, k)) = 1] - Pr[D(R(x)) = 1]| < negl(λ)` where k is uniform and R is a random function.

2. **Knowledge soundness of PLONK**: The PLONK proving system (with universal SRS) satisfies knowledge soundness — from any valid proof, an extractor can recover a valid witness.

3. **Collision resistance of Poseidon**: Finding `(x, x')` with `x ≠ x'` and `Poseidon(x) = Poseidon(x')` requires `Ω(2^{128})` work over F_p.

4. **DLP on Baby Jubjub**: Given `(Ax, Ay) = s * G`, recovering `s` is infeasible.

### Reduction sketch

**Theorem**: If Poseidon-PRF holds, no PPT adversary wins IND-UNL-AS with non-negligible advantage in the T-none model.

**Proof sketch**:

1. **Hybrid 0**: Real game. A receives `(π_left, π_right)` for challenge agent a* on scopes `(scopeId_b, scopeId_{1-b})`.

2. **Hybrid 1**: Replace `scopeNullifier_0 = Poseidon2(scopeId_0, agentSecret*)` with a uniformly random value `r_0 ∈ F_p`. By Poseidon-PRF (keyed on `agentSecret*`), hybrids 0 and 1 are computationally indistinguishable. The `authTag_0 = Poseidon2(r_0, blindingNonce_0)` is then a function of a random input.

3. **Hybrid 2**: Similarly replace `scopeNullifier_1` with uniform `r_1`. Now both scope nullifiers are independent random values.

4. **Hybrid 3**: Replace both `authTag` values with uniform random values (follows from Poseidon-PRF on the now-random nullifier inputs).

5. In Hybrid 3, A's view consists of two PLONK proofs with uniformly random public outputs `(scopeNullifier, authTag)`. The proofs are zero-knowledge (PLONK ZK property), so they reveal nothing about private inputs. The public inputs `(scopeId_0, scopeId_1, requiredScopeMask, currentTimestamp)` are the same in both orderings. A's advantage is 0.

6. By the triangle inequality across hybrids: `Adv(A) ≤ 2 * Adv_PRF + negl_ZK(λ)`.

**Collusion resistance**: An RS receiving `scopeNullifier_A` cannot correlate it with `scopeNullifier_B` held by a colluding RS, even if both share with the AS. The PRF argument applies regardless of which subset of outputs A collects — each `Poseidon2(scopeId_i, agentSecret*)` is independently pseudorandom for distinct `scopeId_i` values.

**Replay within scope**: The `scopeNullifier` is deterministic per `(scopeId, agentSecret)`, enabling the RS to detect double-use within a scope. The `authTag` (blinded) provides presentation freshness without adding a linkage vector.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Agent enrollment | AgentPolicy circuit (PLONK) | §4.2 (Agent Proof Specification) |
| Scope nullifier: `Poseidon2(scopeId, agentSecret)` | Poseidon2 (same as human nullifier pattern) | §2 Terminology: Nullifier |
| Auth tag: `Poseidon2(scopeNullifier, blindingNonce)` | Poseidon2 (same as nonce binding pattern) | §2 Terminology: Nonce Binding |
| Credential commitment: `Poseidon5(...)` | Poseidon5 | §2 Terminology: Credential Commitment |
| Merkle membership | BinaryMerkleRoot(20) with Poseidon2 node hash | §3.2: Lean Incremental Merkle Tree |
| Scope bit satisfaction | Bitwise AND constraint (identical to AgentPolicy §4.2 step 5) | AgentPolicy constraint 5 |
| Cumulative encoding | Tier implication constraints (identical to AgentPolicy §4.2 step 6) | AgentPolicy constraint 6 |
| Expiry enforcement | LessThan(64) (identical to AgentPolicy §4.2 step 7) | AgentPolicy constraint 7 |
| Proof system | PLONK with universal SRS (same as AgentPolicy) | §3.3: Proving Systems |
| Root history verification | 30-entry circular buffer (existing on-chain registry) | §3.1: Root History Buffer |
| Integration with handshake | Session nonce from mutual handshake; ScopeIsolatedAuth runs post-handshake | §4: Mutual Handshake Protocol |

**No new primitives introduced.** ScopeIsolatedAuth reuses every Bolyra primitive; the only novelty is the circuit topology — applying the human nullifier pattern (`Poseidon2(scope, secret)`) to agent authorization and adding a blinding nonce for presentation freshness.

## 6. Circuit cost estimate

### Constraint breakdown

| Gadget | Constraints (approximate) |
|--------|--------------------------|
| `Num2Bits(251)` — secret range | 251 |
| `Poseidon5` — credential commitment | ~1,500 (5-input Poseidon, ~300/round × 5 full rounds) |
| `BinaryMerkleRoot(20)` — 20 levels × Poseidon2 + mux | ~12,000 (20 × ~600) |
| `Num2Bits(64)` × 3 — range checks on bitmask, expiry, timestamp | 192 |
| Scope satisfaction — 64 bit multiplications | 64 |
| Cumulative encoding — 3 constraints | 3 |
| `LessThan(64)` — expiry check | ~130 |
| `Poseidon2` — scope nullifier | ~600 |
| `Poseidon2` — auth tag | ~600 |
| `Num2Bits(251)` — agentSecret range | 251 |
| **Total** | **~15,600** |

### Proving time target

- **PLONK (agent-generated)**: ~15,600 constraints → **< 3 seconds** on commodity hardware (PLONK at ~5,000 constraints/second on modern CPUs with WASM prover). Well within the PLONK agent target of < 5 seconds.
- **Verification**: Single PLONK verification, ~2ms on-chain (one pairing check).
- **Proof size**: ~1 KB (standard PLONK proof).

### Comparison with existing Bolyra circuits

| Circuit | Constraints | Proving system | Target |
|---------|-------------|---------------|--------|
| HumanUniqueness | ~13,000 | Groth16 | < 15s |
| AgentPolicy | ~16,000 | PLONK | < 5s |
| Delegation | ~18,000 | PLONK | < 5s |
| **ScopeIsolatedAuth** | **~15,600** | **PLONK** | **< 3s** |

ScopeIsolatedAuth is smaller than AgentPolicy because it omits the EdDSA signature verification gadget (~2,500 constraints). The operator signature was already verified at enrollment; re-proving it per-scope is unnecessary.

## 7. Concrete deployment scenario

### Stakeholder: State Employees' Credit Union (SECU), North Carolina

**Context**: SECU members use AI agents (financial advisors, payment bots) to interact with multiple resource servers — merchant payment processors, loan originators, and insurance providers. SECU operates the Authorization Server. Regulatory requirement: SECU-as-AS must not learn which merchants a member's agent transacts with (GLBA financial privacy, Reg P).

**Deployment**:

1. **Enrollment (one-time, AS-visible)**: SECU enrolls each member agent's credential commitment into the agent Merkle tree via the standard AgentPolicy circuit. SECU sees the enrollment but learns only that the agent has permission bits `[payments, loans, insurance]` with an expiry. This is the last time SECU observes the agent's authorization activity.

2. **Per-merchant authorization (AS-invisible)**: When the agent accesses Merchant RS-A (scope: `Poseidon("https://merchant-a.secu.org/")`), it generates a ScopeIsolatedAuth proof locally. The proof is sent directly to RS-A. SECU is not contacted.

3. **Cross-scope unlinkability**: If the same agent accesses Insurance RS-B (scope: `Poseidon("https://insurance-b.secu.org/")`), the `scopeNullifier_B` is cryptographically independent of `scopeNullifier_A`. Even if SECU colludes with Merchant RS-A:
   - SECU has the enrollment log (credential commitment, permission bits) but no per-scope nullifiers.
   - Merchant RS-A has `scopeNullifier_A` and `authTag_A`.
   - Neither party can compute `scopeNullifier_B` without `agentSecret` (Poseidon-PRF).
   - Correlation requires breaking Poseidon-PRF or compromising the agent's local environment.

4. **Replay detection within scope**: Merchant RS-A stores seen `scopeNullifier` values. If the same agent presents twice to RS-A, the nullifier matches and RS-A can enforce rate-limiting or replay rejection. This is scope-local and does not leak to other RS instances.

5. **Timing side-channel mitigation**: The agent batches proof generation for all scopes within a configurable window (default: 500ms jitter + random delay ∈ [0, 2s]). Under the T-batch model, SECU observing network metadata sees a single burst, not individual per-RS proof generation events.

### Healthcare variant

**Stakeholder**: Kaiser Permanente (credential issuer for healthcare agents)

An agent delegated by a patient accesses Provider-A (primary care) and Provider-B (specialist referral). Kaiser-as-AS must not learn the referral network. The ScopeIsolatedAuth construction applies identically — Kaiser enrolls the agent once; per-provider authorizations are local. Provider-A cannot link its interactions with the same agent's visits to Provider-B, even if both providers report back to Kaiser.

## 8. Why the baseline cannot match

The baseline's fundamental architectural constraint is that **every authorization requires AS participation at issuance time**. This is not a limitation of specific specs — it is structural to the OAuth 2.0 grant model:

| Property | Baseline (OIDC PPID + RFC 8707 + DPoP + BBS+) | ScopeIsolatedAuth |
|----------|------------------------------------------------|-------------------|
| AS sees which RS is accessed | **Yes** — AS signs audience-bound tokens per RS | **No** — agent generates proofs locally post-enrollment |
| AS can correlate cross-RS access | **Yes** — issuance log contains (agent_id, RS, timestamp) tuples | **No** — AS sees only the one-time enrollment event |
| Colluding AS+RS can de-anonymize | **Yes** — AS can reverse-map PPID; DPoP proofs are AS-visible | **No** — colluding AS+RS sees enrollment + one scope's nullifier; cannot derive other scopes' nullifiers (Poseidon-PRF) |
| Formal IND-UNL-AS security | **No** — no spec defines this game; PPID is prose-level | **Yes** — reduction to Poseidon-PRF + PLONK ZK (§4) |
| Nullifier separation per scope | **Impossible** — no OAuth primitive supports scope-bound unlinkable identifiers | **Native** — `Poseidon2(scopeId, agentSecret)` per scope |
| Side-channel treatment | **Silent** — no spec addresses timing correlation | **Parameterized** — T-batch model with configurable jitter |
| Proof of scope separation to RS | **None** — RS trusts AS policy claim (introspection filtering) | **Cryptographic** — PLONK proof that required bits are satisfied without revealing full bitmask |

The core impossibility: in OAuth/OIDC, the AS is the token factory. Every token carries an audience claim that the AS computed and signed. Removing the AS from the per-scope authorization path is not possible without abandoning the OAuth grant model entirely. PPID hides the subject from RS-to-RS correlation, but the AS itself is the PPID issuer — it can trivially reverse any PPID it generated.

BBS+ addresses holder-to-verifier unlinkability but does not remove the issuer from the authorization path. The issuer (AS) still signs the credential containing the scope. BBS+ selective disclosure hides attributes from verifiers, not from issuers.

ScopeIsolatedAuth breaks this structural dependency: the AS enrolls the credential once (broad permission bitmask in Merkle tree), and all subsequent per-scope authorizations are computed locally by the agent using a ZK proof of Merkle membership and scope satisfaction. The AS is architecturally excluded from the per-scope authorization path, making cross-scope correlation cryptographically infeasible rather than policy-dependent.
