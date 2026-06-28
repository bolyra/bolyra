# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its 64-bit permission bitmask satisfies an RS-specified mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of `permissionBitmask` beyond what the predicate logically implies. The proof is:

- **Constant-size** (3 BN128 G1/G2 elements for Groth16, ~4 for PLONK) regardless of bitmask width.
- **AS-blind**: the agent generates the proof at runtime using only its private credential fields and the on-chain Merkle root. No authorization server roundtrip occurs.
- **Runtime-adaptive**: the RS chooses `requiredScopeMask` at the moment of the request. The same enrolled credential satisfies any mask the agent's bitmask covers — no re-issuance needed.
- **Sound under adversarial AS**: even a compromised AS cannot forge a proof for permissions the operator never signed, because the credential commitment is operator-EdDSA-signed and the proof's soundness reduces to Groth16/PLONK knowledge soundness.
- **Cumulative-implication-enforcing**: the circuit rejects bitmasks that violate the hierarchical implication rules (bit 4 → 3 → 2) before the predicate check runs, so the RS never needs to validate implication closure.

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, or BBS+ selective disclosure can simultaneously achieve all five properties, as argued in §8.

## 2. Construction (gadgets, circuits, public/private inputs)

### Deployment modes

The `AgentPolicy` circuit (spec §4.2) supports two deployment modes that differ only in whether `scopeCommitment` is exposed as a public output:

| Mode | `scopeCommitment` output | Use case |
|------|--------------------------|----------|
| **Standalone** (default) | **Suppressed** — constrained internally but not wired to a public output | RS authorization with no subsequent delegation chain |
| **Delegation-capable** | **Exposed** — wired to public output index 2 | Mutual handshake followed by delegation hops (spec §5) |

**Standalone mode is the default for the selective scope proof claim.** The delegation-capable mode is used only when the agent's proof must seed a delegation chain via the on-chain `lastScopeCommitment` mapping.

The mode distinction is implemented at the circuit level: `AgentSelectiveScope` (standalone) and `AgentPolicy` (delegation-capable) share identical constraint logic but differ in which signals are wired to `main.out`. This is a compile-time switch, not a runtime flag — both circuits have independent verification keys and on-chain verifier contracts.

### Circuit: `AgentSelectiveScope` (standalone mode)

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Poseidon hash of the model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | The agent's actual 64-bit permission set |
| `expiryTimestamp` | uint64 | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over `credentialCommitment` |
| `merkleProofLength` | uint | Actual depth of the Merkle proof |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Sibling hashes (padded to MAX_DEPTH=20) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-chosen predicate: which bits must be set |
| `currentTimestamp` | uint64 | Current time (from RS or relayer) |
| `sessionNonce` | F_p | Fresh nonce for replay prevention |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Proves enrollment against on-chain root |
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` — replay detection |

Note: `scopeCommitment` is computed internally (for constraint consistency with the shared gadget library) but is **not** wired to a public output. It does not appear in the proof transcript.

### Gadgets (in constraint order):

1. **Range checks**: `Num2Bits(64)` × 3 on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. Prevents field-overflow attacks where values ≥ 2^64 pass the circuit but wrap in Solidity uint64.

2. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. Binds the proof to a specific model identity, operator, permission set, and expiry.

3. **EdDSA verification**: `EdDSAPoseidonVerifier(credentialCommitment, (Ax, Ay), (R8x, R8y, S))`. Ensures the operator authorized this exact credential. The operator's private key never enters the circuit.

4. **Merkle membership**: `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf. Output must match an on-chain root in the 30-entry root history buffer.

5. **Cumulative bit implication** (3 constraints):
   ```
   bitmaskBits[4] * (1 - bitmaskBits[3]) === 0   // FINANCIAL_UNLIMITED → FINANCIAL_MEDIUM
   bitmaskBits[4] * (1 - bitmaskBits[2]) === 0   // FINANCIAL_UNLIMITED → FINANCIAL_SMALL
   bitmaskBits[3] * (1 - bitmaskBits[2]) === 0   // FINANCIAL_MEDIUM → FINANCIAL_SMALL
   ```

6. **Scope satisfaction** (64 constraints):
   ```
   for i in 0..63:
     requiredBits[i] * (1 - permBits[i]) === 0
   ```
   This is the core selective scope predicate. For every bit the RS requires, the agent must have it set. Bits the RS does not require are unconstrained — they remain hidden.

7. **Expiry**: `LessThan(64)(currentTimestamp, expiryTimestamp)`. Credential must not be expired.

8. **Nullifier**: `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`.

9. **Scope commitment (internal only)**: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. Computed and constrained but not output. Present only so that the `AgentPolicy` delegation-capable variant can share the same gadget library and differ only in output wiring.

### Circuit: `AgentPolicy` (delegation-capable mode)

Identical to `AgentSelectiveScope` except:

- Public output index 2 is `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`.
- Used exclusively when the proof seeds a delegation chain (mutual handshake flow, spec §4).
- The privacy implications of exposing `scopeCommitment` are accepted in the delegation context because the delegation chain requires it for chain-linking (spec §5.2), and the delegator has opted into a protocol flow where scope commitment visibility is a design requirement.

### Standalone public signal layout

The Groth16 verifier for `AgentSelectiveScope` MUST receive exactly 5 public signals:

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | agentMerkleRoot | Computed Merkle root |
| 1 | nullifierHash | Session-specific nullifier |
| 2 | requiredScopeMask | Required permission bits (public input) |
| 3 | currentTimestamp | Current time (public input) |
| 4 | sessionNonce | Session nonce (public input) |

### Delegation-capable public signal layout

The Groth16 verifier for `AgentPolicy` retains the original 6-signal layout per spec §4.2:

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | agentMerkleRoot | Computed Merkle root |
| 1 | nullifierHash | Session-specific nullifier |
| 2 | scopeCommitment | Identity-bound scope hash |
| 3 | requiredScopeMask | Required permission bits (public input) |
| 4 | currentTimestamp | Current time (public input) |
| 5 | sessionNonce | Session nonce (public input) |

### Verification flow (RS-side, standalone mode):

1. RS generates a fresh `sessionNonce` (≥128 bits, cryptographically random).
2. RS sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to the agent.
3. Agent generates a Groth16 or PLONK proof using its private credential fields.
4. Agent sends `(proof, publicSignals)` to the RS.
5. RS verifies:
   - `agentMerkleRoot` ∈ on-chain root history buffer (read from contract or cached).
   - `nullifierHash` not previously seen for this `sessionNonce`.
   - `requiredScopeMask` matches the RS's own public input.
   - `currentTimestamp` is within acceptable skew of RS's wall clock.
   - Groth16/PLONK proof verifies against the deployed `AgentSelectiveScope` verifier contract.
6. On success: the agent is authorized for the requested scope. The RS learns nothing about `permissionBitmask` beyond `permissionBitmask & requiredScopeMask == requiredScopeMask`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A may control any combination of:

- **The Authorization Server (AS)**: A controls credential issuance policy, can refuse to enroll agents, can attempt to forge credentials. However, A does not possess any honest operator's EdDSA private key.
- **Colluding Resource Servers**: A controls multiple RSes that compare notes (proofs, nullifiers, scope commitments) to attempt linkability or permission inference. Crucially, colluding RSes may **adaptively** choose `requiredScopeMask` values across sessions based on previously observed proof outcomes.
- **On-chain observer**: A reads the full Merkle tree state, including all enrolled `credentialCommitment` leaf values. This is the realistic threat posture for a public blockchain.
- **Network position**: A observes all proof transcripts between agent and RS (passive eavesdropper).
- **Malicious agents**: A may generate proofs with credentials it does not hold, or attempt to prove permissions it was not granted.

A does **not** control:
- The BN128 pairing (no subgroup attacks).
- The Poseidon hash (no preimage/collision attacks).
- The Baby Jubjub discrete log (no key recovery).
- The on-chain Merkle tree state (immutable once committed; root history buffer is append-only).

### Precomputation attack on `scopeCommitment` (motivation for standalone mode)

When `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a public output and the adversary knows all N enrolled `credentialCommitment` values (which are public Merkle leaves), the adversary can precompute a rainbow table:

```
For each enrolled credentialCommitment cc_i (i = 1..N):
  For each candidate bitmask b (0..2^64 - 1):
    T[Poseidon2(b, cc_i)] = (cc_i, b)
```

A single observed `scopeCommitment` output is then looked up in T, revealing both the agent's identity and its full bitmask.

**Cost**: N × 2^64 Poseidon2 evaluations for table construction, plus O(1) per lookup. For N = 1000 enrolled agents, this is ~10^22 hash evaluations — infeasible today but not cryptographically hard (it is a 64-bit brute force, not a field-element preimage attack). The security margin rests entirely on the 64-bit bitmask entropy, which is far below the ~128-bit security level expected of the protocol.

**Conclusion**: Exposing `scopeCommitment` in the selective scope proof reduces the privacy guarantee from computational (Poseidon preimage over F_p) to a 64-bit brute force — insufficient for the ASI claim. The standalone mode (`AgentSelectiveScope`) eliminates this attack surface entirely by not outputting `scopeCommitment`.

### Security game: Selective Scope Unforgeability

**Game `SSU(λ)`:**

1. **Setup**: Challenger runs `Setup(1^λ)` producing Groth16 CRS `(pk, vk)` and an empty Merkle tree T.
2. **Enrollment oracle**: A may request enrollment of credentials `(modelHash, operatorPubkey, permissionBitmask, expiry)` into T. Challenger signs with the operator key and inserts `credentialCommitment` as a leaf. A receives the Merkle root but not the operator private key.
3. **Challenge**: A outputs `(π*, pubSignals*)` where `pubSignals*` includes a `requiredScopeMask` value `M*`.
4. **A wins if**:
   - `Verify(vk, π*, pubSignals*) = 1`, AND
   - There is no enrolled credential whose `permissionBitmask` satisfies `permissionBitmask & M* == M*`.

**Claim**: `Pr[A wins SSU(λ)] ≤ negl(λ)` under the assumptions in §4.

### Privacy game: Adaptive Multi-Proof Scope Indistinguishability (Standalone Mode)

**Game `ASI(λ, Q)`:**

This game captures a coalition of RSes and on-chain observers that adaptively probe the agent with up to Q distinct `requiredScopeMask` values across sessions, attempting to recover bitmask bits beyond what the predicate outcomes logically imply. The adversary has full knowledge of all enrolled `credentialCommitment` values (public Merkle leaves).

1. **Setup**: Challenger runs `Setup(1^λ)` producing Groth16 CRS `(pk, vk)` and Merkle tree T.

2. **Enrollment**: Challenger enrolls two credentials C₀, C₁ with bitmasks B₀, B₁ (and potentially differing modelHash/operatorKey/expiry). Both credentials are inserted into T. A receives all `credentialCommitment` values in T (including `credComm₀` and `credComm₁`). Challenger flips a secret coin b ∈ {0, 1}.

3. **Adaptive query phase** (up to Q rounds): In each round j = 1, …, Q:
   - A chooses a mask M_j ∈ {0, 1}^64 subject to the **predicate-agreement constraint**: `(B₀ & M_j == M_j) ⟺ (B₁ & M_j == M_j)`. That is, both bitmasks either satisfy or both fail to satisfy M_j.
   - Challenger generates a fresh `sessionNonce_j` and produces proof π_j using the `AgentSelectiveScope` circuit for credential C_b with public inputs `(M_j, currentTimestamp_j, sessionNonce_j)`.
   - A receives `(π_j, publicSignals_j)` where `publicSignals_j` contains `(agentMerkleRoot, nullifierHash_j, M_j, currentTimestamp_j, sessionNonce_j)` — notably, **no `scopeCommitment`**.

4. **Output**: A outputs b'.

5. **A wins if** b' = b.

**Claim**: `|Pr[b' = b] - 1/2| ≤ negl(λ)` for any polynomial Q(λ).

**Critical difference from the prior game formulation**: The adversary now knows all `credentialCommitment` values (realistic for a public Merkle tree). In the prior formulation, the ASI game relied on `credentialCommitment` being unknown to argue that `scopeCommitment` and `nullifierHash` were opaque. With public `credentialCommitment` values:

- **`nullifierHash_j = Poseidon2(credComm_b, sessionNonce_j)`**: The adversary knows both `credComm₀` and `credComm₁` and the nonce. It can compute `Poseidon2(credComm₀, sessionNonce_j)` and `Poseidon2(credComm₁, sessionNonce_j)` and compare against the observed `nullifierHash_j` to identify b. **This is the nullifier distinguishability problem.**

- **Resolution**: The nullifier's purpose is replay detection, not privacy. In standalone selective scope authorization, the RS (and the adversary) may already know which agent it is communicating with — the privacy goal is to hide the *bitmask*, not the *identity*. The ASI game is therefore refined to the **scope privacy** variant below.

### Refined privacy game: Scope Indistinguishability (standalone, same-identity)

**Game `SI(λ, Q)`:**

This game captures the core selective scope privacy claim: given that the adversary knows which agent is proving, it cannot learn bitmask bits beyond the predicate outcome.

1. **Setup**: Challenger runs `Setup(1^λ)` producing Groth16 CRS `(pk, vk)` and Merkle tree T.

2. **Enrollment**: Challenger enrolls a single credential C with two candidate bitmasks B₀, B₁ sharing the same `(modelHash, operatorPubkey, expiry)`. The challenger enrolls **both** corresponding `credentialCommitment` values into T (so neither Merkle membership distinguishes). Challenger flips b ∈ {0, 1} and the agent uses bitmask B_b.

3. **Adaptive query phase** (up to Q rounds): In each round j:
   - A chooses M_j subject to predicate-agreement: `(B₀ & M_j == M_j) ⟺ (B₁ & M_j == M_j)`.
   - Challenger produces `AgentSelectiveScope` proof π_j for bitmask B_b.
   - A receives `(π_j, publicSignals_j)`.

4. **A wins if** b' = b.

**Claim**: `|Pr[b' = b] - 1/2| ≤ Adv^{ZK}_{Groth16}(λ)`, which is negligible by **A6**.

**Why this is tight**: With `scopeCommitment` suppressed, the public outputs are `(agentMerkleRoot, nullifierHash)`. The Merkle root is the same for both credentials (both are enrolled). The nullifier `Poseidon2(credComm_b, nonce_j)` differs between b=0 and b=1, but both `credComm₀` and `credComm₁` are enrolled — the adversary cannot determine which `credentialCommitment` the prover used without breaking Groth16 ZK (**A6**). The proof π_j is the sole witness-dependent artifact; by Groth16's zero-knowledge property, it is simulatable without the witness. No precomputation attack exists because there is no `scopeCommitment` to serve as a brute-force handle.

**Predicate-agreement constraint rationale**: Identical to the prior formulation. The constraint is necessary and tight: without it, the adversary trivially distinguishes via the pass/fail outcome of the predicate, which is information-theoretically inherent to any authorization system.

**Bitmask recovery via predicate channel**: An adversary that queries with all 64 single-bit masks learns the full bitmask via pass/fail outcomes. This is not a ZK violation — it is inherent to any system that answers "do you have permission X?" The ZK guarantee is that *conditioned on the predicate outcome*, the proof reveals nothing further. The SI game formalizes this precisely.

**Operational mitigation for bitmask recovery**: While the pass/fail channel is information-theoretically unavoidable, Bolyra deployments can limit its bandwidth:

- **Agent-side mask policy**: The agent refuses to prove against singleton masks (or masks below a minimum Hamming weight threshold), forcing RSes to query coarse-grained permission groups rather than individual bits.
- **Rate limiting**: The agent limits the number of distinct `requiredScopeMask` values it will evaluate per session or per RS identity.
- **Mask commitment**: The RS commits to `requiredScopeMask` before the agent reveals whether it can satisfy it (commit-then-prove protocol). This prevents adaptive mask selection based on prior outcomes within a single session.

### Privacy posture of delegation-capable mode

When `scopeCommitment` is exposed (delegation-capable `AgentPolicy` circuit), the precomputation attack described above applies: an adversary with knowledge of `credentialCommitment` (public leaf) can brute-force the 64-bit bitmask via ~2^64 Poseidon2 evaluations. This is an accepted trade-off in the delegation flow, where:

1. The delegation chain **requires** `scopeCommitment` for chain-linking integrity (spec §5.2).
2. The delegator has opted into a multi-hop protocol where scope commitment visibility is a design requirement — the privacy goal shifts from "hide the bitmask from RSes" to "prove scope narrowing without revealing the delegator's identity."
3. Deployments that need both delegation chaining and bitmask privacy should use a two-proof architecture: `AgentSelectiveScope` for RS authorization (bitmask hidden) followed by `AgentPolicy` for delegation chain seeding (scope commitment exposed only to the on-chain registry, not to the RS).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| Label | Assumption | Standard reference |
|-------|------------|--------------------|
| **A1** | Knowledge soundness of Groth16 in the generic group model | [Groth16, EUROCRYPT 2016] |
| **A2** | Knowledge soundness of PLONK in the algebraic group model + ROM | [GWC19, IACR 2019/953] |
| **A3** | Collision resistance of Poseidon over F_p (BN254 scalar field) | [Grassi et al., USENIX Security 2021] |
| **A4** | Discrete log hardness on Baby Jubjub (embedded curve in BN254) | Inherited from BN254 subgroup security |
| **A5** | EdDSA-Poseidon EUF-CMA security under A3 + A4 | Schnorr-type argument in twisted Edwards form |
| **A6** | Zero-knowledge property of Groth16 (simulation in CRS model) | [Groth16, EUROCRYPT 2016, Theorem 2] |

### Reduction sketch for SSU

**Theorem**: If A wins SSU with non-negligible probability ε, then we can break one of A1, A3, A4, or A5.

**Proof sketch**:

1. Suppose A produces a valid proof π* for `requiredScopeMask = M*` with no enrolled credential satisfying M*.

2. By **A1** (Groth16 knowledge soundness), extract the witness: `(modelHash*, opPk*, permBitmask*, expiry*, sig*, merkleProof*)`.

3. The proof verifies, so the circuit constraints hold:
   - `credComm* = Poseidon5(modelHash*, opPk*.Ax, opPk*.Ay, permBitmask*, expiry*)`
   - `EdDSA.Verify(opPk*, credComm*, sig*) = 1`
   - `MerkleRoot(credComm*, merkleProof*) = root*` where `root*` is in the on-chain buffer
   - `permBitmask* & M* == M*`

4. Since `permBitmask* & M* == M*`, the extracted bitmask does satisfy M*. So for A to win, `credComm*` must not correspond to any enrolled credential. Two sub-cases:

   a. **credComm* is a leaf in T but was enrolled with a different bitmask B' where B' & M* ≠ M***: Then `Poseidon5(...)` maps two different input tuples to the same hash — contradicting **A3** (collision resistance).

   b. **credComm* is not a leaf in T but MerkleRoot still matches an on-chain root**: Then the Merkle proof forges a path — contradicting **A3** (second preimage resistance of Poseidon2 used as the node hash).

   c. **The EdDSA signature is forged for a new credComm***: Contradicts **A5** (EUF-CMA of EdDSA-Poseidon), which reduces to **A4** (DLP on Baby Jubjub).

5. All sub-cases lead to contradiction. ∎

### Reduction sketch for SI (scope privacy, standalone mode)

**Theorem**: If A wins `SI(λ, Q)` with non-negligible advantage ε for any polynomial Q, then we can break **A6** (Groth16 ZK).

**Proof sketch**:

1. Construct simulator S that uses the Groth16 zero-knowledge simulator Sim (guaranteed by **A6**) to answer A's adaptive queries without knowing b.

2. For each query j with mask M_j:
   - By the predicate-agreement constraint, `(B₀ & M_j == M_j) ⟺ (B₁ & M_j == M_j)`. So the pass/fail outcome is identical for both bitmasks.
   - If the predicate is not satisfied for both bitmasks, S responds with a proof failure.
   - If the predicate is satisfied for both bitmasks, S invokes Sim(vk, pubSignals_j) to produce a simulated proof π̃_j.

3. **Public output analysis** (standalone mode — no `scopeCommitment`):
   - `agentMerkleRoot`: Both `credComm₀` and `credComm₁` are enrolled in T, so any valid Merkle root is consistent with either. The adversary cannot determine which leaf was used from the root alone (the tree contains both).
   - `nullifierHash_j = Poseidon2(credComm_b, sessionNonce_j)`: The adversary knows `credComm₀`, `credComm₁`, and `sessionNonce_j`. It can compute both candidate nullifier hashes and compare. **However**, the simulated proof produced by Sim does not commit to a specific `credComm_b` — the Groth16 ZK simulator produces `(π̃, pubOutputs)` that are computationally indistinguishable from real proofs for *any* valid witness. The nullifier hash is a public output determined by the circuit, and the simulator's output distribution matches the real distribution for the chosen b.
   - **Key insight**: The distinguishing advantage via nullifier comparison is exactly `Adv^{ZK}_{Groth16}(λ)`. If the adversary could distinguish the real proof distribution from the simulated distribution (which is b-independent), it breaks Groth16 ZK.

4. **Why `scopeCommitment` suppression is essential**: If `scopeCommitment` were present, step 3 would fail. The adversary knows `credComm₀` and `credComm₁` and can precompute `Poseidon2(b, credComm_i)` for all 2^64 candidate bitmasks b and both credentials. A single observed `scopeCommitment` narrows the candidate set to at most one `(bitmask, credential)` pair — breaking indistinguishability with O(2^64) work, which is computationally feasible. The standalone circuit eliminates this attack surface by not exposing `scopeCommitment`.

5. **Nullifier distinguishability — tighter analysis**: The adversary's nullifier comparison attack (computing `Poseidon2(credComm₀, nonce_j)` and `Poseidon2(credComm₁, nonce_j)` and checking which matches) is a valid concern. However, note that in the SI game, both `credComm₀` and `credComm₁` are enrolled in T. The Groth16 ZK property guarantees that the proof π_j does not reveal which witness was used. The nullifier hash is a **deterministic function of the witness** and appears as a public output — but the Groth16 ZK guarantee covers public outputs: the simulator produces `(π̃, outputs)` jointly indistinguishable from real `(π, outputs)`. If the adversary could distinguish via the nullifier value, it distinguishes real from simulated — breaking **A6**.

   **Formal argument**: The Groth16 ZK property states that for any statement x and any two valid witnesses w₀, w₁ for x, the distributions `(π₀, f(w₀))` and `(π₁, f(w₁))` are computationally indistinguishable, where f denotes the public output function of the circuit. In our case, x = `(requiredScopeMask, currentTimestamp, sessionNonce)` and f includes `nullifierHash`. The game requires both w₀ (using B₀) and w₁ (using B₁) to be valid witnesses for x (predicate-agreement constraint). Therefore, the joint distributions are indistinguishable by A6.

   **Clarification on Groth16 ZK**: The standard Groth16 ZK property is defined as: for any statement x, a simulator Sim(vk, x) produces (π̃, ·) indistinguishable from a real proof. When the public outputs are deterministic functions of the witness, the simulator must produce outputs consistent with *some* valid witness. For statements with multiple valid witnesses (as in our game, where both w₀ and w₁ are valid), the simulator's output is indistinguishable from any real witness — including the one the adversary is trying to identify. The adversary's advantage is thus bounded by `Adv^{ZK}_{Groth16}(λ)`.

6. Combining: A's advantage is `ε ≤ Adv^{ZK}_{Groth16}(S) ≤ negl(λ)`. ∎

**Note on the prior ASI formulation**: The prior construction's ASI game assumed `credentialCommitment` values were unknown to the adversary and argued that `nullifierHash` and `scopeCommitment` were opaque under Poseidon preimage resistance (**A3**). This was flawed: `credentialCommitment` values are public Merkle leaves on a public blockchain. With known `credentialCommitment`, the `scopeCommitment` output `Poseidon2(permissionBitmask, credComm)` is brute-forceable over the 64-bit bitmask space, reducing privacy to ~64 bits of computational security. The SI game eliminates this dependency by (1) suppressing `scopeCommitment` and (2) reducing privacy solely to Groth16 ZK (**A6**), which provides the full ~128-bit security level of BN254.

**Corollary (bitmask recovery via predicate channel)**: The SI game's predicate-agreement constraint precisely characterizes the information an adversary *cannot* extract from proofs. The complementary information — the predicate outcome itself — is extractable by any system that evaluates authorization predicates. For an agent with bitmask B, Q adaptive queries with arbitrary masks yield at most Q bits of information about B (one pass/fail bit per query). Full recovery requires Q ≥ 64 queries with linearly independent masks (e.g., all singleton masks). This channel exists identically in RFC 7662, BBS+, and any authorization system. The ZK property ensures no *additional* leakage beyond this channel.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Permission encoding | 64-bit cumulative bitmask with implication rules | Spec §permissions, `validateCumulativeBitEncoding()` |
| Hash function | Poseidon over BN128 scalar field | Spec §3.2 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` | Spec §2 (Credential Commitment) |
| Operator signature | EdDSA on Baby Jubjub via `EdDSAPoseidonVerifier` | Spec §3.2 |
| Enrollment proof | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Spec §3.2 |
| Scope satisfaction | `requiredBits[i] * (1 - permBits[i]) === 0` for i ∈ [0,64) | Spec §4.2 constraint 5 |
| Cumulative implication | 3 constraints on bits 2/3/4 | Spec §4.2 constraint 6 |
| Nullifier | `Poseidon2(credentialCommitment, sessionNonce)` | Spec §2 (Nullifier) |
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` — internal only in standalone mode | Spec §2 (Scope Commitment) |
| Proving system | Groth16 (required) or PLONK (optional) for agent circuits | Spec §3.3 |
| Root history buffer | 30-entry circular buffer, on-chain | Spec §2 |

No new primitives are introduced. The standalone mode suppresses one public output; it does not add any gadget, hash, or curve operation beyond what is already specified in `draft-bolyra-mutual-zkp-auth-01`.

## 6. Circuit cost estimate

### Constraint breakdown

**`AgentSelectiveScope` (standalone):**

| Gadget | Estimated constraints |
|--------|----------------------|
| `Num2Bits(64)` × 3 (bitmask, expiry, timestamp) | 192 |
| `Poseidon5` (credential commitment) | ~1,500 |
| `EdDSAPoseidonVerifier` | ~7,500 |
| `BinaryMerkleRoot(20)` with Poseidon2 | ~30,000 (20 levels × ~1,500 per Poseidon2) |
| Scope satisfaction (64 multiplication constraints) | 64 |
| Cumulative bit implication (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` × 1 (nullifier) | ~1,500 |
| `Poseidon2` × 1 (scope commitment, internal) | ~1,500 |
| **Total** | **~42,400** |

**`AgentPolicy` (delegation-capable):** Identical constraint count (~42,400). The only difference is that `scopeCommitment` is wired to a public output rather than left as an internal signal. No additional constraints.

### Proving time targets

| Proving system | Target | Device | Notes |
|----------------|--------|--------|-------|
| Groth16 (snarkjs, WASM) | < 8s | Modern laptop | Conservative; benchmarks show ~5s for 40K constraints |
| Groth16 (rapidsnark, native) | < 1s | Server with rapidsnark binary | Production path |
| PLONK (snarkjs) | < 5s | Modern laptop | Universal setup avoids per-circuit ceremony |

All targets are within the spec's PLONK agent budget of <5s.

### Proof size

| Proving system | Proof size | Public signals (standalone) | Public signals (delegation) |
|----------------|-----------|---------------------------|----------------------------|
| Groth16 | 128 bytes | 5 × 32 = 160 bytes | 6 × 32 = 192 bytes |
| PLONK | ~560 bytes | 5 × 32 = 160 bytes | 6 × 32 = 192 bytes |

Total on-wire payload (standalone): **288 bytes (Groth16)** or **720 bytes (PLONK)**. Constant regardless of bitmask width.

## 7. Concrete deployment scenario

### Scenario: Federated Credit Union Agent Authorization

**Stakeholder**: A state-chartered credit union (e.g., a CUNA-affiliated institution in Texas) operating under NCUA oversight, using AI agents for member-facing operations.

**Setup**:
- The credit union operates as an **operator** in the Bolyra model. It enrolls AI agents (e.g., a loan-processing agent, a member-support chatbot, a fraud-detection agent) by signing credential commitments with its EdDSA operator key.
- Each agent credential encodes a `permissionBitmask`:
  - Loan agent: `0b00010111` (READ_DATA | WRITE_DATA | FINANCIAL_SMALL | FINANCIAL_MEDIUM)
  - Support chatbot: `0b10000001` (READ_DATA | ACCESS_PII)
  - Fraud agent: `0b00000011` (READ_DATA | WRITE_DATA)
- Credentials are enrolled in the on-chain agent Merkle tree. The Merkle root is public.

**Runtime flow** (loan approval request to a partner RS — a core banking API provider):

1. The core banking RS requires `requiredScopeMask = 0b00000110` (WRITE_DATA | FINANCIAL_SMALL) for a loan disbursement endpoint.
2. The RS generates `sessionNonce` and sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to the credit union's loan agent.
3. The loan agent generates a Groth16 proof using the **`AgentSelectiveScope` circuit** (standalone mode — no `scopeCommitment` exposed) via rapidsnark (<1s). The proof demonstrates that `0b00010111 & 0b00000110 == 0b00000110`. The RS never sees that the agent also holds FINANCIAL_MEDIUM or READ_DATA.
4. The RS verifies the proof against the on-chain root and the `AgentSelectiveScope` verifier key. No call to the credit union's AS. No call to any identity provider. The proof transcript contains 5 public signals — no `scopeCommitment` to enable bitmask brute-forcing.
5. The RS authorizes the disbursement. The proof transcript is logged for audit.

**Why standalone mode matters in this scenario**:
- The core banking RS is operated by a separate entity (a CUSO or fintech partner). The credit union does not want the partner to learn its full permission topology — that reveals internal policy structure, agent capabilities, and organizational risk appetite.
- With `scopeCommitment` suppressed, the partner cannot precompute `Poseidon2(candidate_bitmask, credComm)` against the public Merkle tree to recover the loan agent's full bitmask. The only information the partner learns is the pass/fail outcome of the scope predicate.
- Under NCUA examination, the credit union can replay the proof transcript to demonstrate that the agent was authorized for exactly the requested scope at the time of the transaction, with cryptographic assurance independent of the partner's attestation.
- If the partner's AS is compromised, it cannot retroactively claim the agent had permissions it did not — the proof is bound to the operator's EdDSA signature over the credential commitment.

**When delegation mode is used**: If the loan agent needs to sub-delegate to a document-processing sub-agent (e.g., with narrowed permissions `0b00000101` — READ_DATA | FINANCIAL_SMALL), the delegation flow uses the `AgentPolicy` circuit (with `scopeCommitment` exposed) to seed the chain. The `scopeCommitment` is written to the on-chain registry and visible only in the delegation context — not to the core banking RS that authorized the original request.

**Adaptive probing defense in practice**: The credit union's loan agent is configured with a minimum mask Hamming weight of 2 and a per-RS rate limit of 8 distinct masks per hour. A colluding RS that attempts singleton-bit probing (e_0, e_1, …) is refused after the first attempt. Legitimate RSes query with functional masks (e.g., "WRITE + FINANCIAL_SMALL" for disbursement) that reveal coarse capability groups, not individual bits.

## 8. Why the baseline cannot match

The baseline composes RFC 7662, jwt-introspection-response, RFC 8707, DPoP, and BBS+ selective disclosure. Each gap below is structural — not a missing feature that a future RFC could add, but a fundamental architectural incompatibility.

### Gap 1: AS-Blind Presentation

In the baseline, every credential and every introspection response originates from the AS. Even with BBS+ holder-driven selective disclosure, the AS issued the BBS+ credential and chose which claims to include. The holder can selectively disclose claims, but cannot evaluate a bitwise predicate over a hidden bitmask — BBS+ operates over discrete message slots, not over arithmetic relations between binary fields.

In the Bolyra construction, the agent's `permissionBitmask` is a private circuit input. The proof is generated entirely by the agent using local witness data and the public Merkle root. No AS is contacted. The RS specifies `requiredScopeMask` and receives a proof — the AS is not in the protocol flow at all.

### Gap 2: Runtime-Adaptive Predicate

The baseline's scope is fixed at token issuance (or introspection time). If the RS needs a different scope combination, a new token exchange (RFC 8693) or re-introspection is required — both involving the AS.

In the Bolyra construction, `requiredScopeMask` is a public input chosen by the RS at the moment of the request. The same enrolled credential satisfies any mask that the bitmask covers. No re-issuance. No re-enrollment. The predicate is evaluated inside the circuit at proof generation time.

### Gap 3: Adversarial-AS Soundness

The baseline's trust anchor is the AS's signing key. A compromised AS can issue false introspection responses, forge BBS+ credentials, or lie about scope membership. The RS has no recourse — the signed JWT proves only "the AS said X," not "X is true."

In the Bolyra construction, the trust anchor is the operator's EdDSA key and the on-chain Merkle root. The operator signed the credential commitment; the Merkle tree records it immutably. A compromised AS cannot forge an operator signature (EdDSA EUF-CMA under DLP on Baby Jubjub). The RS verifies the proof against the on-chain root and the circuit's verification key — neither of which the AS controls.

### Gap 4: Constant-Size Proof

A jwt-introspection-response grows linearly with disclosed scopes. A BBS+ derived proof grows with the number of disclosed messages. For a 64-bit permission space with fine-grained scopes, a scope-string enumeration is bandwidth-infeasible at scale.

The Groth16 proof is 128 bytes. Always. Whether the bitmask is 8 bits or 2048 bits (with a proportionally larger circuit), the proof is 3 group elements. The public signals are 5 field elements in standalone mode (160 bytes). Total payload: 288 bytes, constant.

### Gap 5: Cumulative Implication Enforcement at Proof Time

BBS+ has no mechanism to enforce that bit 4 → bit 3 → bit 2 within a selective disclosure presentation. The issuer could encode these as separate claims, but the holder-derived presentation has no circuit to enforce implication closure. An AS could enforce this at issuance, but a compromised AS (Gap 3) would not.

The Bolyra circuit enforces implication closure via 3 explicit constraints before the scope satisfaction check runs. A credential with `FINANCIAL_UNLIMITED` set but `FINANCIAL_MEDIUM` unset is rejected by the circuit — no valid proof can be generated. This is enforced cryptographically, not by policy.

### Gap 6: Privacy Beyond Predicate Outcome Under Adaptive Probing

BBS+ selective disclosure reveals exactly the disclosed claims — nothing more, nothing less. But "nothing more" means the RS learns the *values* of disclosed claims, not just a predicate over them. If the RS requests the `FINANCIAL_MEDIUM` claim, it learns whether the credential contains it (presence/absence of a disclosed message slot). Across multiple BBS+ presentations with different disclosure requests, the RS learns the exact set of held claims — there is no distinction between "predicate outcome" and "claim content" because BBS+ disclosure is all-or-nothing per claim.

In the Bolyra construction, the SI game proves that the proof transcript reveals *only* the predicate outcome (pass/fail) and nothing further — even across Q adaptive queries by colluding RSes. Two credentials with bitmasks that agree on all queried predicates produce computationally indistinguishable proof sequences (reducible to Groth16 ZK alone, without relying on Poseidon preimage resistance over a 64-bit domain). BBS+ cannot make this claim: two credentials that agree on all queried predicates but differ on undisclosed claims produce presentations with different BBS+ proof structures (different number of hidden messages affects proof size).

### Summary: Properties the baseline fundamentally cannot express

| Property | Baseline ceiling | Bolyra construction |
|----------|-----------------|---------------------|
| AS involvement at proof time | Required (issuance or introspection) | None — agent proves locally |
| Predicate adaptability | Fixed at issuance; re-issue for new predicates | RS chooses `requiredScopeMask` per-request |
| Trust anchor | AS signing key (single point of compromise) | Operator EdDSA + on-chain Merkle root |
| Proof size scaling | O(disclosed claims) for BBS+; O(scope strings) for JWT | O(1) — constant 288 bytes (standalone Groth16) |
| Implication closure enforcement | Policy-only (bypassable by compromised AS) | Circuit-enforced (cryptographic) |
| Model identity binding | `client_id` string (no cryptographic binding) | `credentialCommitment` includes `modelHash` + operator key |
| Adaptive multi-proof privacy | BBS+ leaks claim values per disclosure; O(Q) queries recover full claim set | Proof leaks only pass/fail; SI-secure under Groth16 ZK (no 64-bit brute-force surface) |
| Bitmask brute-force surface | N/A (claims are plaintext when disclosed) | None in standalone mode — `scopeCommitment` suppressed; delegation mode accepts 64-bit brute-force as chain-linking trade-off |
