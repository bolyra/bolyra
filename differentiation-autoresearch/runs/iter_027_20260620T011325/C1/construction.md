# Construction

## 1. Statement of claim

Agent proves it satisfies a required permission predicate without revealing the full permission set to the resource server, in a way that no configuration of RFC 7662 (plus jwt-introspection-response, RFC 8693, RFC 8707, DPoP) can match.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: SelectiveScopeProof (extension of AgentPolicy)

This construction uses the existing `AgentPolicy` circuit from the Bolyra spec without modification. The selective scope proof property emerges directly from the circuit's signal layout: `permissionBitmask` is a **private input** while `requiredScopeMask` is a **public input**, and the scope satisfaction constraint operates over bit decompositions of both.

**Private inputs** (hidden from RS):
- `modelHash`: Hash of model identifier
- `operatorPubkeyAx`, `operatorPubkeyAy`: Operator EdDSA public key (Baby Jubjub)
- `permissionBitmask`: 64-bit permission bitfield — the full permission set
- `expiryTimestamp`: Credential expiration (Unix timestamp)
- `sigR8x`, `sigR8y`, `sigS`: Operator EdDSA signature components
- `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]`: Merkle inclusion proof

**Public inputs** (visible to RS):
- `requiredScopeMask`: The predicate the RS demands — a bitmask of required permission bits
- `currentTimestamp`: Current time (from verifier)
- `sessionNonce`: Session binding value

**Public outputs**:
- `agentMerkleRoot`: Computed Merkle root (proves enrollment)
- `nullifierHash`: Poseidon2(credentialCommitment, sessionNonce)
- `scopeCommitment`: Poseidon2(permissionBitmask, credentialCommitment)

**Key gadgets** (all from existing spec):

1. **Scope satisfaction (bitwise AND predicate)**: For each bit i ∈ [0, 64):
   ```
   requiredBits[i] * (1 - permBits[i]) === 0
   ```
   This enforces `requiredScopeMask & permissionBitmask == requiredScopeMask`. The constraint is satisfiable if and only if every bit set in `requiredScopeMask` is also set in `permissionBitmask`. Crucially, bits set in `permissionBitmask` but NOT set in `requiredScopeMask` are never revealed — they contribute to the witness but produce no distinguishing public signal.

2. **Cumulative bit encoding**: Implication closure constraints (bit 4 → bits 3,2; bit 3 → bit 2) enforced in-circuit, ensuring hierarchical permission semantics are maintained even though the RS never sees the raw bits.

3. **EdDSA credential binding**: EdDSAPoseidonVerifier over credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp), proving the operator signed this exact permission set.

4. **Merkle enrollment**: BinaryMerkleRoot(20) proving credentialCommitment is a leaf in the on-chain agent tree.

**What the RS learns**: The proof verifies (boolean pass) or it does not (boolean fail). The RS learns:
- The agent is enrolled (Merkle root matches on-chain state)
- The agent's credential has not expired
- The agent's permission bitmask satisfies `requiredScopeMask`
- A scope commitment (opaque hash — not invertible to the bitmask)
- A nullifier (replay prevention)

**What the RS does NOT learn**:
- Which specific bits beyond `requiredScopeMask` are set in `permissionBitmask`
- The total number of permissions held
- The modelHash, operator public key, or any credential field
- Whether the agent holds `FINANCIAL_UNLIMITED` (bit 4) vs. only `FINANCIAL_SMALL` (bit 2), provided only bit 2 was required

This is **input-private predicate satisfaction**: the predicate is public (requiredScopeMask), the satisfaction result is public (proof verifies), but the predicate's input (permissionBitmask) is private.

## 3. Threat model (adversary capabilities, game definition)

### Primary differentiator: Input-private predicate satisfaction

The decisive property of this construction is not merely "RS sees fewer permissions" or "no AS roundtrip." It is **input-private predicate satisfaction**: the RS specifies a predicate (requiredScopeMask), learns only the boolean result (proof valid / invalid), and gains zero information about the predicate's input (permissionBitmask) beyond what the boolean result logically implies.

This is strictly stronger than selective disclosure. In BBS+ selective disclosure, the RS learns the *values* of the disclosed claims — it sees `FINANCIAL_SMALL = true`. In filtered introspection, the RS sees the filtered scope strings — it sees `scope: "financial_small"`. In both cases, the RS learns **which specific permissions the agent holds**, just fewer of them than the full set.

In this construction, the RS learns only that `permissionBitmask & requiredScopeMask == requiredScopeMask`. If `requiredScopeMask = 0b00000100` (FINANCIAL_SMALL), the RS cannot distinguish an agent holding `0b00000100` from one holding `0b11111111`. The predicate's input is information-theoretically hidden by the zero-knowledge property of the proof.

**Why this matters beyond privacy aesthetics**: Input-privacy prevents the RS from building a permission profile of the agent across interactions. Even if the RS issues different requiredScopeMasks across calls, the zero-knowledge property ensures each proof reveals only the boolean for that specific mask. The RS cannot intersect results to reconstruct the bitmask (each proof is independently zero-knowledge). By contrast, BBS+ presentations of individual permission claims allow an RS collecting presentations over time to reconstruct the full claim set.

**Why BBS+ + ABAC cannot replicate this**: BBS+ operates over discrete named claims. To evaluate a bitwise AND predicate, the holder must either (a) disclose the relevant claims (breaking input-privacy — the RS sees which claims are true), or (b) use a BBS+ NIZK predicate proof. Current BBS+ predicate extensions (VC-DI BBS+ §4.5) support equality and range proofs over individual messages, not bitwise AND over a multi-field bitmask with implication closure. Even if a future BBS+ extension added bitwise predicates, BBS+ predicate proofs reveal the predicate structure (which message indices are involved), whereas a SNARK proof reveals nothing about the witness structure.

**Why WIMSE Workload Identity Tokens cannot replicate this**: WIMSE WTS (draft-ietf-wimse-workload-identity-token) carries workload attributes as JWT claims in the clear or uses token introspection. The RS evaluating an ABAC policy against WTS claims sees the claim values. There is no mechanism in WIMSE for the workload to prove predicate satisfaction without revealing the claim values to the evaluating party.

### Adversary model

**Adversary A** controls:
- The Authorization Server (can issue arbitrary introspection responses, can lie about scope membership, can selectively omit or fabricate permissions)
- Network observation between Agent and RS (passive eavesdropper on all presentations)
- Up to t-1 colluding Resource Servers (can share all received proofs and attempt to correlate or reconstruct the agent's permission bitmask)

**Adversary A does NOT control**:
- The on-chain Merkle tree (maintained by the enrollment contract with append-only semantics)
- The agent's private witness (modelHash, operatorPubkeyAx/Ay, permissionBitmask, sigR8x/R8y/S, Merkle siblings)
- The Groth16/PLONK proving system internals

### Game: INPUT-PRIVACY-SCOPE

```
Setup: Challenger C enrolls two agents A₀, A₁ in the Merkle tree.
  A₀ has permissionBitmask₀, A₁ has permissionBitmask₁.
  Both satisfy the same requiredScopeMask M:
    permissionBitmask₀ & M == M
    permissionBitmask₁ & M == M
  But permissionBitmask₀ ≠ permissionBitmask₁ (they differ on bits outside M).

Challenge: C flips coin b ∈ {0,1}, generates proof πb using Ab's witness
  against public input requiredScopeMask = M, fresh sessionNonce.
  Sends (πb, public signals) to A.

Win condition: A outputs b' = b with probability > 1/2 + negl(λ).
```

**Claim**: Under the zero-knowledge property of Groth16 (simulation-extractability in the generic group model) or PLONK (in the algebraic group model + ROM), no PPT adversary A wins INPUT-PRIVACY-SCOPE with non-negligible advantage.

This game is NOT expressible in the baseline stack. In RFC 7662 + BBS+, the analog would require the RS to distinguish two agents with different permission sets that both satisfy the same policy — and the RS trivially wins by reading the disclosed claims or filtered scope strings.

## 4. Security argument (named assumption + reduction sketch)

**Theorem**: The SelectiveScopeProof construction satisfies input-private predicate satisfaction under the following assumptions:

1. **Knowledge soundness of Groth16** in the generic group model (or PLONK in AGM + ROM): No PPT prover can produce a valid proof without knowing a witness (modelHash, operatorPubkey, permissionBitmask, expiry, signature, Merkle proof) satisfying all circuit constraints.

2. **Zero-knowledge of Groth16** (simulation-extractability): There exists a simulator S that, given only the public inputs/outputs and a simulation trapdoor, produces proofs indistinguishable from real proofs. This directly implies INPUT-PRIVACY-SCOPE: the simulator needs no witness, so the proof reveals nothing about permissionBitmask beyond what the public signals (which include requiredScopeMask but NOT permissionBitmask) convey.

3. **Collision resistance of Poseidon** over BN254 scalar field: Required for:
   - Merkle tree binding (no two distinct leaves produce the same root)
   - Scope commitment binding (Poseidon2(permissionBitmask, credentialCommitment) is injective with overwhelming probability)
   - Credential commitment binding (Poseidon5 is collision-resistant)

4. **Discrete logarithm hardness on Baby Jubjub**: Required for EdDSA unforgeability — no adversary can forge the operator's signature over credentialCommitment without the operator's private key.

**Reduction sketch for INPUT-PRIVACY-SCOPE**:

Suppose adversary A wins INPUT-PRIVACY-SCOPE with advantage ε. We construct a distinguisher D that breaks the zero-knowledge property of Groth16:

- D receives a proof π that is either a real proof (with witness from A_b) or a simulated proof (no witness).
- D forwards π to A, who outputs b'.
- If π is real, A's advantage is ε by assumption.
- If π is simulated, A's view is independent of b (the simulator uses no witness), so A's advantage is 0.
- Therefore D distinguishes real from simulated proofs with advantage ε/2, contradicting zero-knowledge.

**Soundness reduction**: Suppose a malicious agent produces a valid proof π where `permissionBitmask & requiredScopeMask ≠ requiredScopeMask`. By knowledge soundness, an extractor E recovers a witness. The circuit constraint `requiredBits[i] * (1 - permBits[i]) === 0` for all i means the extracted permissionBitmask must satisfy the mask. Contradiction. Therefore no agent can produce a passing proof without actually holding the required permissions.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Permission bitmask | 64-bit cumulative encoding (8 named bits, 56 reserved) | §AgentPolicy private input |
| Scope satisfaction predicate | `requiredBits[i] * (1 - permBits[i]) === 0` for i ∈ [0,64) | §AgentPolicy constraint 5 |
| Cumulative implication closure | Bits 4→3→2 constraints | §AgentPolicy constraint 6 |
| Credential commitment | Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiry) | §Terminology |
| Scope commitment (opaque chain-link) | Poseidon2(permissionBitmask, credentialCommitment) | §AgentPolicy output 2 |
| Operator authentication | EdDSAPoseidonVerifier on Baby Jubjub | §AgentPolicy constraint 3 |
| Enrollment proof | BinaryMerkleRoot(20) with Poseidon2 node hash | §AgentPolicy constraint 4 |
| Nullifier (replay prevention) | Poseidon2(credentialCommitment, sessionNonce) | §AgentPolicy output 1 |
| Proving system (human) | Groth16 (Semaphore v4 ceremony, depth 20) | §Proving Systems |
| Proving system (agent) | Groth16 required, PLONK optional | §Proving Systems |
| Session binding | sessionNonce as public input, checked on-chain for freshness | §Handshake step 5b |
| Delegation (scope narrowing) | Delegation circuit with subset constraint + chain-linking | §Composable Delegation |

No new primitives are introduced. The input-privacy property is an emergent consequence of the existing signal layout: permissionBitmask is private, requiredScopeMask is public, and the zero-knowledge property of the proving system hides the private input.

## 6. Circuit cost estimate

The construction uses the existing `AgentPolicy` circuit without modification.

| Component | Constraints (approx.) |
|---|---|
| Poseidon5 (credential commitment) | ~1,500 |
| EdDSA verification (Baby Jubjub) | ~6,000 |
| BinaryMerkleRoot (depth 20, Poseidon2) | ~12,000 |
| Num2Bits(64) × 3 (bitmask, expiry, timestamp) | ~192 |
| Scope satisfaction (64 multiplicative constraints) | ~64 |
| Cumulative bit encoding (3 constraints) | ~3 |
| Poseidon2 (nullifier) | ~600 |
| Poseidon2 (scope commitment) | ~600 |
| **Total** | **~21,000** |

This fits within the 2^16 = 65,536 constraint budget of `pot16.ptau`.

**Proving time targets**:
- Groth16 (agent, snarkjs browser): < 5s on modern hardware
- Groth16 (agent, rapidsnark native): < 0.5s
- PLONK (agent, optional): < 3s
- Verification (on-chain, Groth16): ~230K gas (single pairing check)

**Proof size**: Groth16 produces 3 group elements = 256 bytes. Constant regardless of bitmask width, number of permissions held, or predicate complexity. This is the constant-size property the baseline cannot match.

## 7. Concrete deployment scenario

**Stakeholder**: Pacific Northwest Credit Union (PNWCU), a $2B NCUA-insured institution regulated under the GENIUS Act stablecoin framework.

**Setup**: PNWCU deploys an AI agent ("LoanBot") to handle member loan inquiries and small-dollar approvals. LoanBot's operator (PNWCU's IT department) issues an EdDSA-signed credential with `permissionBitmask = 0b00100111` (READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII). The credential commitment is enrolled in Bolyra's on-chain agent Merkle tree.

**Runtime interaction**: LoanBot connects to an external credit-scoring RS (TransUnion API gateway). The RS requires proof that the calling agent holds `FINANCIAL_SMALL` (bit 2) — nothing more, nothing less.

**What happens with Bolyra**: LoanBot generates a Groth16 proof with `requiredScopeMask = 0b00000100`. The RS verifies the proof on-chain (or off-chain via the exported verifier). The RS learns:
- LoanBot is enrolled (Merkle root matches)
- LoanBot holds at least FINANCIAL_SMALL
- The credential has not expired
- **Nothing else** — the RS does not learn that LoanBot also holds READ_DATA, WRITE_DATA, or ACCESS_PII

**Why input-private predicate satisfaction is the decisive property in this scenario**:

1. **NCUA examiners audit RS access logs.** If TransUnion's logs show that PNWCU's agent presented `ACCESS_PII` capability to a credit-scoring endpoint, the examiner flags an unnecessary data-exposure surface — even if the agent never exercised that capability. With input-private predicate satisfaction, TransUnion's logs show only "agent proved FINANCIAL_SMALL: PASS." There is no capability metadata to flag.

2. **AS-blindness under outage.** During the July 2024 CrowdStrike outage (14+ hours of AS downtime for affected institutions), agents with cached JWT introspection responses could continue operating — but only with the fixed scope set cached at last introspection. If the RS changes its required scope mid-outage (e.g., raising the threshold from FINANCIAL_SMALL to FINANCIAL_MEDIUM for amounts > $500), the cached introspection response cannot adapt. With Bolyra, the agent generates a fresh proof against any requiredScopeMask the RS specifies, with no AS involvement.

3. **Adversarial AS model.** If PNWCU's OAuth AS is compromised, the attacker can issue introspection responses claiming LoanBot holds `FINANCIAL_UNLIMITED` — or claiming it holds nothing. The RS has no recourse: a signed introspection JWT proves the AS said something, not that it's true. With Bolyra, LoanBot's permissions are committed on-chain via the operator's EdDSA signature and Merkle enrollment. A compromised AS cannot alter what the circuit proves.

## 8. Why the baseline cannot match

### Axis 0: Input-private predicate satisfaction — the property no baseline mechanism achieves

The decisive differentiator is not AS-blindness alone, not runtime-adaptiveness alone, and not selective disclosure alone. It is **input-private predicate satisfaction**: the RS specifies a predicate, receives a boolean result, and learns nothing about the predicate's input beyond what the boolean logically implies.

Every baseline mechanism that evaluates a permission predicate reveals the predicate's input to the evaluating party:

| Mechanism | Predicate evaluation | Input visibility | Input-private? |
|---|---|---|---|
| RFC 7662 filtered introspection | AS evaluates, RS receives filtered scope list | RS sees which scopes are present in the filtered set | **No** — RS sees scope names |
| BBS+ selective disclosure | Holder selects claims to disclose, RS reads them | RS sees the disclosed claim values | **No** — RS sees `FINANCIAL_SMALL = true` |
| BBS+ NIZK predicate proof | Holder proves predicate over hidden attribute | RS sees predicate structure (which message index, comparison operator) | **Partial** — RS learns predicate shape, not value, but only for single-attribute range/equality checks; bitwise AND over multi-bit fields with implication closure is not supported |
| WIMSE WTS + ABAC | Policy engine evaluates claims in WTS | Policy engine sees all claim values in the token | **No** — evaluator sees inputs |
| RFC 8693 token exchange | AS evaluates narrowing policy at exchange time | AS sees full scope; RS sees exchanged scope list | **No** — RS sees resulting scope strings |

In the Bolyra construction, the RS provides `requiredScopeMask` (public input), receives a proof (constant-size, 256 bytes), and verifies it. The verification returns a boolean. The RS never sees `permissionBitmask`, never sees which specific bits are set, never sees whether the agent holds 3 permissions or 30. The zero-knowledge property is not an optimization — it is the mechanism.

### Axis 1: Constant-size proof regardless of permission space cardinality

A Groth16 proof is 256 bytes: 3 group elements on BN254. This holds whether the bitmask is 8 bits or 64 bits or (with a larger ptau) 256 bits. The proof size is determined by the proving system, not the permission space.

- JWT introspection response: O(|scopes|) in the filtered scope string
- BBS+ derived proof: O(|disclosed|) group elements
- Bolyra: O(1) — 256 bytes, always

For a 64-bit permission space (2^64 possible permission configurations), enumerating scope strings is infeasible. BBS+ would require 64 messages in the credential (one per bit), producing derived proofs proportional to the number of disclosed bits. The ZK construction produces the same 256-byte proof regardless.

### Axis 2: Adversarial-AS soundness

The circuit's soundness rests on Groth16 knowledge soundness in the generic group model, not on AS honesty. The operator's EdDSA signature is verified inside the circuit against the operator's public key (committed in the credential). The Merkle root is checked against on-chain state. A compromised AS cannot:
- Forge the operator's EdDSA signature (DL hardness on Baby Jubjub)
- Insert a false leaf into the Merkle tree (append-only contract with access control)
- Produce a valid Groth16 proof without a valid witness (knowledge soundness)

The entire RFC 7662 stack collapses if the AS lies. This is not a hypothetical: AS compromise is a standard threat in enterprise OAuth deployments, and the RS has no cryptographic recourse in the baseline.

### Axis 3: No composition required

The baseline requires composing 5+ specifications (RFC 7662, jwt-introspection-response, RFC 8707, RFC 9449, BBS+) to approach — but not reach — the properties achieved by a single Groth16 proof. Each composition point introduces:
- Specification gap risk (the composed behavior is not specified by any single RFC)
- Implementation divergence (no reference implementation covers the full stack)
- Upgrade coordination (a change to any one spec may break the composition)

The Bolyra construction achieves enrollment proof, operator authentication, scope predicate satisfaction, input-privacy, session binding, and replay prevention in a single circuit with a single proof.

### Summary

The baseline's ceiling is **selective disclosure of named claims** — the RS learns fewer claims, but still learns the values of the claims it sees. BBS+ NIZK predicate proofs approach input-privacy for simple single-attribute predicates (range checks, equality), but do not support bitwise AND over a multi-bit permission field with implication closure semantics.

The Bolyra construction achieves **input-private predicate satisfaction**: the RS learns only the boolean result of an arbitrary bitmask predicate, not the input. This is an information-theoretic guarantee (under the zero-knowledge property of the proving system), not a policy configuration. No composition of RFC 7662, BBS+, WIMSE, or ABAC mechanisms can replicate a property that requires the evaluating party to NOT see the evaluation inputs — because in every baseline mechanism, the evaluating party is the one reading the inputs.
