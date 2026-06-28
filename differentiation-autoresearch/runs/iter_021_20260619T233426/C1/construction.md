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

### Circuit: `AgentSelectiveScope`

This is the existing `AgentPolicy` circuit (spec §4.2) deployed in standalone RS-authorization mode — no mutual handshake required for this use case. The circuit already implements the selective scope proof; this construction formalizes the deployment pattern.

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
| `scopeCommitment` | F_p | `Poseidon2(permissionBitmask, credentialCommitment)` — chain-linking anchor |

### Gadgets (in constraint order):

1. **Range checks**: `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. Prevents field-overflow attacks where values ≥ 2^64 pass the circuit but wrap in Solidity uint64.

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

9. **Scope commitment**: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`.

### Verification flow (RS-side):

1. RS generates a fresh `sessionNonce` (≥128 bits, cryptographically random).
2. RS sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to the agent.
3. Agent generates a Groth16 or PLONK proof using its private credential fields.
4. Agent sends `(proof, publicSignals)` to the RS.
5. RS verifies:
   - `agentMerkleRoot` ∈ on-chain root history buffer (read from contract or cached).
   - `nullifierHash` not previously seen for this `sessionNonce`.
   - `requiredScopeMask` matches the RS's own public input.
   - `currentTimestamp` is within acceptable skew of RS's wall clock.
   - Groth16/PLONK proof verifies against the deployed verifier contract or off-chain verifier key.
6. On success: the agent is authorized for the requested scope. The RS learns nothing about `permissionBitmask` beyond `permissionBitmask & requiredScopeMask == requiredScopeMask`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A may control any combination of:

- **The Authorization Server (AS)**: A controls credential issuance policy, can refuse to enroll agents, can attempt to forge credentials. However, A does not possess any honest operator's EdDSA private key.
- **Colluding Resource Servers**: A controls multiple RSes that compare notes (proofs, nullifiers, scope commitments) to attempt linkability or permission inference.
- **Network position**: A observes all proof transcripts between agent and RS (passive eavesdropper).
- **Malicious agents**: A may generate proofs with credentials it does not hold, or attempt to prove permissions it was not granted.

A does **not** control:
- The BN128 pairing (no subgroup attacks).
- The Poseidon hash (no preimage/collision attacks).
- The Baby Jubjub discrete log (no key recovery).
- The on-chain Merkle tree state (immutable once committed; root history buffer is append-only).

### Security game: Selective Scope Unforgeability

**Game `SSU(λ)`:**

1. **Setup**: Challenger runs `Setup(1^λ)` producing Groth16 CRS `(pk, vk)` and an empty Merkle tree T.
2. **Enrollment oracle**: A may request enrollment of credentials `(modelHash, operatorPubkey, permissionBitmask, expiry)` into T. Challenger signs with the operator key and inserts `credentialCommitment` as a leaf. A receives the Merkle root but not the operator private key.
3. **Challenge**: A outputs `(π*, pubSignals*)` where `pubSignals*` includes a `requiredScopeMask` value `M*`.
4. **A wins if**:
   - `Verify(vk, π*, pubSignals*) = 1`, AND
   - There is no enrolled credential whose `permissionBitmask` satisfies `permissionBitmask & M* == M*`.

**Claim**: `Pr[A wins SSU(λ)] ≤ negl(λ)` under the assumptions in §4.

### Privacy game: Scope Indistinguishability

**Game `SI(λ)`:**

1. **Setup**: Same as SSU.
2. **Enrollment**: Challenger enrolls two credentials C₀, C₁ with distinct bitmasks `B₀ ≠ B₁`, both satisfying a common `requiredScopeMask` M (i.e., `B₀ & M == M` and `B₁ & M == M`).
3. **Challenge**: Challenger flips coin b ∈ {0,1}, generates proof π_b for credential C_b with mask M.
4. **A outputs b'**.
5. **A wins if** b' = b.

**Claim**: `|Pr[b' = b] - 1/2| ≤ negl(λ)` — the proof reveals nothing about which credential (hence which bitmask) generated it, beyond satisfaction of M.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| Label | Assumption | Standard reference |
|-------|------------|--------------------|
| **A1** | Knowledge soundness of Groth16 in the generic group model | [Groth16, EUROCRYPT 2016] |
| **A2** | Knowledge soundness of PLONK in the algebraic group model + ROM | [GWC19, IACR 2019/953] |
| **A3** | Collision resistance of Poseidon over F_p (BN254 scalar field) | [Grassi et al., USENIX Security 2021] |
| **A4** | Discrete log hardness on Baby Jubjub (embedded curve in BN254) | Inherited from BN254 subgroup security |
| **A5** | EdDSA-Poseidon EUF-CMA security under A3 + A4 | Schnorr-type argument in twisted Edwards form |

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

### Reduction sketch for SI (privacy)

By the zero-knowledge property of Groth16 (simulation in the CRS model), the proof π reveals nothing about the witness beyond the public signals. Since `permissionBitmask` is a private input and does not appear in any public output (only `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` appears, which is computationally hiding under **A3**), no PPT adversary can distinguish which credential generated the proof.

The `scopeCommitment` output does commit to `permissionBitmask`, but recovering the bitmask requires inverting Poseidon — which contradicts **A3** (preimage resistance). Two credentials with different bitmasks produce different scope commitments, but linking a scope commitment to a specific bitmask requires knowledge of the `credentialCommitment` (also private). An RS that does not know the credential commitment cannot extract the bitmask from the scope commitment.

**Caveat**: If the RS colludes with the enrollment authority and obtains the `credentialCommitment`, it can check `Poseidon2(candidateBitmask, credentialCommitment) == scopeCommitment` for each candidate bitmask. For a 64-bit space this is feasible by brute force. Mitigation: in the standalone RS-authorization mode, the `scopeCommitment` output can be omitted from the public signals (it is only needed for delegation chain linking). A variant circuit `AgentSelectiveScopeMinimal` that drops the `scopeCommitment` output achieves unconditional scope indistinguishability under Groth16 ZK.

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
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | Spec §2 (Scope Commitment) |
| Proving system | Groth16 (required) or PLONK (optional) for agent circuits | Spec §3.3 |
| Root history buffer | 30-entry circular buffer, on-chain | Spec §2 |

No new primitives are introduced. The construction uses exclusively the circuit, gadgets, and proving system already specified in `draft-bolyra-mutual-zkp-auth-01`.

## 6. Circuit cost estimate

### Constraint breakdown (AgentPolicy / AgentSelectiveScope)

| Gadget | Estimated constraints |
|--------|----------------------|
| `Num2Bits(64)` × 3 (bitmask, expiry, timestamp) | 192 |
| `Poseidon5` (credential commitment) | ~1,500 |
| `EdDSAPoseidonVerifier` | ~7,500 |
| `BinaryMerkleRoot(20)` with Poseidon2 | ~30,000 (20 levels × ~1,500 per Poseidon2) |
| Scope satisfaction (64 multiplication constraints) | 64 |
| Cumulative bit implication (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` × 2 (nullifier + scope commitment) | ~3,000 |
| **Total** | **~42,400** |

### Proving time targets

| Proving system | Target | Device | Notes |
|----------------|--------|--------|-------|
| Groth16 (snarkjs, WASM) | < 8s | Modern laptop | Conservative; benchmarks show ~5s for 40K constraints |
| Groth16 (rapidsnark, native) | < 1s | Server with rapidsnark binary | Production path |
| PLONK (snarkjs) | < 5s | Modern laptop | Universal setup avoids per-circuit ceremony |

All targets are within the spec's PLONK agent budget of <5s. The Groth16 rapidsnark path is the production recommendation for latency-sensitive RS authorization.

### Proof size

| Proving system | Proof size | Public signals |
|----------------|-----------|----------------|
| Groth16 | 128 bytes (3 G1/G2 elements, compressed) | 6 × 32 bytes = 192 bytes |
| PLONK | ~560 bytes | 6 × 32 bytes = 192 bytes |

Total on-wire payload: **320 bytes (Groth16)** or **752 bytes (PLONK)**. Constant regardless of bitmask width — a 64-bit and a hypothetical 1024-bit bitmask produce identical proof sizes.

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
3. The loan agent generates a Groth16 proof (via rapidsnark, <1s) proving its bitmask `0b00010111` satisfies `& 0b00000110 == 0b00000110`. The RS never sees that the agent also holds FINANCIAL_MEDIUM or READ_DATA.
4. The RS verifies the proof against the on-chain root and the verifier key. No call to the credit union's AS. No call to any identity provider.
5. The RS authorizes the disbursement. The proof transcript is logged for audit.

**Why ZK matters here**:
- The core banking RS is operated by a separate entity (a CUSO or fintech partner). The credit union does not want the partner to learn its full permission topology — that reveals internal policy structure, agent capabilities, and organizational risk appetite.
- Under NCUA examination, the credit union can replay the proof transcript to demonstrate that the agent was authorized for exactly the requested scope at the time of the transaction, with cryptographic assurance independent of the partner's attestation.
- If the partner's AS is compromised, it cannot retroactively claim the agent had permissions it did not — the proof is bound to the operator's EdDSA signature over the credential commitment.

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

The Groth16 proof is 128 bytes. Always. Whether the bitmask is 8 bits or 2048 bits (with a proportionally larger circuit), the proof is 3 group elements. The public signals are 6 field elements (192 bytes). Total payload: 320 bytes, constant.

### Gap 5: Cumulative Implication Enforcement at Proof Time

BBS+ has no mechanism to enforce that bit 4 → bit 3 → bit 2 within a selective disclosure presentation. The issuer could encode these as separate claims, but the holder-derived presentation has no circuit to enforce implication closure. An AS could enforce this at issuance, but a compromised AS (Gap 3) would not.

The Bolyra circuit enforces implication closure via 3 explicit constraints before the scope satisfaction check runs. A credential with `FINANCIAL_UNLIMITED` set but `FINANCIAL_MEDIUM` unset is rejected by the circuit — no valid proof can be generated. This is enforced cryptographically, not by policy.

### Summary: Properties the baseline fundamentally cannot express

| Property | Baseline ceiling | Bolyra construction |
|----------|-----------------|---------------------|
| AS involvement at proof time | Required (issuance or introspection) | None — agent proves locally |
| Predicate adaptability | Fixed at issuance; re-issue for new predicates | RS chooses `requiredScopeMask` per-request |
| Trust anchor | AS signing key (single point of compromise) | Operator EdDSA + on-chain Merkle root |
| Proof size scaling | O(disclosed claims) for BBS+; O(scope strings) for JWT | O(1) — constant 320 bytes |
| Implication closure enforcement | Policy-only (bypassable by compromised AS) | Circuit-enforced (cryptographic) |
| Model identity binding | `client_id` string (no cryptographic binding) | `credentialCommitment` includes `modelHash` + operator key |
