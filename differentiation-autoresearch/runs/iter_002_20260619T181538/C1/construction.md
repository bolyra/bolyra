The file write keeps being denied. Let me output the construction directly:

# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its permission bitmask satisfies a verifier-specified mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of the permission bitmask beyond predicate satisfaction, in a single constant-size proof, with no authorization server (AS) roundtrip at presentation time, and with security that holds even when the AS is fully adversarial (colluding, compromised, or offline).

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, RFC 9449 (DPoP), or W3C VC + BBS+ selective disclosure can simultaneously achieve all five properties: (1) AS-blind presentation, (2) runtime-adaptive bitmask predicate with implication-closure enforcement, (3) adversarial-AS soundness, (4) constant-size proof regardless of bitmask width, and (5) cryptographic binding to the agent's runtime model identity.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: SelectiveScopeProof

A specialization of the existing `AgentPolicy` circuit, restructured for standalone RS-facing presentation (no handshake required). The agent generates this proof at the moment of resource access, with the RS supplying `requiredScopeMask` as the predicate.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Poseidon hash of model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | uint8 | Actual Merkle proof depth |
| `merkleProofIndex` | uint64 | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Sibling hashes (padded to MAX_DEPTH=20) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Current time (RS-supplied) |
| `onChainAgentRoot` | field | Agent Merkle tree root (RS reads from on-chain registry) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopePredicateHash` | field | `Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)` — binds the predicate evaluation to this specific credential and moment |
| `agentNullifier` | field | `Poseidon2(credentialCommitment, requiredScopeMask)` — deterministic per credential per predicate, enables rate-limiting |

### Gadgets (constraint groups)

**G1 — Range checks (4 Num2Bits):**
- `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`, `requiredScopeMask`

**G2 — Credential commitment (1 Poseidon5):**
- `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`

**G3 — Operator signature (1 EdDSAPoseidonVerifier):**
- `EdDSA.Verify((operatorPubkeyAx, operatorPubkeyAy), credentialCommitment, (sigR8x, sigR8y, sigS))`

**G4 — Merkle membership (1 BinaryMerkleRoot):**
- `computedRoot = BinaryMerkleRoot(credentialCommitment, merkleProofSiblings, merkleProofIndex, merkleProofLength)`
- `computedRoot === onChainAgentRoot` (equality constraint against public input)

**G5 — Scope satisfaction (64 bit-AND constraints):**
- For each bit `i` in `[0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`
- Proves `permissionBitmask & requiredScopeMask == requiredScopeMask` without revealing any bit of `permissionBitmask` that is not required.

**G6 — Cumulative bit encoding (3 implication constraints):**
- `permBits[4] * (1 - permBits[3]) === 0`
- `permBits[4] * (1 - permBits[2]) === 0`
- `permBits[3] * (1 - permBits[2]) === 0`

**G7 — Expiry enforcement (1 LessThan):**
- `LessThan(64): currentTimestamp < expiryTimestamp`

**G8 — Predicate binding (1 Poseidon3):**
- `scopePredicateHash = Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)`

**G9 — Agent nullifier (1 Poseidon2):**
- `agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)`

### Verification protocol (RS-side)

1. RS reads `onChainAgentRoot` from the Bolyra on-chain registry (cached, no AS contact).
2. RS constructs public inputs: `[requiredScopeMask, currentTimestamp, onChainAgentRoot]`.
3. RS receives proof `pi` and public outputs `[scopePredicateHash, agentNullifier]` from the agent.
4. RS calls the PLONK verifier contract (or verifies locally with the verification key): `Verify(vk, pi, pubSignals)`.
5. RS checks `agentNullifier` against a local rate-limit table (optional).
6. On success: the agent has the required permissions, the credential is unexpired, and the credential is enrolled on-chain — all without learning the agent's full permission set, model hash, operator key, or any other credential field.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls:
- The authorization server (AS) — can issue arbitrary tokens, lie in introspection responses, collude with other parties
- Network position — can observe all RS-agent traffic
- Up to `N-1` of `N` enrolled agents (corrupted agents whose secrets are known)

The adversary does NOT control:
- The on-chain registry (Ethereum/Base L2 consensus assumptions)
- The RS's local copy of the PLONK verification key
- The honest agent's private inputs (secret, operator key)

### Security game: Selective Scope Forgery

```
Game SelectiveScopeForgery(lambda):
  1. Setup: Run trusted setup for SelectiveScopeProof circuit -> (pk, vk)
  2. Enrollment: Challenger enrolls honest agent credential commitment C*
     into the on-chain Merkle tree. A learns C* but not the private inputs.
  3. Oracle: A may query the honest agent for proofs on predicates of A's
     choice (chosen-predicate queries). A receives (pi, scopePredicateHash,
     agentNullifier) for each query.
  4. Challenge: A outputs (pi*, pubSignals*) where requiredScopeMask* is a
     predicate that the honest agent's permissionBitmask does NOT satisfy
     (i.e., exists bit i: requiredBits*[i] = 1 and permBits[i] = 0).
  5. A wins if Verify(vk, pi*, pubSignals*) = ACCEPT and the
     onChainAgentRoot in pubSignals* is a valid root from the registry's
     root history buffer.
```

**Claim:** `Pr[A wins] <= negl(lambda)` under the assumptions in Section 4.

### Privacy game: Scope Extraction

```
Game ScopeExtraction(lambda):
  1. Setup and enrollment as above.
  2. Challenge: A chooses two permission bitmasks B0, B1 such that both
     satisfy the same requiredScopeMask R. Challenger flips coin b <- {0,1},
     generates proof with Bb.
  3. A receives (pi, scopePredicateHash, agentNullifier).
  4. A outputs guess b'.
  5. A wins if b' = b.
```

**Claim:** `|Pr[A wins] - 1/2| <= negl(lambda)` under PLONK zero-knowledge.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Knowledge soundness of PLONK** (with universal SRS): Any PPT prover that produces an accepting proof knows a valid witness satisfying all circuit constraints.
2. **Collision resistance of Poseidon** over BN254 scalar field: No PPT adversary can find distinct inputs `(x1,...,xn) != (x1',...,xn')` such that `Poseidon(x1,...,xn) = Poseidon(x1',...,xn')`.
3. **Discrete log hardness on Baby Jubjub**: Given `(Ax, Ay) = s * G`, no PPT adversary can recover `s`.
4. **Unforgeability of EdDSA-Poseidon on Baby Jubjub**: No PPT adversary can forge a valid signature on a new message without the signing key.
5. **Random Oracle Model (ROM)**: Fiat-Shamir transform in PLONK is modeled as a random oracle.

### Reduction sketch (soundness)

Suppose adversary `A` wins SelectiveScopeForgery with non-negligible probability `eps`.

By PLONK knowledge soundness (Assumption 1 + 5), extract witness `w = (modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp, sig, merkleProof)` from `A`'s accepting proof.

**Case 1:** The extracted `permissionBitmask` does NOT satisfy `requiredScopeMask*` (i.e., G5 constraints are violated). This contradicts knowledge soundness — the extractor produced a witness that does not satisfy the circuit relation. Contradiction.

**Case 2:** The extracted `permissionBitmask` DOES satisfy `requiredScopeMask*`. Then the extracted `credentialCommitment` must be a leaf in the Merkle tree at root `onChainAgentRoot` (G4). Sub-cases:

- **2a:** `credentialCommitment = C*` (the honest agent's commitment). But the honest agent's bitmask does not satisfy the predicate by game definition. Since `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` and the extracted bitmask differs from the honest agent's, we have a Poseidon5 collision (Assumption 2 violated). Contradiction.

- **2b:** `credentialCommitment != C*` but is still a valid leaf. Then `A` is using a different enrolled agent's credential — not a forgery against the honest agent, but a legitimate proof for a different agent. If `A` controls the credential, this is not a forgery.

- **2c:** `credentialCommitment` is NOT a leaf but `BinaryMerkleRoot` still outputs `onChainAgentRoot`. This requires a second-preimage attack on the Poseidon-based Merkle tree (Assumption 2 violated). Contradiction.

Therefore `Pr[A wins] <= Adv_PLONK_ks + Adv_Poseidon_cr + negl(lambda)`.

### Reduction sketch (privacy)

The ScopeExtraction game reduces directly to PLONK zero-knowledge. Since `permissionBitmask` is a private input and does not appear in any public output — `agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)` is identical for B0 and B1 (same credential, same predicate), and `scopePredicateHash = Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)` is also identical — the public outputs are identical across both challenge worlds. The adversary's only distinguishing information is the proof `pi` itself, which is zero-knowledge. `|Pr[A wins] - 1/2| <= Adv_PLONK_zk`.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---|---|---|
| Hash function (all commitments) | Poseidon over BN254 scalar field | `circuits/src/` — all circuits |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` | `AgentPolicy.circom` G2 |
| Operator signature | EdDSA on Baby Jubjub via `EdDSAPoseidonVerifier` | `AgentPolicy.circom` G3 |
| Merkle inclusion | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | Shared across all circuits |
| Scope predicate | Bit-AND: `requiredBits[i] * (1 - permBits[i]) === 0` | `AgentPolicy.circom` G5 |
| Cumulative encoding | 3 implication constraints (bits 4->3->2) | `AgentPolicy.circom` G6 |
| Nullifier | `Poseidon2(credentialCommitment, requiredScopeMask)` | Adapted from agent nullifier pattern |
| Proving system | PLONK with universal SRS (`pot16.ptau`) | `AgentPolicy` PLONK build in `circuits/build/` |
| On-chain root | Agent Merkle root from `BolyraRegistry` with 30-entry root history buffer | `contracts/` |

No new cryptographic building blocks introduced. Key differences from existing `AgentPolicy`: (a) `onChainAgentRoot` is a public input (RS-verified against chain state, not just a proof output), (b) `scopePredicateHash` binds the evaluation to a timestamp, (c) nullifier is scoped per predicate rather than per session nonce.

## 6. Circuit cost estimate

| Gadget | Estimated constraints | Notes |
|---|---|---|
| G1: 4x Num2Bits(64) | 256 | 64 constraints each |
| G2: Poseidon5 | ~1,500 | 5-input Poseidon, ~8 full rounds + 57 partial |
| G3: EdDSAPoseidonVerifier | ~8,000 | Dominant cost: Baby Jubjub scalar mul + Poseidon |
| G4: BinaryMerkleRoot(20) | ~6,000 | 20 levels x (Poseidon2 + mux) |
| G5: 64 bit-AND constraints | 64 | One multiplication each |
| G6: 3 implication constraints | 3 | One multiplication each |
| G7: LessThan(64) | ~130 | Num2Bits(65) + comparator |
| G8: Poseidon3 | ~1,000 | 3-input Poseidon |
| G9: Poseidon2 | ~700 | 2-input Poseidon |
| **Total** | **~17,650** | Well within 2^16 = 65,536 (pot16.ptau) |

**Proving time targets:**
- PLONK (snarkjs): **< 3 seconds** on commodity hardware
- PLONK (rapidsnark native): **< 500 ms**
- Verification: **< 2 ms** on-chain, **< 1 ms** off-chain

**Proof size:** 768 bytes (PLONK) — constant regardless of bitmask width or predicate complexity.

## 7. Concrete deployment scenario

### Scenario: Pacific Northwest Credit Union Consortium — AI Agent Loan Processing

**Stakeholder:** Columbia Credit Union (Vancouver, WA) — $3.4B in assets, member of the Northwest Credit Union Association.

**Context:** Columbia CU deploys AI agents to automate member loan pre-qualification across a consortium of 12 credit unions sharing a federated data lake. Each credit union's RS hosts member financial data behind API endpoints. An agent acting on behalf of Columbia CU needs `READ_DATA` (bit 0) and `FINANCIAL_SMALL` (bit 2) to pull credit summaries and run sub-$100 fee calculations — but must NOT reveal that it also holds `FINANCIAL_UNLIMITED` (bit 4) and `ACCESS_PII` (bit 7), reserved for internal Columbia CU operations.

**Problem with baseline:**
1. **Adversarial-AS risk:** Rival credit unions do not trust Columbia CU's AS to be honest about the agent's actual permissions. A compromised AS could claim the agent has `ACCESS_PII` at a partner CU's RS, or deny permissions it actually holds.
2. **AS availability:** During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours. All consortium agents are locked out because partner RSes cannot introspect tokens.
3. **Scope leakage:** Even with BBS+ selective disclosure, the credential issuer knows the full permission set and can correlate which partner CU the agent accessed.

**Bolyra deployment:**
1. Columbia CU enrolls the agent's credential commitment (`Poseidon5(modelHash, opAx, opAy, 0b10010111, expiry)`) into the on-chain Bolyra agent Merkle tree.
2. When the agent contacts a partner CU's RS, the RS specifies `requiredScopeMask = 0b00000101` (bits 0 and 2: `READ_DATA | FINANCIAL_SMALL`).
3. The agent generates a `SelectiveScopeProof` locally (< 500 ms with rapidsnark). The proof is 768 bytes.
4. The partner RS verifies against the on-chain `agentMerkleRoot` — no call to Columbia CU's AS, no trust in Columbia CU's infrastructure, no knowledge of the agent's full permission set.
5. The RS learns exactly one bit of information: the agent satisfies `READ_DATA | FINANCIAL_SMALL`. It learns nothing about `FINANCIAL_UNLIMITED`, `ACCESS_PII`, or any other permission.

**Regulatory alignment:** NCUA examiners reviewing consortium data-sharing agreements can verify that only cryptographically proven minimum-necessary permissions were exercised at each access point — satisfying NCUA guidance on third-party AI risk management (Letter to Credit Unions 24-CU-03).

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + RFC 8707 + DPoP + W3C VC/BBS+) fails on five properties the `SelectiveScopeProof` achieves simultaneously:

### Property 1: AS-blind presentation
**Baseline:** Every RFC 7662 variant requires AS involvement at issuance/introspection. Even cached jwt-introspection-responses were AS-generated.
**Construction:** The agent generates the proof locally. The RS verifies against on-chain state. The AS is not contacted, not informed, not needed.

### Property 2: Runtime-adaptive bitmask predicate with implication closure
**Baseline:** Introspection returns a fixed scope string. BBS+ supports equality/range predicates over discrete claims but cannot evaluate `bitmask & requiredMask == requiredMask` with cumulative-bit implication rules (`bit4 -> bit3 -> bit2`) inside the credential presentation.
**Construction:** The RS specifies `requiredScopeMask` as a public input at verification time. The circuit evaluates the bitwise AND predicate AND enforces implication closure — all inside the proof, with no issuance-time predicate binding.

### Property 3: Adversarial-AS soundness
**Baseline:** RS assurance rests entirely on the AS's signed assertion. A malicious AS can lie. BBS+ credentials are still AS-issued; a malicious issuer can issue fraudulent credentials.
**Construction:** Credential commitment is enrolled on-chain. The RS verifies the Merkle proof against a root the AS cannot unilaterally alter (blockchain consensus). The operator's EdDSA signature is verified inside the circuit. Even a fully compromised AS cannot forge a valid proof.

### Property 4: Constant-size proof regardless of bitmask width
**Baseline:** JWT scope strings grow linearly. BBS+ derived proofs grow with disclosed message count `O(|disclosed|)`. For a 64-bit permission space, enumeration is infeasible.
**Construction:** PLONK proof is exactly 768 bytes regardless of bitmask width, predicate size, or permission count.

### Property 5: Cryptographic binding to runtime model identity
**Baseline:** `client_id` is a static registration string. Neither RFC 7662, DPoP, nor BBS+ bind the token to a specific model hash + operator key + permission bitmask at call time.
**Construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. A different model, operator, or permission set produces a different commitment that is not enrolled.

### Summary

The baseline's limitations are architectural, not configurational. RFC 7662 defines introspection as "the AS tells you about this token" — structurally AS-dependent. BBS+ is structurally issuer-dependent. No layering of DPoP, audience binding, or token exchange changes the trust root.

The `SelectiveScopeProof` moves the trust root from "the AS said so" to "the on-chain Merkle tree contains this commitment, the operator's signature is valid, and the bitmask satisfies the predicate" — verified inside a zero-knowledge proof that reveals nothing beyond predicate satisfaction. This is a category difference, not a degree difference.
