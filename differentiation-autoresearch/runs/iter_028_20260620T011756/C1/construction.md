# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its 64-bit permission bitmask satisfies an RS-specified mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of `permissionBitmask` beyond the predicate outcome. The proof is:

- **AS-blind**: generated locally by the agent with no authorization-server roundtrip at presentation time.
- **Constant-size**: a single Groth16 or PLONK proof (~128 or ~256 bytes) regardless of bitmask width or predicate complexity.
- **Runtime-adaptive**: the RS chooses `requiredScopeMask` at the moment of the request; the agent proves satisfaction against whatever mask is demanded without reissuance.
- **Adversarial-AS-resilient**: the RS trusts the on-chain Merkle root and the proving system's knowledge soundness, not the AS's attestation. A compromised AS cannot forge scope satisfaction proofs for agents it did not enroll.
- **Model-identity-bound**: the proof commits to the agent's `modelHash`, `operatorPubKey`, and `permissionBitmask` via a Poseidon5 credential commitment, binding scope satisfaction to a specific runtime identity.

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, and W3C VC/BBS+ can simultaneously achieve all five properties.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `AgentPolicy(MAX_DEPTH=20)`

The construction uses the Bolyra `AgentPolicy` circuit as specified in `draft-bolyra-mutual-zkp-auth-01`, Section 4.2.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Poseidon hash of model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | [0, 2^64) | Agent's full 64-bit permission bitfield |
| `expiryTimestamp` | [0, 2^64) | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | ≤ 20 | Actual Merkle depth |
| `merkleProofIndex` | [0, 2^20) | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Sibling hashes, zero-padded |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | [0, 2^64) | RS-chosen predicate: which bits must be set |
| `currentTimestamp` | [0, 2^64) | Verifier-supplied wall-clock time |
| `sessionNonce` | F_p | Fresh per-request nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history) |
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` |
| `scopeCommitment` | F_p | `Poseidon2(permissionBitmask, credentialCommitment)` |

### Gadgets and constraints

1. **Range checks** — `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. Prevents field-overflow attacks where values ≥ 2^64 pass the circuit but overflow Solidity `uint64`.

2. **Credential commitment** — `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. Binds scope to runtime model identity.

3. **EdDSA signature verification** — `EdDSAPoseidonVerifier(operatorPubKey, credentialCommitment, sig)`. Proves the operator authorized this credential.

4. **Merkle membership** — `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf. Proves enrollment in the on-chain agent registry.

5. **Scope satisfaction (the core selective-disclosure gadget):**
   ```
   permBits[64] = Num2Bits(64)(permissionBitmask)
   reqBits[64]  = Num2Bits(64)(requiredScopeMask)
   for i in [0, 64):
       reqBits[i] * (1 - permBits[i]) === 0
   ```
   This is equivalent to `requiredScopeMask & permissionBitmask == requiredScopeMask`. The RS learns only that the predicate holds, not which additional bits are set.

6. **Cumulative-bit implication closure:**
   ```
   permBits[4] * (1 - permBits[3]) === 0   // FINANCIAL_UNLIMITED → FINANCIAL_MEDIUM
   permBits[4] * (1 - permBits[2]) === 0   // FINANCIAL_UNLIMITED → FINANCIAL_SMALL
   permBits[3] * (1 - permBits[2]) === 0   // FINANCIAL_MEDIUM   → FINANCIAL_SMALL
   ```
   Enforces tier hierarchy inside the circuit, not as a policy-layer convention.

7. **Expiry** — `LessThan(64)(currentTimestamp, expiryTimestamp)`. Credential must be live.

8. **Nullifier** — `Poseidon2(credentialCommitment, sessionNonce)`. Replay detection per session.

9. **Scope commitment** — `Poseidon2(permissionBitmask, credentialCommitment)`. Identity-bound chain-linking output for downstream delegation.

### Verification protocol (RS perspective)

1. RS generates fresh `sessionNonce`, selects `requiredScopeMask` for the requested resource, reads `currentTimestamp`.
2. Agent receives `(requiredScopeMask, currentTimestamp, sessionNonce)` as public inputs.
3. Agent generates proof π locally using private credential material. **No AS contact.**
4. RS receives `(π, publicSignals[6])`.
5. RS checks:
   - `agentMerkleRoot` ∈ on-chain root history buffer (last 30 roots).
   - `nullifierHash` is fresh (not in used-nonce mapping).
   - `requiredScopeMask` matches what the RS specified.
   - `currentTimestamp` is within acceptable clock skew (e.g., ±30 seconds).
   - Groth16/PLONK verification passes.
6. RS accepts. It learns nothing about `permissionBitmask` beyond `permissionBitmask & requiredScopeMask == requiredScopeMask`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The authorization server (AS) — can issue arbitrary tokens, lie about scope membership, collude with other parties.
- The network between agent and RS — can observe, delay, and replay messages.
- Up to `N-1` of `N` enrolled agents' credential material (corruption threshold).
- Any number of RS endpoints (for cross-RS linkability attacks).

The adversary does NOT control:
- The on-chain Merkle root (secured by the underlying L1/L2 consensus).
- The Groth16/PLONK trusted setup (honest-majority ceremony assumption).
- The agent's private credential fields (for the honest agent under test).

### Game: Selective Scope Unforgeability (SSU)

```
Game SSU(λ):
  1. Setup: Generate CRS for AgentPolicy circuit. Deploy on-chain registry.
  2. Enrollment: Challenger enrolls honest agent with credential
     (modelHash, operatorPubKey, permissionBitmask*, expiryTimestamp)
     into the Merkle tree.
  3. Query phase: A may:
     a. Request proofs for any (requiredScopeMask, sessionNonce) where
        permissionBitmask* & requiredScopeMask == requiredScopeMask.
     b. Corrupt any other enrolled agent.
     c. Compromise the AS entirely.
  4. Forgery: A outputs (π*, pubSignals*) for a requiredScopeMask* where
     permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*
     (i.e., the honest agent does NOT satisfy the predicate).
  5. A wins if the on-chain verifier accepts (π*, pubSignals*) with
     agentMerkleRoot matching a valid root containing the honest agent's leaf.
```

**Claim:** No PPT adversary wins SSU with non-negligible probability under the assumptions in §4.

### Game: Scope Privacy (SP)

```
Game SP(λ):
  1. Setup: as above.
  2. Challenger enrolls two agents with bitmasks b₀, b₁ where
     b₀ & requiredScopeMask == requiredScopeMask AND
     b₁ & requiredScopeMask == requiredScopeMask
     (both satisfy the predicate, but differ in other bits).
  3. Challenger flips coin c ∈ {0,1}, generates proof πc for agent c.
  4. A receives (πc, publicSignals). A outputs guess c'.
  5. A wins if c' = c.
```

**Claim:** Pr[A wins SP] ≤ 1/2 + negl(λ) under Groth16 zero-knowledge / PLONK honest-verifier ZK.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Where used |
|----|-----------|------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) | SSU game — extracting witness from valid proof |
| A2 | **Knowledge soundness of PLONK** (universal SRS, ROM) | SSU game (PLONK variant) |
| A3 | **Poseidon collision resistance** over BN254 scalar field | Merkle membership, credential commitment binding |
| A4 | **Discrete logarithm hardness on Baby Jubjub** | EdDSA unforgeability, operator key binding |
| A5 | **Poseidon acts as a PRF** when keyed by the secret | Nullifier unlinkability across sessions |
| A6 | **Zero-knowledge property of Groth16/PLONK** | Scope Privacy game |

### Reduction sketch for SSU

1. Suppose A wins SSU with non-negligible probability ε.
2. By A1 (Groth16 knowledge soundness), extract witness `w = (modelHash, operatorPubKey, permissionBitmask', expiryTimestamp, sig, merkleProof)` from π*.
3. The circuit enforces `reqBits[i] * (1 - permBits'[i]) === 0` for all i ∈ [0,64). So `permissionBitmask' & requiredScopeMask* == requiredScopeMask*`.
4. The circuit enforces `credentialCommitment' = Poseidon5(modelHash, ..., permissionBitmask', expiryTimestamp)`.
5. The circuit enforces Merkle membership of `credentialCommitment'` under `agentMerkleRoot`.
6. Since `agentMerkleRoot` matches a valid on-chain root containing the honest agent's leaf:
   - If `credentialCommitment' = credentialCommitment*` (honest agent's commitment), then by Poseidon collision resistance (A3), `permissionBitmask' = permissionBitmask*`. But we assumed `permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*`. Contradiction.
   - If `credentialCommitment' ≠ credentialCommitment*`, then A enrolled a different agent whose bitmask does satisfy the predicate. This is not a forgery against the honest agent — it's a legitimate proof for a different agent. The SSU game restricts the winning condition to the honest agent's leaf, so this case requires a Merkle collision (A3) or a second preimage for the credential commitment (A3). Both contradict A3.
7. Therefore ε is negligible. ∎

### Reduction sketch for SP

By A6, Groth16 proofs are zero-knowledge: the simulator produces proofs indistinguishable from real proofs without knowledge of the witness. Since `permissionBitmask` is a private input, and the only public signals are `agentMerkleRoot`, `nullifierHash`, `scopeCommitment`, `requiredScopeMask`, `currentTimestamp`, and `sessionNonce` — none of which leak individual bits of `permissionBitmask` beyond predicate satisfaction — A cannot distinguish b₀ from b₁.

Note: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is public, but under A3 (Poseidon preimage resistance), recovering `permissionBitmask` from `scopeCommitment` is infeasible. Different bitmasks yield distinct scope commitments, but the adversary in SP sees only one proof and cannot test which bitmask produced it without inverting Poseidon. ∎

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Hash function | Poseidon over BN254 scalar field | §2.2 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` | §4.2 |
| Scope satisfaction | Bitwise AND via `Num2Bits(64)` + per-bit constraint | §4.2, constraint 5 |
| Cumulative-bit closure | Implication constraints on bits 2/3/4 | §4.2, constraint 6 |
| Operator binding | `EdDSAPoseidonVerifier` on Baby Jubjub | §4.2, constraint 3 |
| Enrollment proof | `BinaryMerkleRoot(20)` with Poseidon2 node hash | §4.2, constraint 4 |
| Nullifier | `Poseidon2(credentialCommitment, sessionNonce)` | §4.2 |
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §3, §4.2 |
| Proving system (primary) | Groth16 with project `pot16.ptau` Phase 1 | §2.3 |
| Proving system (optional) | PLONK universal setup | §2.3 |
| Root history | 30-entry circular buffer on-chain | §2.1 |

## 6. Circuit cost estimate

### Constraint breakdown for `AgentPolicy(MAX_DEPTH=20)`

| Gadget | Constraints (approx.) |
|--------|----------------------|
| `Num2Bits(64)` × 3 (bitmask, expiry, timestamp) | 192 |
| `Poseidon5` (credential commitment) | ~1,200 |
| `EdDSAPoseidonVerifier` | ~6,500 |
| `BinaryMerkleRoot(20)` (20 × Poseidon2 + MUX) | ~12,000 |
| Scope satisfaction (64 per-bit constraints) | 64 |
| Cumulative-bit implication (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` × 2 (nullifier + scopeCommitment) | ~600 |
| **Total** | **~20,700** |

This fits comfortably under 2^16 = 65,536 constraints, confirming `pot16.ptau` sufficiency.

### Proving time targets

| Proving system | Target | Platform |
|---------------|--------|----------|
| Groth16 (snarkjs, WASM) | < 5 s | Browser / Node.js |
| Groth16 (rapidsnark, native) | < 0.5 s | Server-side agent |
| PLONK (snarkjs) | < 5 s | Server-side agent |

### Proof size

| System | Proof size | Public signals |
|--------|-----------|---------------|
| Groth16 | 128 bytes (3 G1 + 1 G2 point, compressed) | 6 × 32 bytes = 192 bytes |
| PLONK | ~256 bytes | 6 × 32 bytes = 192 bytes |

**Total on-wire: 320–448 bytes** regardless of bitmask width, predicate complexity, or permission-space cardinality.

## 7. Concrete deployment scenario

### Scenario: Federated Credit Union Agent Authorization

**Stakeholder:** A CUSO (Credit Union Service Organization) operating a shared data platform across 200 member credit unions, regulated under NCUA §701.27 (third-party due diligence).

**Setup:**
- Each credit union operates AI agents (loan underwriting, fraud detection, member service) with varying permission levels.
- The CUSO's shared platform hosts APIs for member PII lookup, transaction history, and inter-CU wire initiation.
- Permissions span 8 tiers (Bolyra's cumulative-bit encoding): `READ_DATA` through `ACCESS_PII`.

**Problem the baseline cannot solve:**
- The CUSO cannot run a single centralized AS trusted by all 200 CUs — each CU's compliance officer insists on independent credential issuance.
- An agent from CU-A accessing CU-B's member data via the shared platform must prove `READ_DATA ∧ ACCESS_PII` without revealing that it also holds `FINANCIAL_UNLIMITED` (a competitive signal).
- The CUSO platform (RS) must verify authorization without trusting any individual CU's AS — a CU could be compromised and issue inflated tokens.

**Bolyra deployment:**
1. Each CU enrolls its agents into the shared Bolyra agent Merkle tree (deployed on Base Sepolia, graduating to Base mainnet). Enrollment requires an operator EdDSA signature over the credential commitment.
2. When CU-A's fraud-detection agent calls the CUSO platform's `/member/transactions` endpoint, the platform returns `requiredScopeMask = 0b10000001` (bits 0 and 7: `READ_DATA | ACCESS_PII`).
3. The agent generates a Groth16 proof locally (rapidsnark, < 0.5 s) proving its bitmask satisfies the mask. The CUSO platform learns only that the predicate holds — not whether the agent also holds `FINANCIAL_UNLIMITED`, `SIGN_ON_BEHALF`, or `SUB_DELEGATE`.
4. The platform checks `agentMerkleRoot` against the on-chain root history buffer. No AS is contacted. No CU's AS is trusted.
5. The agent's credential expiry is enforced inside the circuit. Revocation is handled by updating the Merkle tree (removing the credential leaf).

**Regulatory value:** NCUA examiners can audit the on-chain enrollment registry without accessing any agent's private credential fields. The ZK proof provides cryptographic assurance of authorization that satisfies third-party due diligence requirements without creating a centralized authority that any single CU must trust.

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + RFC 8707 + DPoP + BBS+) fails on five properties that this construction achieves simultaneously. No subset or composition of the baseline stack can close these gaps.

### Gap 1: AS-blind presentation

In the baseline, the AS is the sole authority that determines and attests to the agent's scope. Even with jwt-introspection-response caching, the AS was contacted at issuance and at first introspection. The agent cannot present a selective scope proof to a *new* RS without the AS having been involved for that audience (RFC 8707 requires audience-specific token issuance). BBS+ allows holder-driven selective disclosure over discrete claims, but the AS still issues the original BBS+ signature — a compromised AS can refuse to sign, or sign incorrect claims.

**Bolyra construction:** The agent generates proofs locally against an on-chain Merkle root. The operator signed the credential at enrollment time; no AS is contacted at presentation time. The agent chooses which `requiredScopeMask` to prove against at runtime, without reissuance.

### Gap 2: Runtime-adaptive bitmask predicate with implication closure

The baseline's scope model is string-based (`scope: "read write financial_small"`). Predicate evaluation is string-set membership, not bitwise Boolean logic. BBS+ supports equality and range predicates over hidden attributes, but bitwise AND over a 64-bit field with implication closure (bit 4 ⟹ bits 3 and 2) requires arithmetic-circuit-level evaluation. No BBS+ extension in `draft-irtf-cfrg-bbs-signatures` or `vc-di-bbs` supports this.

**Bolyra construction:** The `AgentPolicy` circuit evaluates `reqBits[i] * (1 - permBits[i]) === 0` for all 64 bits and enforces cumulative-bit implication constraints inside the R1CS. The predicate is evaluated over the hidden bitmask at proof time, not fixed at issuance.

### Gap 3: Adversarial-AS model

The baseline's trust anchor is the AS's signing key. A compromised AS can assert that an agent holds scopes it does not, or deny scopes it does hold. The RS has no cryptographic recourse — it verifies only that "the AS said X," not that X is true.

**Bolyra construction:** The trust anchor is the on-chain Merkle root (consensus-secured) and the Groth16 knowledge soundness guarantee. The proof extracts a witness containing a valid credential commitment that is a leaf in the tree. No party — including the entity that enrolled the agent — can forge a proof for a bitmask that does not satisfy the predicate without breaking Poseidon collision resistance or Groth16 soundness. The AS is not in the trust path.

### Gap 4: Constant-size proof regardless of permission-space cardinality

In the baseline, jwt-introspection-response size scales linearly with disclosed scopes. BBS+ derived proof size scales with `O(|disclosed|)`. For a permission space with 64 independent bits (2^64 theoretical combinations), enumeration-based approaches are infeasible.

**Bolyra construction:** The Groth16 proof is 128 bytes. The PLONK proof is ~256 bytes. Neither depends on the number of bits in `permissionBitmask`, the number of bits set in `requiredScopeMask`, or the cardinality of the permission space. A 64-bit bitmask and a 256-bit bitmask (with proportionally more constraints) still produce a constant-size proof.

### Gap 5: Cryptographic binding to runtime model identity

The baseline's `client_id` is a static string registered at the AS. It does not bind the token to a specific model hash, operator key, or permission state at the moment of a specific API call.

**Bolyra construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` binds the scope proof to a specific model, a specific operator, and a specific permission state. The EdDSA signature over this commitment proves the operator authorized this exact combination. Changing the model or operator requires a new credential — there is no way to reuse a proof across model versions or operator keys.

### Summary: simultaneous achievement

| Property | RFC 7662 stack | BBS+ layer | Bolyra AgentPolicy |
|----------|---------------|------------|-------------------|
| AS-blind presentation | No | No (AS signs credential) | **Yes** |
| Runtime-adaptive bitmask predicate | No | Partial (no bitwise AND) | **Yes** |
| Adversarial-AS resilience | No | No (AS trust anchor) | **Yes** |
| Constant-size proof | No | O(\|disclosed\|) | **Yes** (128–256 bytes) |
| Model-identity binding | No | No | **Yes** |
| All five simultaneously | **Impossible** | **Impossible** | **Yes** |

The baseline can achieve subsets (BBS+ gives selective disclosure; DPoP gives sender binding; jwt-introspection-response gives offline verification), but no composition achieves all five. The fundamental barrier is architectural: the baseline stack trusts the AS as the scope authority, while this construction trusts the proving system and the on-chain enrollment root. These are incompatible trust models — you cannot retrofit AS-independence onto a stack whose security definition requires AS honesty.
