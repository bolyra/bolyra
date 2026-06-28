# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its 64-bit permission bitmask satisfies an RS-specified required-mask predicate (`permissionBitmask & requiredMask == requiredMask`), without revealing any bits of `permissionBitmask` beyond predicate satisfaction, without any Authorization Server (AS) roundtrip at presentation time, in a single constant-size proof, even when the AS is adversarial (i.e., the RS trusts only the on-chain Merkle root and the PLONK/Groth16 knowledge-soundness guarantee, not the AS's attestations).

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, or BBS+ selective disclosure can simultaneously achieve: (a) AS-blind presentation, (b) runtime-adaptive bitwise predicate evaluation over a hidden bitmask with implication-closure enforcement, (c) constant-size proof independent of bitmask width, and (d) security under an adversarial AS.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `SelectiveScopeProof`

This is a specialization of the existing `AgentPolicy` circuit, extracted as a standalone verifier-facing proof. The agent generates this proof at presentation time — after initial enrollment — to convince an RS of scope satisfaction without revealing the full bitmask.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `permissionBitmask` | 64-bit | Agent's full permission bitfield |
| `modelHash` | field | Hash of model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `expiryTimestamp` | 64-bit | Credential expiration (Unix) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credentialCommitment |
| `merkleProofLength` | field | Actual depth of Merkle proof |
| `merkleProofIndex` | field | Leaf index |
| `merkleProofSiblings[20]` | field[] | Sibling hashes (padded to MAX_DEPTH=20) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | 64-bit | RS-specified required permission bits |
| `currentTimestamp` | 64-bit | Current time (from RS/verifier) |
| `sessionNonce` | field | Fresh nonce from RS, binds proof to session |
| `agentMerkleRoot` | field | On-chain agent tree root (RS reads from registry) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeSatisfied` | 1-bit | Always 1 if proof verifies (implicit) |
| `nullifierHash` | field | `Poseidon2(credentialCommitment, sessionNonce)` — replay detection |
| `scopeCommitment` | field | `Poseidon2(permissionBitmask, credentialCommitment)` — delegation chain anchor |

**Constraints (in order):**

1. **Range checks:**
   - `Num2Bits(64)` on `permissionBitmask` → `permBits[0..63]`
   - `Num2Bits(64)` on `requiredScopeMask` → `reqBits[0..63]`
   - `Num2Bits(64)` on `expiryTimestamp`
   - `Num2Bits(64)` on `currentTimestamp`

2. **Credential commitment:**
   ```
   credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)
   ```

3. **EdDSA signature verification:**
   ```
   EdDSAPoseidonVerifier(credentialCommitment, operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS) === 1
   ```

4. **Merkle membership:**
   ```
   BinaryMerkleRoot(20, credentialCommitment, merkleProofIndex, merkleProofSiblings, merkleProofLength) === agentMerkleRoot
   ```
   The RS supplies `agentMerkleRoot` by reading the on-chain registry. The circuit proves the credential is enrolled without revealing which leaf.

5. **Selective scope satisfaction (the core predicate):**
   ```
   for i in [0, 64):
       reqBits[i] * (1 - permBits[i]) === 0
   ```
   This enforces `permissionBitmask & requiredScopeMask == requiredScopeMask`. Every bit required by the RS must be present in the agent's bitmask. Bits NOT in `requiredScopeMask` are completely hidden — the RS learns nothing about them.

6. **Cumulative bit implication closure:**
   ```
   permBits[4] * (1 - permBits[3]) === 0
   permBits[4] * (1 - permBits[2]) === 0
   permBits[3] * (1 - permBits[2]) === 0
   ```
   Prevents agents from constructing invalid bitmask states (e.g., FINANCIAL_UNLIMITED without FINANCIAL_SMALL).

7. **Expiry:**
   ```
   LessThan(64)(currentTimestamp, expiryTimestamp) === 1
   ```

8. **Nullifier:**
   ```
   nullifierHash = Poseidon2(credentialCommitment, sessionNonce)
   ```

9. **Scope commitment:**
   ```
   scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
   ```

### Verification protocol (RS-side):

1. RS generates fresh `sessionNonce`, reads current `agentMerkleRoot` from on-chain registry.
2. RS sends `(requiredScopeMask, currentTimestamp, sessionNonce, agentMerkleRoot)` to agent.
3. Agent generates PLONK proof `π` over `SelectiveScopeProof`.
4. RS verifies `π` against the PLONK verification key. If valid: the agent's enrolled credential satisfies the required mask, is not expired, and is operator-signed.
5. RS checks `nullifierHash` against a local replay cache for the current session window.
6. RS optionally stores `scopeCommitment` to seed a delegation chain.

No AS is contacted. No token is exchanged. The RS trusts only the on-chain root and the proof system's soundness.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls:

- The Authorization Server (AS) — can issue arbitrary tokens, lie about scope membership, collude with agents
- Network observation — sees all proofs presented to all RSes
- Up to `N-1` of `N` enrolled agents' secrets (static corruption)

The adversary does NOT control:

- The on-chain registry smart contract (integrity of Merkle roots)
- The RS's verification key and PLONK/Groth16 verifier implementation
- The Baby Jubjub discrete log problem
- The Poseidon hash function (collision resistance in BN254 scalar field)

### Security game: `Game_SelectiveScope`

```
Setup:
  Challenger C enrolls agent with credential (modelHash, opPk, permissionBitmask, expiry)
  into the agent Merkle tree, obtaining credentialCommitment and root R.

Challenge:
  C sends (requiredScopeMask*, currentTimestamp, sessionNonce, R) to A,
  where requiredScopeMask* is chosen such that
  permissionBitmask & requiredScopeMask* ≠ requiredScopeMask*
  (i.e., the enrolled agent does NOT satisfy the required mask).

A wins if:
  A produces a valid proof π that the PLONK verifier accepts with
  public inputs (requiredScopeMask*, currentTimestamp, sessionNonce, R)
  and the output agentMerkleRoot matches R.
```

**Claim:** `Pr[A wins] ≤ negl(λ)` under knowledge soundness of PLONK (or Groth16) in the algebraic group model + ROM, Poseidon collision resistance, and DLP hardness on Baby Jubjub.

### Privacy game: `Game_ScopePrivacy`

```
Setup:
  C enrolls two agents with identical requiredScopeMask satisfaction but
  different unrequired bits:
    Agent₀: permissionBitmask₀ (satisfies mask, has extra bit 5 set)
    Agent₁: permissionBitmask₁ (satisfies mask, does NOT have bit 5 set)

Challenge:
  C flips coin b ∈ {0,1}, generates proof πb.
  A receives (πb, requiredScopeMask, public outputs).

A wins if:
  A guesses b with probability > 1/2 + negl(λ).
```

**Claim:** `Pr[A wins] ≤ 1/2 + negl(λ)` under the zero-knowledge property of PLONK/Groth16 (simulator existence in the CRS model).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Knowledge soundness of Groth16** (generic bilinear group model) / **Knowledge soundness of PLONK** (algebraic group model + ROM)
2. **Poseidon collision resistance** over the BN254 scalar field
3. **Discrete logarithm hardness on Baby Jubjub** (subgroup of BN254)
4. **EdDSA-Poseidon EUF-CMA** (existential unforgeability under chosen-message attack, reduced to DLP on Baby Jubjub)

### Reduction sketch for soundness

**Theorem:** If `A` wins `Game_SelectiveScope` with non-negligible probability `ε`, then we can construct either:

- `B₁` that breaks Poseidon collision resistance with probability ≥ `ε/2`, or
- `B₂` that breaks PLONK knowledge soundness with probability ≥ `ε/2`

**Proof sketch:**

By PLONK knowledge soundness, if `A` produces a valid proof `π`, the extractor `E` extracts a witness `w = (permissionBitmask', modelHash', opPk', expiry', sig', merkleProof')` satisfying all circuit constraints.

Case 1: `credentialCommitment' = Poseidon5(w.modelHash', w.opPk', w.permissionBitmask', w.expiry')` produces a leaf that IS in the tree with root `R`, but corresponds to a different enrolled credential whose actual `permissionBitmask` differs from `w.permissionBitmask'`. This implies `Poseidon5` collision → contradiction with assumption (2).

Case 2: The extracted `permissionBitmask'` satisfies `permissionBitmask' & requiredScopeMask* == requiredScopeMask*` (from constraint 5). But we chose `requiredScopeMask*` such that the enrolled agent's actual bitmask does NOT satisfy it. Combined with Case 1 (no collision), the extracted witness has a `permissionBitmask'` that is not the enrolled bitmask but produces the same `credentialCommitment` → collision, contradiction.

Case 3: The extracted Merkle proof verifies against `R` but the leaf `credentialCommitment'` is not in the tree. This requires finding a Poseidon collision in the Merkle hash chain → contradiction with assumption (2).

Therefore `Pr[A wins] ≤ negl(λ)`. ∎

**Zero-knowledge argument:** The PLONK (resp. Groth16) simulator, given only the public inputs/outputs and the CRS trapdoor, produces a proof indistinguishable from a real proof. The RS learns only: (a) the predicate is satisfied, (b) the nullifier, (c) the scope commitment. No information about unrequired bits of `permissionBitmask`, the operator key, model hash, or Merkle path leaks.

### Adversarial-AS resilience

The AS never appears in the verification path. The RS verifies the proof against the on-chain Merkle root and the circuit's verification key. Even if the AS is fully compromised:

- It cannot forge a proof for an unenrolled credential (Merkle membership is checked against the on-chain root the RS reads independently).
- It cannot inflate an agent's permissions (the `credentialCommitment` binds the bitmask at enrollment time; changing the bitmask changes the commitment, breaking Merkle membership).
- It cannot suppress an agent's permissions (the agent holds its own secret inputs and generates the proof autonomously).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Hash function | Poseidon over BN254 scalar field | §2 Cryptographic Primitives |
| Credential commitment | `Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiryTimestamp)` | §4.1 Agent Proof Specification |
| Operator signature | EdDSA-Poseidon on Baby Jubjub (a=168700, d=168696) | §2 |
| Merkle tree | Lean Incremental Merkle Tree, depth 20, Poseidon2 node hash | §2, §3.1 |
| Scope satisfaction constraint | `reqBits[i] * (1 - permBits[i]) === 0` for i∈[0,64) | §4.1 constraint 5 |
| Cumulative bit encoding | Implication constraints on bits 2,3,4 | §4.1 constraint 6 |
| Nullifier | `Poseidon2(credentialCommitment, sessionNonce)` | §4.1 |
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4.1 / §5 |
| Proving system | PLONK (agent circuit, universal setup via pot16.ptau) | §2.1 Proving Systems |
| On-chain root | Agent root history buffer (30-entry circular) | §3.1 |

The `SelectiveScopeProof` circuit is the `AgentPolicy` circuit from the spec with `agentMerkleRoot` moved from output to public input (RS-supplied from on-chain read). All constraints are identical. The only structural change is that `agentMerkleRoot` is verified by the RS against its own on-chain read rather than being trusted as a circuit output — this is what enables the adversarial-AS model.

## 6. Circuit cost estimate

| Gadget | Estimated constraints |
|---|---|
| `Num2Bits(64)` × 4 (bitmask, requiredMask, expiry, timestamp) | 256 |
| `Poseidon5` (credential commitment) | ~1,500 |
| `EdDSAPoseidonVerifier` | ~14,000 |
| `BinaryMerkleRoot(20)` (20 levels × Poseidon2) | ~15,000 |
| Scope satisfaction (64 multiplication constraints) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` (nullifier) | ~750 |
| `Poseidon2` (scope commitment) | ~750 |
| **Total** | **~32,500** |

This fits comfortably under the 2^16 = 65,536 constraint ceiling of `pot16.ptau`.

**Proving time targets:**

| System | Target | Rationale |
|---|---|---|
| PLONK (snarkjs, browser) | < 5s | Agent-side, matches spec PLONK agent target |
| PLONK (rapidsnark, server) | < 500ms | Server-side agent proving |
| Groth16 (if used) | < 3s | Agent circuits are smaller than human circuits |

**Proof size:** PLONK proof: ~768 bytes. Groth16 proof: 128 bytes (3 group elements). Both are constant regardless of bitmask width — a 64-bit bitmask and a hypothetical 256-bit bitmask produce identically sized proofs.

## 7. Concrete deployment scenario

### Scenario: Navy Federal Credit Union — AI agent accessing member financial data

**Stakeholder:** Navy Federal Credit Union (NFCU), the largest credit union in the US (13M+ members).

**Setup:** NFCU deploys the Bolyra agent registry. A fintech partner (e.g., a budgeting app) enrolls its AI agent with the following credential:

- `modelHash`: Poseidon hash of `"gpt-4o-2025-06-01"`
- `operatorPubkey`: Fintech's Baby Jubjub EdDSA keypair
- `permissionBitmask`: `0b00000111` (bits 0,1,2 = READ_DATA + WRITE_DATA + FINANCIAL_SMALL)
- `expiryTimestamp`: 30 days from enrollment

The agent's `credentialCommitment` is inserted into the on-chain agent Merkle tree.

**Runtime flow:**

1. The agent calls NFCU's transaction-read API endpoint. The RS (NFCU's gateway) requires `requiredScopeMask = 0b00000001` (READ_DATA only).

2. The RS generates a fresh `sessionNonce`, reads the current `agentMerkleRoot` from the on-chain registry, and sends `(requiredScopeMask=1, currentTimestamp, sessionNonce, agentMerkleRoot)` to the agent.

3. The agent generates a PLONK `SelectiveScopeProof` locally in < 500ms (rapidsnark). The proof demonstrates:
   - The agent holds an enrolled credential (Merkle membership)
   - The credential is operator-signed (EdDSA verification)
   - `permissionBitmask & 0b00000001 == 0b00000001` (READ_DATA is set)
   - The credential is not expired

4. **What NFCU's RS learns:** The agent has READ_DATA permission, is enrolled, is not expired, and is operator-signed. **What NFCU's RS does NOT learn:** That the agent also has WRITE_DATA and FINANCIAL_SMALL permissions. The RS cannot distinguish this agent from one with only READ_DATA.

5. NFCU's RS verifies the proof against the PLONK verification key. No call to any AS. No token exchange. No introspection endpoint.

**Why this matters for NFCU:**

- **Regulatory compliance (NCUA Part 748):** The credit union can demonstrate that agent access is cryptographically authorized without maintaining a centralized scope-disclosure log that itself becomes a data liability.
- **Adversarial AS resilience:** If the fintech's OAuth AS is compromised, the attacker cannot inflate permissions — the bitmask is committed in the on-chain Merkle tree. Nor can the compromised AS suppress permissions to cause a denial-of-service — the agent proves its own credential autonomously.
- **Audit simplicity:** The on-chain registry provides a tamper-evident log of all enrolled credentials and nullifiers. NCUA examiners can verify the enrollment set without accessing any agent's private credential fields.
- **Minimal disclosure to third parties:** When NFCU's CUSO (Credit Union Service Organization) partners share infrastructure, each RS sees only predicate satisfaction for its own `requiredScopeMask`. Cross-RS collusion reveals nothing about unrequired bits (zero-knowledge property). BBS+ achieves cross-RS unlinkability for discrete claims but cannot evaluate bitwise predicates with implication closure.

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + RFC 8707 + DPoP + BBS+) fails on four independent axes. Any one is sufficient; together they are definitive.

### Axis 1: AS-blind presentation is structurally impossible

In every RFC 7662 variant, the AS issues the token and populates the introspection response. The jwt-introspection-response draft caches this as a signed JWT, but the AS was present at issuance and at first introspection. The agent cannot present a scope proof to an RS the AS has never seen without the AS having pre-computed and signed a response covering that RS's required mask. BBS+ selective disclosure lets the holder choose which claims to reveal, but the AS (issuer) still signed all claims at issuance — a compromised AS can issue credentials with inflated or deflated claims, and the RS has no recourse.

In `SelectiveScopeProof`, the agent generates the proof autonomously using its private inputs. The RS verifies against the on-chain Merkle root. The AS is not in the loop at presentation time and cannot interfere.

### Axis 2: Runtime-adaptive bitwise predicate over a hidden bitmask

The baseline evaluates scope as a fixed string set (`"read write financial_small"`). The RS receives exactly the scopes the AS chose to include. BBS+ supports equality predicates and range proofs over hidden attributes, but bitwise AND over a multi-bit field with implication closure (bit 4 ⟹ bits 2,3) requires arithmetic circuit evaluation — specifically, the constraint `reqBits[i] * (1 - permBits[i]) === 0` for each bit position, plus the implication constraints. No BBS+ extension in draft-irtf-cfrg-bbs-signatures or VC-DI-BBS supports this.

`SelectiveScopeProof` evaluates the predicate inside the circuit at proof-generation time. The RS specifies `requiredScopeMask` as a public input; the agent's `permissionBitmask` is private. The predicate is evaluated over the hidden bitmask with implication closure enforced by the circuit. The RS can change `requiredScopeMask` per request without any AS involvement.

### Axis 3: Adversarial-AS security

The entire RFC 7662 stack assumes AS trustworthiness. A signed introspection JWT proves the AS said what it said — not that the AS told the truth. A compromised AS can:

- Claim an agent has scope it does not have → RS grants unauthorized access
- Claim an agent lacks scope it does have → denial of service
- Correlate all introspection requests across RSes

BBS+ shifts the trust from AS-at-verification-time to AS-at-issuance-time, but the issuer (AS) still controls the signed credential content. A malicious issuer can embed false claims.

`SelectiveScopeProof` removes the AS from the trust model entirely. The `credentialCommitment` is computed deterministically from the credential fields and enrolled in the on-chain Merkle tree. The circuit proves the bitmask inside the commitment satisfies the predicate. The only trust assumptions are: (1) the on-chain registry is not compromised, (2) Poseidon is collision-resistant, (3) PLONK/Groth16 is knowledge-sound. None of these involve the AS.

### Axis 4: Constant-size proof regardless of bitmask width

A jwt-introspection-response grows linearly with the number of scopes. A BBS+ derived proof grows with the number of disclosed messages. For a 64-bit permission space (2^64 possible configurations), enumerating scope strings is infeasible.

The `SelectiveScopeProof` is a single PLONK proof (~768 bytes) or Groth16 proof (128 bytes) regardless of whether the bitmask is 8 bits, 64 bits, or (with circuit extension) 256 bits. The proof size is determined by the proving system, not the predicate complexity or bitmask width.

### Summary table

| Property | RFC 7662 + BBS+ baseline | SelectiveScopeProof |
|---|---|---|
| AS-blind presentation | Impossible — AS signs all claims | Agent proves autonomously, RS reads on-chain root |
| Runtime-adaptive bitwise predicate | Not expressible — scope is fixed string set | `requiredScopeMask` is a public input, evaluated per-request |
| Adversarial-AS security | None — RS trusts AS attestation | AS not in verification path; trust = on-chain root + proof soundness |
| Constant-size proof | O(disclosed claims) for BBS+; O(scope strings) for JWT | O(1) — 128 bytes (Groth16) or 768 bytes (PLONK) |
| Implication-closure enforcement | Application-layer only | Circuit-enforced: `permBits[4]*(1-permBits[3])===0` |
| Cross-RS unlinkability | BBS+ achieves at RS layer; AS can correlate | ZK property: RS learns only predicate satisfaction; no AS to correlate |
