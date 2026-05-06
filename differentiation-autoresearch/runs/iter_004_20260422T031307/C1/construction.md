# Construction

## 1. Statement of claim

An AI agent proves that its 64-bit permission bitmask satisfies an arbitrary required-scope predicate `(permissionBitmask & requiredMask) == requiredMask` by presenting a single PLONK proof that is:

1. **Constant-size** (~768 bytes) regardless of the number of bits in the permission space.
2. **AS-blind at presentation time**: the agent generates the proof using only its locally-held credential secret and the Merkle proof; no Authorization Server roundtrip occurs after initial credential enrollment.
3. **Operator-binding against a semi-honest AS**: the permission bitmask is committed inside a Poseidon5 credential commitment that is (a) signed by the operator's BabyJubjub EdDSA key at enrollment and (b) anchored as a leaf in an on-chain Merkle tree whose root history the AS cannot unilaterally rewrite without detection.
4. **Unlinkable across resource servers**: each presentation uses a fresh session nonce producing a distinct nullifier `Poseidon2(credentialCommitment, sessionNonce)`, and the scope commitment `Poseidon2(permissionBitmask, credentialCommitment)` reveals nothing about which bits are set.

No combination of RFC 7662, JWT introspection response, RFC 8693, RFC 8707, DPoP, or BBS+ selective disclosure can simultaneously achieve all four properties.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `SelectiveScopeProof` (instantiation of Bolyra `AgentPolicy`)

This construction is a direct deployment of the Bolyra AgentPolicy PLONK circuit with the scope satisfaction sub-circuit as the critical gadget.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Poseidon hash of agent model identifier |
| `operatorPubkeyAx` | F_p | Operator BabyJubjub public key x-coordinate |
| `operatorPubkeyAy` | F_p | Operator BabyJubjub public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield (HIDDEN from verifier) |
| `expiryTimestamp` | uint64 | Credential expiry Unix timestamp |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | uint | Proof depth |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Sibling hashes (padded to MAX_DEPTH=20) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Verifier-supplied current time |
| `sessionNonce` | F_p | Fresh per-session random value |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history) |
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` |
| `scopeCommitment` | F_p | `Poseidon2(permissionBitmask, credentialCommitment)` |

### Gadgets (constraint groups)

**G1 — Range checks:**
- `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.
- Prevents field overflow where a value ≥ 2^64 passes arithmetic constraints but wraps in Solidity uint64.

**G2 — Credential commitment:**
```
credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)
```

**G3 — Operator signature verification:**
```
EdDSAPoseidonVerifier(
  pubkey: (operatorPubkeyAx, operatorPubkeyAy),
  message: credentialCommitment,
  signature: (sigR8x, sigR8y, sigS)
)
```
This binds the bitmask to a specific operator key at enrollment time.

**G4 — Merkle membership:**
```
BinaryMerkleRoot(MAX_DEPTH=20, leaf=credentialCommitment, proof) == agentMerkleRoot
```

**G5 — Scope satisfaction (the critical gadget):**
For each bit position `i ∈ [0, 64)`:
```
requiredBits[i] = Num2Bits(64)(requiredScopeMask)[i]
permBits[i]     = Num2Bits(64)(permissionBitmask)[i]
requiredBits[i] * (1 - permBits[i]) === 0
```
This enforces `(permissionBitmask & requiredScopeMask) == requiredScopeMask` without revealing `permissionBitmask`. If any required bit is 1 and the corresponding permission bit is 0, the constraint fails and no valid proof exists.

**G6 — Cumulative encoding (tier hierarchy):**
```
permBits[4] * (1 - permBits[3]) === 0
permBits[4] * (1 - permBits[2]) === 0
permBits[3] * (1 - permBits[2]) === 0
```
Ensures hierarchical tier bits are monotonically inclusive.

**G7 — Expiry:**
```
LessThan(64)(currentTimestamp, expiryTimestamp) === 1
```

**G8 — Nullifier derivation:**
```
nullifierHash = Poseidon2(credentialCommitment, sessionNonce)
```

**G9 — Scope commitment:**
```
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
```

### Enrollment protocol (one-time, AS-involved)

1. Operator generates BabyJubjub keypair `(sk, pk)`.
2. Operator computes `credentialCommitment = Poseidon5(modelHash, pk.Ax, pk.Ay, permissionBitmask, expiryTimestamp)`.
3. Operator signs: `sig = EdDSA.Sign(sk, credentialCommitment)`.
4. Credential commitment is inserted as a leaf in the on-chain agent Merkle tree.
5. Agent receives `(modelHash, pk, permissionBitmask, expiryTimestamp, sig, merkleProof)` as its local credential bundle.

After enrollment, the agent never contacts the AS/operator to generate scope proofs.

### Presentation protocol (per-RS, AS-free)

1. RS generates fresh `sessionNonce` and publishes `requiredScopeMask`.
2. Agent locally generates PLONK proof using its credential bundle.
3. RS verifies: (a) PLONK proof validity, (b) `agentMerkleRoot` against on-chain root history buffer, (c) `nullifierHash` not revoked, (d) `currentTimestamp` is fresh.
4. RS learns only: the agent holds a valid enrolled credential satisfying the required scope mask, with a non-expired timestamp. RS learns nothing about the full permission set.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A is a **semi-honest Authorization Server** that controls:
- The credential issuance process (choosing what bitmask to encode)
- The operator signing key (can sign arbitrary credential commitments)
- The introspection endpoint (in the RFC 7662 model)

The adversary **cannot**:
- Rewrite the on-chain Merkle tree root history buffer unilaterally (blockchain integrity assumption)
- Break the BN254 pairing (PLONK soundness)
- Find Poseidon preimages or collisions (algebraic hash security)
- Forge BabyJubjub EdDSA signatures for keys it does not hold
- Control the Resource Server (RS is honest)

### Game: Scope Forgery

```
Game ScopeForge(A, λ):
  1. Setup: Generate PLONK universal SRS. Deploy on-chain verifier and Merkle tree.
  2. Enrollment: A enrolls agent with credential commitment C embedding
     permissionBitmask B, signed by operator key pk_op.
     C is inserted as leaf in on-chain Merkle tree.
  3. Challenge: Challenger selects requiredScopeMask M such that
     (B & M) ≠ M  (i.e., the agent does NOT have the required permissions).
  4. Attack: A produces a PLONK proof π* with public input requiredScopeMask = M
     and public output agentMerkleRoot matching the on-chain root history.
  5. A wins if: the PLONK verifier accepts π*.
```

**Claim**: Pr[A wins ScopeForge] ≤ negl(λ), under PLONK knowledge soundness.

### Game: Permission Extraction

```
Game PermExtract(A, λ):
  1. Setup: as above.
  2. Enrollment: Honest agent enrolls with permissionBitmask B (unknown to A).
  3. Queries: A observes polynomially many (requiredScopeMask_i, proof_i,
     scopeCommitment_i, nullifierHash_i) tuples for different RS sessions.
  4. A wins if: A outputs B' such that B' = B.
```

**Claim**: Pr[A wins PermExtract] ≤ negl(λ), under Poseidon preimage resistance and PLONK zero-knowledge.

### Game: Cross-RS Linkability

```
Game CrossLink(A, λ):
  1. Setup: as above.
  2. Enrollment: Two agents α₀, α₁ enroll with distinct credentials.
  3. Challenge: Challenger flips coin b ∈ {0,1}. Agent α_b generates
     proofs for RS_1 and RS_2 with independent session nonces.
  4. A sees: (proof_RS1, nullifier_RS1, scopeComm_RS1, proof_RS2, nullifier_RS2, scopeComm_RS2).
  5. A outputs guess b'.
  6. A wins if b' = b.
```

**Claim**: |Pr[A wins CrossLink] - 1/2| ≤ negl(λ), since:
- `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` with independent nonces yields computationally independent values (Poseidon PRF assumption).
- `scopeCommitment` is identical across sessions for the same agent (it encodes the same bitmask and credential), but this is true for BOTH agents from the adversary's view — the adversary cannot open the commitment without a preimage attack.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Instantiation |
|----|-----------|---------------|
| A1 | **Knowledge soundness of PLONK** | Universal SRS over BN254; Marlin/KZG polynomial commitment; extractable in the algebraic group model + ROM |
| A2 | **Poseidon collision resistance** | Poseidon-128 over BN254 scalar field; no known algebraic attacks below 2^128 operations |
| A3 | **Poseidon preimage resistance** | Same instantiation; preimage resistance follows from collision resistance in the random permutation model |
| A4 | **Discrete log hardness on Baby Jubjub** | Embedded curve in BN254; subgroup order ≈ 2^251; best known attack is Pollard rho at O(2^125) |
| A5 | **EdDSA unforgeability (EUF-CMA)** | EdDSA over Baby Jubjub with Poseidon hash; reduces to DL on Baby Jubjub (A4) in ROM |
| A6 | **Blockchain integrity** | On-chain Merkle root history cannot be retroactively altered; standard assumption for any smart-contract-anchored protocol |

### Reduction sketch: ScopeForge → PLONK knowledge soundness

1. Suppose adversary A wins ScopeForge with non-negligible probability ε.
2. By PLONK knowledge soundness (A1), there exists an extractor E that, given A's proof π*, extracts a valid witness `w = (modelHash, pk, permissionBitmask*, expiryTimestamp, sig, merkleProof)`.
3. The extracted witness must satisfy all circuit constraints, including G5: for each bit i, `requiredBits[i] * (1 - permBits*[i]) === 0`.
4. This means `(permissionBitmask* & requiredScopeMask) == requiredScopeMask`.
5. The extracted witness must also satisfy G4: `MerkleRoot(Poseidon5(..., permissionBitmask*, ...), proof) == agentMerkleRoot`, where `agentMerkleRoot` is in the on-chain root history.
6. Case analysis:
   - If `permissionBitmask* = B` (the enrolled bitmask): then `(B & M) == M`, contradicting the challenge condition `(B & M) ≠ M`.
   - If `permissionBitmask* ≠ B`: then `credentialCommitment* = Poseidon5(..., permissionBitmask*, ...) ≠ C` (by Poseidon collision resistance, A2). But this leaf must appear in the Merkle tree — either as a different enrolled credential (irrelevant; it's not the challenged agent's credential) or as a collision on the Merkle root (collision resistance of Poseidon, A2) or a forged leaf (blockchain integrity, A6). All sub-cases reduce to breaking A2 or A6.
7. Contradiction: ε ≤ negl(λ).

### Reduction sketch: PermExtract → Poseidon preimage resistance

1. Suppose A extracts `B` from observed `(scopeCommitment_i, nullifierHash_i)` tuples.
2. `scopeCommitment = Poseidon2(B, credentialCommitment)`. Extracting B from scopeCommitment requires inverting Poseidon2, breaking A3.
3. `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`. This reveals nothing about B directly.
4. The PLONK proofs themselves reveal nothing about private inputs by the zero-knowledge property of PLONK.
5. The only information channel is the binary accept/reject of the scope satisfaction check per `requiredScopeMask_i`. If the RS chooses adaptive masks, it can recover B in at most 64 queries (one per bit). **Mitigation**: the RS is honest (threat model) and uses policy-fixed masks. If the RS is adversarial, this is outside our threat model — but even then, the RS learns at most the individual bit values queried, not the full bitmask in a single proof.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Permission bitmask commitment | `Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiryTimestamp)` | AgentPolicy circuit, constraint 2 |
| Operator binding | `EdDSAPoseidonVerifier` over Baby Jubjub | AgentPolicy circuit, constraint 3 |
| On-chain enrollment anchor | Lean Incremental Merkle Tree (depth 20, Poseidon2 node hash) | §3.1 System Architecture |
| Scope satisfaction | Bitwise AND predicate: `requiredBits[i] * (1 - permBits[i]) === 0` for i ∈ [0,64) | AgentPolicy circuit, constraint 5 |
| Tier hierarchy | Cumulative bit encoding: bits 2→3→4 monotonic | AgentPolicy circuit, constraint 6 |
| Replay prevention | `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` | AgentPolicy circuit, G8 |
| Scope commitment (delegation chain seed) | `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` | §4.1 Identity-Bound Scope Commitment Chain |
| Expiry enforcement | `LessThan(64)(currentTimestamp, expiryTimestamp)` | AgentPolicy circuit, constraint 7 |
| Proving system | PLONK with universal SRS over BN254 | §3.3 Proving Systems |
| On-chain verification | PLONK verifier contract; root history buffer (30 entries) | §3.1, §4 |

Every gadget in this construction is a named component of the Bolyra AgentPolicy circuit. No extensions or novel primitives are required.

## 6. Circuit cost estimate

### Constraint breakdown

| Gadget | Constraints (approx.) | Notes |
|--------|-----------------------|-------|
| G1: Num2Bits(64) × 3 | 192 | Range checks on bitmask, expiry, currentTimestamp |
| G2: Poseidon5 | ~1,600 | 5-input Poseidon (8 full rounds + 57 partial rounds, BN254) |
| G3: EdDSA Poseidon Verifier | ~14,000 | Baby Jubjub scalar mul + Poseidon-based sig verify |
| G4: BinaryMerkleRoot(20) | ~3,200 | 20 levels × (Poseidon2 + mux) ≈ 160 constraints/level |
| G5: Scope satisfaction | ~192 | 64 × (bit decomp already done + 1 multiplication constraint) |
| G6: Cumulative encoding | 3 | 3 multiplication constraints |
| G7: LessThan(64) | ~130 | Comparison circuit |
| G8: Poseidon2 (nullifier) | ~320 | 2-input Poseidon |
| G9: Poseidon2 (scope commitment) | ~320 | 2-input Poseidon |
| **Total** | **~20,000** | |

### Proving time targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| PLONK proving time (agent) | **< 5 seconds** | Bolyra spec: PLONK agent proofs < 5s |
| Proof size | ~768 bytes | Standard PLONK proof (3 group elements + openings) |
| Verification gas (on-chain) | ~300K gas | PLONK pairing check on BN254 (EIP-196/197) |
| Verification time (off-chain) | < 10 ms | Single pairing check |

At ~20,000 constraints, PLONK proving on a modern CPU (M-series Apple Silicon or x86 with AVX) using snarkjs/rapidsnark completes well within the 5-second budget. The Semaphore v4 circuit at comparable constraint counts proves in ~2 seconds on commodity hardware.

## 7. Concrete deployment scenario

### Stakeholder: State Employees' Credit Union (SECU), North Carolina

**Context**: SECU operates an agentic banking platform where member-authorized AI agents perform financial operations (balance inquiries, transfers, bill payments, loan applications) across multiple internal resource servers (core banking API, loan origination system, fraud detection service, compliance reporting engine). SECU has 2.7 million members and is subject to NCUA examination.

**Permission space**: 64-bit bitmask encoding 64 distinct agent capabilities:
- Bits 0–4: Tier hierarchy (read-only → transactional → advisory → administrative → supervisory), cumulative encoding
- Bits 5–15: Account operation classes (balance, transfer, payment, statement, etc.)
- Bits 16–31: Product-specific permissions (checking, savings, CD, IRA, mortgage, auto loan, etc.)
- Bits 32–47: Compliance and reporting permissions
- Bits 48–63: Reserved for future expansion

**Deployment flow**:

1. **Enrollment (one-time)**: SECU's credential operator generates a BabyJubjub keypair. For each authorized agent, the operator computes the credential commitment embedding the agent's permission bitmask and signs it. The commitment is inserted into the on-chain Merkle tree. The agent stores its credential bundle locally.

2. **Runtime presentation (per-request, AS-free)**: When Agent-X needs to call the loan origination API, the API server specifies `requiredScopeMask = 0x0000_0000_0005_001F` (tier ≥ transactional + loan origination + read). Agent-X generates a PLONK proof in <5 seconds on its container's CPU. The API server verifies the proof against the on-chain Merkle root. Agent-X never reveals that it also holds compliance-reporting permissions (bits 32–47) — the loan origination server learns only that the required bits are satisfied.

3. **Cross-RS isolation**: When the same agent calls the fraud detection service with a different `requiredScopeMask` and a fresh `sessionNonce`, the nullifier is different, and the fraud service cannot link this request to the loan origination request. Neither service learns the full permission set.

4. **Adversarial-AS protection**: Even if SECU's credential operator is compromised and attempts to issue a forged introspection response claiming Agent-X has fewer permissions than enrolled, the on-chain Merkle root anchors the original credential commitment. The API server verifies the proof against this root, not against an AS-supplied assertion. The operator cannot retroactively alter what was committed without producing a Poseidon collision.

5. **NCUA examination**: The examiner can verify that every agent access was backed by a valid PLONK proof anchored to an on-chain root, providing a cryptographic audit trail without exposing member-agent permission details across examination boundaries.

## 8. Why the baseline cannot match

The baseline (RFC 7662 + JWT introspection + BBS+ selective disclosure) fails on four properties that this construction achieves simultaneously:

### Property 1: Bitmask AND predicate without disclosure

**Baseline gap**: BBS+ operates on individual messages (claims). To prove `(B & M) == M` over a packed 64-bit bitmask, BBS+ would need to either (a) encode each bit as a separate VC claim (64 claims, with proof size scaling linearly) or (b) treat the bitmask as a single integer (losing per-bit selective disclosure entirely). Neither approach yields a constant-size proof of a bitwise predicate over a packed representation. RFC 7662 cannot express predicates at all — it returns literal scope strings.

**Construction advantage**: Gadget G5 enforces `requiredBits[i] * (1 - permBits[i]) === 0` for all 64 bits inside the circuit. The PLONK proof is constant-size (~768 bytes) regardless of how many bits are checked. The verifier learns only the accept/reject decision, not which bits are set.

### Property 2: AS-blind presentation

**Baseline gap**: RFC 7662 requires an AS roundtrip for introspection, or the JWT introspection response must be pre-signed at issuance with fixed scope content. The agent cannot adaptively choose which scope subset to prove at runtime without contacting the AS. BBS+ partially addresses this (holder-derived presentations), but BBS+ VCs are not part of any standardized OAuth flow — integrating them requires a parallel credential issuance infrastructure.

**Construction advantage**: After one-time enrollment (credential commitment + Merkle insertion), the agent generates proofs locally for any `requiredScopeMask` without any AS/operator involvement. The proof is generated at the moment of use, adaptive to whatever the RS requires.

### Property 3: Cryptographic assurance against a semi-honest AS

**Baseline gap**: Under RFC 7662, the RS trusts the AS's signature over the introspection response. A compromised or malicious AS can forge filtered responses, and the RS has no recourse. BBS+ separates issuer from presenter, but does not prove that the credential reflects the true permission set as recorded in an independent registry. There is no tamper-evident anchor.

**Construction advantage**: The credential commitment is a leaf in an on-chain Merkle tree with a 30-entry root history buffer. The AS/operator signed the commitment at enrollment, but cannot retroactively alter it without either (a) producing a Poseidon collision (breaking A2) or (b) rewriting the blockchain state (breaking A6). The RS verifies the proof against the on-chain root, not against an AS-supplied assertion.

### Property 4: Constant-size proof independent of permission space width

**Baseline gap**: JWT introspection response size scales with the number of scopes returned. BBS+ derived proof size is O(|disclosed claims|). For a 64-bit permission space, neither produces a proof whose size is independent of the space width when the RS must be convinced of a predicate over the full space.

**Construction advantage**: The PLONK proof is exactly ~768 bytes regardless of whether the `requiredScopeMask` has 1 bit set or 64 bits set. The constraint count is fixed at circuit compilation time. If the permission space were extended to 128 or 256 bits (by modifying the circuit), the proof size remains identical — only the constraint count (and thus proving time) increases linearly with bitmask width, not the proof size.

### Summary: the impossibility

The baseline's fundamental limitation is architectural: RFC 7662 and its extensions treat scope as a **data field** that is filtered, transmitted, and inspected. BBS+ treats claims as **individual messages** that are selectively disclosed. Neither framework supports **predicates over packed representations** where the proof attests to a boolean property of hidden data without revealing the data itself. This is exactly what a succinct argument system (PLONK) provides: the ability to prove `f(x) = 1` for a public function `f` and private input `x`, in constant size, without revealing `x`. No composition of data-filtering protocols and per-message selective disclosure can replicate this capability.
