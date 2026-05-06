# Construction

## 1. Statement of claim

Agent proves a predicate over credential attributes (e.g. `chartered_by_NCUA == true`) without the verifier learning which issuer signed the credential, with constant-size proof and arbitrary-schema support. The proof is constant-size (128 bytes Groth16 / ~600 bytes PLONK) regardless of the number of issuers in the registry, the complexity of the Boolean predicate, or the credential schema. A formal IND-ISS game demonstrates computational issuer indistinguishability against an adaptive adversary who controls the authorization server, has access to public NCUA charter records, and can observe epoch transitions.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Issuer Registry Merkle Tree

A depth-16 Lean Incremental Merkle Tree with Poseidon2 node hashing stores issuer public key commitments. Each leaf is:

```
issuerLeaf = Poseidon2(issuerPubkeyAx, issuerPubkeyAy)
```

where `(issuerPubkeyAx, issuerPubkeyAy)` is the issuer's EdDSA public key on Baby Jubjub. The tree supports up to 65,536 issuers. The registry contract maintains a **versioned root history buffer** of the last 30 roots (Section 2.6).

### 2.2 Credential Structure

A credential consists of 8 attribute slots `attr[0..7]`, each a BN254 scalar field element, plus issuer metadata. The credential commitment is:

```
credCommitment = Poseidon(attr[0], attr[1], ..., attr[7], issuerPubkeyAx, issuerPubkeyAy, expiryTimestamp)
```

using a 12-input Poseidon hash (Poseidon12). The issuer signs this commitment:

```
sig = EdDSA.Sign(issuerSecretKey, credCommitment)
```

### 2.3 Predicate Encoding

A predicate descriptor is a fixed-size structure encoding up to 8 clauses over the 8 attribute slots, combined via a conjunction/disjunction mask:

| Field | Size | Description |
|-------|------|-------------|
| `slotIndex[0..7]` | 3 bits each (24 bits total) | Which attribute slot each clause targets |
| `opcode[0..7]` | 3 bits each (24 bits total) | Operation: 0=NOP, 1=EQ, 2=NEQ, 3=LT, 4=GT, 5=LTE, 6=GTE, 7=BITMASK |
| `value[0..7]` | 64 bits each (512 bits total) | Comparison value for each clause |
| `clauseActive[0..7]` | 1 bit each (8 bits total) | Whether each clause participates |
| `conjMask` | 8 bits | Bit i=1 means clause i is ANDed; bit i=0 means ORed |

Total predicate descriptor: 576 bits. The **predicate policy hash** is:

```
predicateHash = Poseidon4(
  pack(slotIndex[0..7], opcode[0..7]),   // 48 bits → field element
  pack(clauseActive[0..7], conjMask),     // 16 bits → field element
  pack(value[0..3]),                       // 256 bits → field element
  pack(value[4..7])                        // 256 bits → field element
)
```

This hash is a **public signal**, binding the verifier to the exact predicate evaluated.

### 2.4 Issuer Revocation Accumulator

An RSA-2048 accumulator (or equivalently, a sparse Merkle exclusion tree of depth 16 with Poseidon2 hashing) tracks revoked issuer keys. The construction uses the exclusion-tree variant for field compatibility:

- A **revocation bitmap tree** of depth 16 mirrors the issuer registry tree. Leaf `i` is 1 if issuer `i` is revoked, 0 otherwise.
- The circuit proves a **non-membership** (exclusion) proof: the leaf at the prover's issuer index is 0.
- The revocation root `revocationRoot` is a public signal, updated on-chain by the registry operator (e.g., NCUA).
- Revoking issuer `k` sets leaf `k` to 1 and updates only the `O(log n)` path — all other issuers' proofs remain valid.

### 2.5 Regulated Break-Glass Escrow

For NCUA Part 748 incident response, the credential holder computes an **escrowed issuer commitment**:

```
escrowNonce = random 128-bit value
escrowedIssuer = Poseidon2(issuerLeaf, escrowNonce)
encryptedEscrow = ECIES.Encrypt(ncuaEscrowPubkey, issuerLeaf || escrowNonce)
```

The circuit proves that `escrowedIssuer` is correctly derived from the same `issuerLeaf` used in the Merkle membership proof, and that the encrypted payload corresponds to the committed values. The `escrowedIssuer` commitment and `encryptedEscrow` ciphertext are public signals. Only the NCUA-designated escrow key holder can decrypt and recover the issuer identity. The verifier sees only an opaque commitment and ciphertext — IND-ISS holds against the verifier since `escrowedIssuer` is randomized by `escrowNonce`.

### 2.6 Merkle Root Rotation Protocol

The issuer registry contract maintains:

- `issuerRootHistory[30]`: circular buffer of the last 30 issuer Merkle roots, each tagged with a monotonic `epoch` counter and block timestamp.
- `rootValidityWindow`: configurable parameter (default: 3600 seconds / 1 hour). A proof referencing root at epoch `e` is valid if `block.timestamp - rootTimestamp[e] ≤ rootValidityWindow`.
- **Migration path for in-flight proofs**: When a new issuer is added or removed, the epoch increments. Proofs generated against epoch `e` remain valid until `rootValidityWindow` expires. The prover's `issuerMerkleRoot` public signal is checked against the history buffer, not just the current root.
- **Staleness SLA**: Provers SHOULD regenerate proofs if their referenced root is older than `rootValidityWindow / 2` (30 minutes default) to avoid race conditions. Verifiers MUST accept any root in the history buffer within the validity window. Verifiers MUST reject roots older than the validity window with error `StaleIssuerRoot`.
- Revocation root follows the same rotation protocol with its own history buffer.

### 2.7 Circuit: IssuerBlindPredicate (PLONK, agent path)

**Private inputs:**

| Signal | Description |
|--------|-------------|
| `attr[0..7]` | 8 credential attribute values (field elements) |
| `issuerPubkeyAx, issuerPubkeyAy` | Issuer EdDSA public key (Baby Jubjub) |
| `expiryTimestamp` | Credential expiry (Unix timestamp, 64-bit) |
| `sigR8x, sigR8y, sigS` | Issuer's EdDSA signature over credCommitment |
| `issuerMerkleIndex` | Leaf index in issuer registry tree |
| `issuerMerkleSiblings[16]` | Sibling hashes for issuer tree |
| `revocationMerkleIndex` | Leaf index in revocation tree |
| `revocationMerkleSiblings[16]` | Sibling hashes for revocation tree |
| `revocationLeafValue` | Must be 0 (non-revoked) |
| `escrowNonce` | 128-bit randomness for escrow commitment |
| `slotIndex[0..7]` | Predicate clause slot indices |
| `opcode[0..7]` | Predicate clause opcodes |
| `value[0..7]` | Predicate clause comparison values |
| `clauseActive[0..7]` | Clause activation bits |
| `conjMask` | Conjunction/disjunction mask |

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `currentTimestamp` | Current time from verifier |
| `sessionNonce` | Session binding |
| `predicateHash` | Hash of the predicate descriptor (binds verifier to evaluated predicate) |
| `ncuaEscrowPubkey` | NCUA-designated escrow public key |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `issuerMerkleRoot` | Computed issuer registry root |
| `revocationRoot` | Computed revocation tree root |
| `predicateSatisfied` | 1 if predicate holds, 0 otherwise |
| `nullifierHash` | `Poseidon2(credCommitment, sessionNonce)` |
| `escrowedIssuer` | `Poseidon2(issuerLeaf, escrowNonce)` |
| `encryptedEscrow` | ECIES ciphertext (issuerLeaf ‖ escrowNonce) under ncuaEscrowPubkey |

**Circuit constraints (in order):**

1. **Credential commitment** (Poseidon12):
   ```
   credCommitment = Poseidon12(attr[0..7], issuerPubkeyAx, issuerPubkeyAy, expiryTimestamp)
   ```

2. **EdDSA signature verification** (EdDSAPoseidonVerifier):
   ```
   EdDSA.Verify((issuerPubkeyAx, issuerPubkeyAy), credCommitment, (sigR8x, sigR8y, sigS)) === 1
   ```

3. **Issuer leaf computation**:
   ```
   issuerLeaf = Poseidon2(issuerPubkeyAx, issuerPubkeyAy)
   ```

4. **Issuer Merkle membership** (BinaryMerkleRoot, depth 16):
   ```
   BinaryMerkleRoot(issuerLeaf, issuerMerkleIndex, issuerMerkleSiblings) === issuerMerkleRoot
   ```

5. **Issuer non-revocation** (exclusion proof):
   ```
   revocationLeafValue === 0
   BinaryMerkleRoot(revocationLeafValue, revocationMerkleIndex, revocationMerkleSiblings) === revocationRoot
   revocationMerkleIndex === issuerMerkleIndex  // same position in both trees
   ```

6. **Expiry check** (LessThan(64)):
   ```
   Num2Bits(64)(expiryTimestamp)
   Num2Bits(64)(currentTimestamp)
   currentTimestamp < expiryTimestamp
   ```

7. **Predicate policy binding**:
   ```
   computedPredicateHash = Poseidon4(
     pack(slotIndex[0..7], opcode[0..7]),
     pack(clauseActive[0..7], conjMask),
     pack(value[0..3]),
     pack(value[4..7])
   )
   computedPredicateHash === predicateHash
   ```

8. **Predicate evaluation** (8 clause evaluators + Boolean combiner):
   For each clause `i` in `[0, 8)`:
   ```
   selectedAttr[i] = MUX8(attr[0..7], slotIndex[i])
   clauseResult[i] = EvalOp(opcode[i], selectedAttr[i], value[i])
   effectiveResult[i] = clauseActive[i] ? clauseResult[i] : defaultForMask[i]
   ```
   where `defaultForMask[i]` = 1 if `conjMask[i]` = 1 (AND identity), 0 if `conjMask[i]` = 0 (OR identity).

   Boolean combination:
   ```
   andTerms = AND of all effectiveResult[i] where conjMask[i] = 1
   orTerms = OR of all effectiveResult[i] where conjMask[i] = 0
   predicateSatisfied = andTerms AND (orTerms OR noOrClauses)
   ```
   where `noOrClauses` = 1 iff no clause has `conjMask[i] = 0 AND clauseActive[i] = 1`.

   `EvalOp` gadget per clause uses `LessThan(64)` for comparison opcodes and equality checks via `IsZero(selectedAttr[i] - value[i])`.

9. **Nullifier** (Poseidon2):
   ```
   nullifierHash = Poseidon2(credCommitment, sessionNonce)
   ```

10. **Escrow commitment**:
    ```
    Num2Bits(128)(escrowNonce)
    escrowedIssuer = Poseidon2(issuerLeaf, escrowNonce)
    ```

11. **Escrow encryption** (in-circuit ECIES over Baby Jubjub):
    ```
    ephemeralKey = BabyPbk(escrowNonce)  // reuse nonce as ephemeral secret
    sharedSecret = BabyJubScalarMul(escrowNonce, ncuaEscrowPubkey)
    encryptedEscrow = Poseidon2(issuerLeaf, sharedSecret) // simplified: symmetric encrypt via Poseidon
    ```
    Note: Full ECIES would require the ephemeral public key as an additional public output. The simplified construction uses Poseidon as a PRF keyed by the shared secret; the escrow holder derives the same shared secret from the ephemeral key (output alongside) and their private key.

### 2.8 Circuit: IssuerBlindPredicateHuman (Groth16, human path)

Identical constraint structure to Section 2.7 but compiled for Groth16. The only difference is the proving system and ceremony requirement (circuit-specific Phase 2 on top of Semaphore v4 Phase 1 Powers of Tau).

## 3. Threat model (adversary capabilities, game definition)

### 3.1 IND-ISS Game (Issuer Indistinguishability)

**Adversary model:** The adversary A is a **malicious authorization server (AS)** or verifier who:

- Controls the verification endpoint and chooses the predicate, session nonce, and timestamp
- Has read access to the full issuer registry Merkle tree (all issuer public keys are public)
- Has access to public NCUA charter records (knows which CUs exist, their charter numbers, regulatory status)
- Can adaptively query an **epoch oracle** that triggers issuer registry mutations (additions, revocations) and returns updated roots
- Observes all public signals from proofs
- Can request multiple proofs across different epochs
- Does NOT have the NCUA escrow private key

**Game definition:**

```
Game IND-ISS(λ):

  Setup:
    pp ← PLONK.Setup(1^λ) or Groth16.Setup(circuit)
    (issuerTree, revTree) ← InitRegistry()
    ncuaEscrowKeypair ← KeyGen()
    b ←$ {0, 1}

  Phase 1 — Adaptive queries:
    A may adaptively:
      - Call AddIssuer(pk_i) → updated issuerTree root
      - Call RevokeIssuer(index_j) → updated revTree root
      - Call Prove(issuerIndex_k, attrs, predicate, nonce) for any enrolled
        non-challenged issuer → (proof, publicSignals)
      - Call GetEpoch() → (currentIssuerRoot, currentRevRoot, epochNumber)

  Challenge:
    A selects two non-revoked issuer indices (i₀, i₁) and attributes
    (attrs₀, attrs₁) such that:
      - Both issuers are enrolled in the current issuerTree
      - Neither issuer is revoked in the current revTree
      - For A's chosen predicate P: Eval(P, attrs₀) = Eval(P, attrs₁) = 1
    Challenger generates:
      proof* ← Prove(issuer_{i_b}, attrs_b, P, nonce*)

    A receives: (proof*, publicSignals*)
    where publicSignals* = (issuerMerkleRoot, revocationRoot,
      predicateSatisfied=1, nullifierHash, escrowedIssuer, encryptedEscrow)

  Phase 2 — Post-challenge adaptive queries:
    A may continue all Phase 1 queries EXCEPT:
      - Cannot call Prove with issuer i₀ or i₁ under the challenge nonce
      - Cannot call RevokeIssuer on i₀ or i₁

  Output:
    A outputs b' ∈ {0, 1}
    A wins if b' = b

  Advantage:
    Adv^{IND-ISS}_A(λ) = |Pr[b' = b] - 1/2|
```

**AS-as-adversary framing:** The game explicitly models the authorization server as the adversary because the AS is the entity with maximum verifier-side information: it controls which predicates are evaluated, it can correlate proofs with session metadata, and in federated identity systems (OIDC, SAML) the AS traditionally learns the issuer identity. The IND-ISS game requires that even this maximally-informed party cannot distinguish issuers. This rules out:

- **RFC 7662 introspection**: AS is on the hot path and sees the issuer directly.
- **OIDC PPID (Pairwise Pseudonymous Identifiers)**: PPIDs hide the user from the RP, but the AS (IdP) always knows its own identity — the issuer is the IdP itself, trivially revealed.
- **SPIFFE federation**: Trust domain is structurally encoded in the SPIFFE ID; any federation gateway sees it.

### 3.2 Auxiliary Input: Public NCUA Records

The adversary has access to auxiliary information `aux = {(charterNum_i, cuName_i, state_i, issuerPubkey_i)}` for all NCUA-chartered credit unions. The reduction must hold even when A can correlate public signals with this auxiliary data. Since all public signals are independent of the issuer identity (Section 4), and `escrowedIssuer` is randomized by `escrowNonce`, the auxiliary input provides no additional advantage.

### 3.3 Epoch-Adaptive Security

The adversary can trigger `O(poly(λ))` epoch transitions during the game. The reduction accounts for this by noting that each epoch produces a new Merkle root, but the root is a public signal that does not depend on *which* issuer was used (only on the *set* of all issuers). The adversary gains no information from observing root transitions, since root updates are determined by the full issuer set, not by individual prover actions.

## 4. Security argument (named assumption + reduction sketch)

### 4.1 Named Assumptions

- **A1: Knowledge soundness of Groth16** in the generic group model (Groth, 2016) / **knowledge soundness of PLONK** in the algebraic group model with random oracle (Gabizon-Williamson-Ciobotaru, 2019).
- **A2: Collision resistance of Poseidon** over BN254 scalar field (Grassi et al., 2021). Required for Merkle tree binding, credential commitment binding, and predicate hash binding.
- **A3: Discrete logarithm hardness on Baby Jubjub** (subgroup of BN254). Required for EdDSA unforgeability and escrow key security.
- **A4: Random Oracle Model (ROM)** for Fiat-Shamir transform in PLONK.

### 4.2 Reduction: IND-ISS from Zero-Knowledge

**Theorem:** If the proving system (Groth16 or PLONK) satisfies computational zero-knowledge, and Poseidon is collision-resistant, then for all PPT adversaries A:

```
Adv^{IND-ISS}_A(λ) ≤ Adv^{ZK}_{Sim}(λ) + Adv^{CR-Poseidon}(λ) + negl(λ)
```

**Reduction sketch:**

1. **Simulator construction:** Given the IND-ISS challenge, construct a simulator Sim that, given only the public signals (which are identical for both challenge issuers), produces a simulated proof indistinguishable from a real proof. This is exactly the ZK simulator guaranteed by Groth16/PLONK.

2. **Public signal analysis — issuer independence:** Enumerate all public signals and verify none depend on the issuer identity:
   - `issuerMerkleRoot`: Depends on the *entire* issuer set, not on which issuer the prover used. Both challenge issuers are in the same tree, so the root is identical for both. Across epochs, the root changes based on the full set mutation, not on prover choice.
   - `revocationRoot`: Same argument — depends on the full revocation set.
   - `predicateSatisfied`: By challenge construction, `Eval(P, attrs₀) = Eval(P, attrs₁) = 1`, so this is 1 for both.
   - `nullifierHash = Poseidon2(credCommitment, sessionNonce)`: Different for each issuer, but by ZK property, the verifier sees only the output of the ZK proof, not the witness. The nullifier is a public *output* of the circuit, computed from private inputs. Under Poseidon's PRF property, `Poseidon2(credCommitment_0, nonce)` and `Poseidon2(credCommitment_1, nonce)` are computationally indistinguishable without knowing the credential commitments (which are private).
   - `escrowedIssuer = Poseidon2(issuerLeaf, escrowNonce)`: Randomized by the 128-bit `escrowNonce`. Under Poseidon's PRF property, this is indistinguishable from random for any two distinct `issuerLeaf` values, given that `escrowNonce` is fresh and private.
   - `encryptedEscrow`: ECIES ciphertext under a key A does not hold. IND-CPA security of ECIES ensures this reveals nothing about `issuerLeaf`.
   - `predicateHash`: Depends only on the predicate descriptor chosen by A, not on the issuer.

3. **Nullifier distinguishability caveat:** The nullifier `Poseidon2(credCommitment, sessionNonce)` differs between the two challenge issuers. However, the adversary never sees `credCommitment` directly. If A could distinguish the two nullifier values (mapping them to specific `credCommitment` values), A would break Poseidon's PRF property. Formally: if A has advantage ε in IND-ISS via the nullifier, we construct a PRF distinguisher B for Poseidon with advantage ε.

4. **Epoch-adaptive queries:** During Phase 1 and Phase 2, A may trigger registry mutations. Each mutation changes `issuerMerkleRoot` deterministically based on the full tree. Since both challenge issuers remain enrolled and non-revoked throughout (by game rules), every proof A requests in adaptive queries references a root that contains both challenge issuers. The root reveals which issuers *exist* (public knowledge via NCUA records) but not which one the prover used. The reduction to ZK holds per-epoch because the simulator operates on each proof independently.

5. **Binding the hybrid:** Combining: A's view in the real game is (proof*, publicSignals*). Replace proof* with Sim(publicSignals*) — indistinguishable by ZK. In the simulated game, b is information-theoretically hidden because publicSignals* are identical for b=0 and b=1 (up to nullifier and escrow, which are PRF/IND-CPA indistinguishable). Therefore `Adv^{IND-ISS}_A ≤ Adv^{ZK} + Adv^{PRF-Poseidon} + Adv^{IND-CPA-ECIES} + negl(λ)`.

### 4.3 Predicate Soundness

**Theorem:** No PPT prover can produce a valid proof with `predicateSatisfied = 1` for attributes that do not satisfy the predicate bound by `predicateHash`, except with negligible probability.

**Proof sketch:** By knowledge soundness (A1), a valid proof implies the existence of an extractor that recovers the full witness, including attribute values and predicate descriptor. The constraint in step 7 (Section 2.7) forces `computedPredicateHash === predicateHash`, so the extracted predicate descriptor matches what the verifier committed to. The constraint in step 8 forces `predicateSatisfied` to be the correct evaluation of that descriptor over the extracted attributes. If the extractor recovers attributes not satisfying the predicate, it contradicts the constraint satisfaction.

### 4.4 Escrow Correctness

**Theorem:** The NCUA escrow holder (and only the escrow holder) can recover the issuer identity from `(escrowedIssuer, encryptedEscrow, ephemeralPubkey)`.

**Proof sketch:** Correctness follows from ECIES decryption. Exclusivity follows from DL hardness on Baby Jubjub (A3): recovering the shared secret without the escrow private key requires solving DLP. The escrow mechanism does not break IND-ISS for verifiers because the verifier does not hold the escrow private key (game assumption in Section 3.1).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Credential commitment | Poseidon12 (extended from Poseidon5) | Section 4, credentialCommitment |
| Issuer leaf | Poseidon2(issuerPubkeyAx, issuerPubkeyAy) | Terminology: Identity Commitment (generalized) |
| Issuer Merkle tree | Lean Incremental Merkle Tree, depth 16, Poseidon2 | Section 3.2, Merkle Tree |
| Revocation tree | Lean Incremental Merkle Tree, depth 16, Poseidon2 | Extension of Section 3.2 |
| Issuer signature | EdDSA on Baby Jubjub | Section 3.2, Signature Scheme |
| Nullifier | Poseidon2(credCommitment, sessionNonce) | Terminology: Nullifier (agent variant) |
| Predicate hash | Poseidon4 | New — extends scope commitment pattern |
| Escrow commitment | Poseidon2(issuerLeaf, escrowNonce) | New — extends nonce binding pattern |
| Escrow encryption | ECIES over Baby Jubjub | Extension of EdDSA key infrastructure |
| Human proof | Groth16 (Semaphore v4 Phase 1 ceremony) | Section 3.3, HumanUniqueness |
| Agent proof | PLONK with universal setup | Section 3.3, AgentPolicy |
| Root history buffer | 30-entry circular buffer per tree | Section 3.1, Root History Buffer |
| Session binding | sessionNonce as public input | Section 4, Mutual Handshake |

## 6. Circuit cost estimate

### IssuerBlindPredicate (PLONK, agent path)

| Gadget | Constraints |
|--------|-------------|
| Poseidon12 (credential commitment) | ~4,800 |
| EdDSAPoseidonVerifier (issuer signature) | ~13,500 |
| Poseidon2 (issuer leaf) | ~600 |
| BinaryMerkleRoot depth 16 (issuer tree) | ~9,600 (16 × ~600) |
| BinaryMerkleRoot depth 16 (revocation tree) | ~9,600 |
| Revocation leaf equality check | ~2 |
| Index equality (revocation = issuer index) | ~16 (bit comparison) |
| Num2Bits(64) × 3 (expiry, currentTimestamp, value range) | ~192 |
| LessThan(64) (expiry check) | ~130 |
| Poseidon4 (predicate hash) | ~1,600 |
| Predicate hash equality | ~1 |
| MUX8 × 8 (attribute selection) | ~512 |
| EvalOp × 8 (clause evaluation, includes LessThan(64)) | ~2,400 |
| Boolean combiner (AND/OR over 8 clauses) | ~64 |
| Poseidon2 (nullifier) | ~600 |
| Num2Bits(128) (escrow nonce) | ~128 |
| Poseidon2 (escrow commitment) | ~600 |
| BabyPbk (ephemeral key for ECIES) | ~2,000 |
| BabyJubScalarMul (shared secret) | ~2,000 |
| Poseidon2 (symmetric encrypt) | ~600 |
| **Total** | **~49,445** |

**Proving time target:** <3 seconds (PLONK, agent path, modern laptop GPU).

### IssuerBlindPredicateHuman (Groth16, human path)

Same constraint count (~49,445) but Groth16 proving is slower due to FFT and multi-scalar multiplication.

**Proving time target:** <10 seconds (Groth16, human path, browser WASM).

### Proof sizes

- Groth16: 128 bytes (constant, 2 G1 + 1 G2 point)
- PLONK: ~600 bytes (constant, depends on commitment scheme)

Both are constant-size regardless of predicate complexity, issuer set size, or schema.

## 7. Concrete deployment scenario

**Stakeholder:** Credit Union National Association (CUNA) / America's Credit Unions, managing a registry of ~4,700 NCUA-chartered federal and state credit unions.

**Scenario: Privacy-preserving shared branching — cross-CU NCUA membership verification**

1. **Registry setup:** CUNA deploys the issuer registry contract on an EVM-compatible chain. Each of the ~4,700 NCUA-chartered credit unions registers its EdDSA public key, producing an issuer Merkle tree of depth 16 (capacity 65,536, sufficient for growth). NCUA maintains the revocation tree; when a CU loses its charter, NCUA sets the corresponding revocation leaf to 1.

2. **Credential issuance:** State Employees' Credit Union (SECU, North Carolina, ~2.8M members) issues a credential to member Alice with attributes:
   - `attr[0]` = 1 (chartered_by_NCUA = true)
   - `attr[1]` = 27 (state_code = NC)
   - `attr[2]` = 1946 (charter_year)
   - `attr[3]` = 3 (membership_tier, encoded)
   - `attr[4..7]` = 0 (unused)
   - SECU signs the credential commitment with its EdDSA key.

3. **Presentation:** Alice visits a PenFed Credit Union (Virginia) shared branch. PenFed's terminal sets the predicate: `attr[0] EQ 1` (NCUA-chartered = true), with `predicateHash` computed and displayed. Alice's wallet generates an IssuerBlindPredicate proof. PenFed sees:
   - `predicateSatisfied = 1` (Alice is NCUA-chartered)
   - `issuerMerkleRoot` (matches current on-chain root)
   - `revocationRoot` (issuer not revoked)
   - `nullifierHash` (for session Sybil detection)
   - `escrowedIssuer` + `encryptedEscrow` (for NCUA incident response only)
   - PenFed does NOT learn that Alice is a SECU member, that she is from NC, or any other attribute.

4. **Incident response:** If PenFed reports suspicious activity under NCUA Part 748, NCUA's designated escrow key holder decrypts `encryptedEscrow` to recover `issuerLeaf`, identifies SECU as the issuing CU, and coordinates the investigation. This is a one-way channel: NCUA can attribute, but the verifier (PenFed) cannot.

5. **Root rotation:** When a new CU joins NCUA or one loses its charter, CUNA updates the issuer tree (or NCUA updates the revocation tree). Proofs generated against the previous root remain valid for the `rootValidityWindow` (1 hour default). Members whose proofs reference roots older than 30 minutes receive a wallet notification to regenerate.

**Additional scenarios:**

- **Cross-firm FINRA-licensed agent proof:** A broker-dealer verifies that a financial advisor holds an active FINRA license without learning which firm employs them. The issuer set is FINRA member firms (~3,400). Predicate: `attr[0] EQ 1` (FINRA-registered) AND `attr[1] GTE 2020` (registration year ≥ 2020).
- **Cross-country jurisdiction-hiding KYB:** A multinational fintech verifies that a business entity is KYB-approved by *some* G20 regulatory body without learning which jurisdiction. The issuer set is G20 financial regulators (~25). Jurisdiction is hidden because the issuer key is the only signal that would reveal it, and it is entirely in the private witness.

## 8. Why the baseline cannot match

### 8.1 Structural impossibility: BBS+ issuer key exposure

The BBS+ `ProofVerify` algorithm (draft-irtf-cfrg-bbs-signatures, Section 3.5.3) takes the issuer's public key `PK` as a **mandatory explicit parameter**:

```
result = ProofVerify(PK, proof, header, ph, disclosed_messages, disclosed_indexes)
```

There is no variant of `ProofVerify` that accepts a *set* of public keys and determines which one signed. The verifier must know `PK` to verify. This is not a limitation of the VC-DI BBS+ profile — it is a mathematical property of the BBS+ proof system: the verification equation is linear in `PK`, and substituting a different key produces a different verification result. Issuer-hiding within a set requires either:

- Trial verification against all keys (linear in set size, reveals which key succeeded), or
- A ZK proof of knowledge of a valid BBS+ signature under *some* key in a committed set — which is precisely a ZK construction, not BBS+ itself.

### 8.2 AS-as-adversary impossibility

Beyond BBS+ specifically, *any* non-ZK federated identity protocol where the authorization server is on the verification path reveals the issuer to the AS by construction:

- **RFC 7662 (Token Introspection):** The AS *is* the issuer; it handles the introspection request and knows its own identity trivially.
- **OIDC with PPIDs:** Pairwise pseudonymous identifiers hide the *user* from the relying party, but the IdP (issuer) is identified in the `iss` claim of every ID token. The RP always knows the issuer.
- **SPIFFE/WIMSE federation:** The SPIFFE ID structurally encodes the trust domain, which is the issuer. Any federation gateway that routes based on trust domain sees the issuer.

The IND-ISS game (Section 3.1) formalizes this: the adversary *is* the AS/verifier with full auxiliary information. No protocol where the verifier must identify the issuer to verify the credential can satisfy IND-ISS. The Bolyra construction satisfies it because the issuer key is exclusively in the private witness.

### 8.3 No constant-size arbitrary predicate in BBS+

BBS+ selective disclosure reveals specific message fields. To prove a Boolean predicate *over hidden fields* (e.g., `attr[0] == 1 AND attr[2] >= 1946`), BBS+ must compose with external NIZK gadgets (Sigma protocols, Bulletproofs). Each predicate type requires a bespoke composition:

- Equality predicates: Sigma protocol for discrete-log equality (~64 bytes per clause)
- Range predicates: Bulletproof or set-membership proof (~672 bytes for 64-bit range)
- Disjunctions: OR-composition via CDS94, multiplying proof size by branch count

For a predicate with `k` clauses including `r` range checks and `d` disjunction branches, proof size is `O(k + r·log(range) + d)`. The Bolyra construction produces a fixed ~600-byte PLONK proof or 128-byte Groth16 proof for any predicate expressible in the 8-clause descriptor, regardless of clause types or combination logic.

### 8.4 Per-schema issuer key management

For W3C VC + BBS+ to operate across multiple schemas (NCUA membership, FINRA licensing, G20 KYB), the verifier must maintain a registry mapping schemas to issuer public keys. This registry is itself an issuer-revealing side channel: the verifier can enumerate which issuers are registered for which schemas and, upon receiving a proof, narrow the issuer to the schema's registered set. In the cross-country KYB scenario, this immediately reveals the jurisdiction.

The Bolyra construction uses a single issuer Merkle tree for all schemas. The verifier sees only the root, which reveals the *set* of all issuers but not which one signed. Combined with issuer-hiding, the verifier learns nothing beyond "some issuer in this tree signed attributes satisfying this predicate."

### 8.5 No issuer revocation without identity revelation in BBS+

If a BBS+ issuer's key is compromised, the verifier must remove that specific key from its trusted set. This requires the verifier to know which key to distrust — i.e., to have per-issuer key knowledge. In the Bolyra construction, issuer revocation is handled by the revocation tree (Section 2.4): the registry operator sets a leaf to 1, and the circuit proves non-revocation against the updated root. The verifier never learns which specific issuer was revoked for a given proof — only that the prover's issuer is not in the revoked set.
