# Construction

## 1. Statement of claim

An AI agent proves that a predicate `φ` over its credential attributes evaluates to `true`, that the credential was signed by *some* issuer whose public key belongs to a published issuer registry (a Merkle tree of issuer keys), and that the credential has not been revoked — all without the verifier learning *which* issuer signed the credential, which specific attribute values the credential contains (beyond what `φ` implies), or which leaf in the issuer tree was used. The proof is constant-size (a single PLONK proof ≈ 768 bytes) regardless of the number of issuers in the registry or the complexity of the predicate, and the construction is formally secure under an IND-ISS game defined below.

## 2. Construction (gadgets, circuits, public/private inputs)

### Overview

A new circuit **IssuerBlindPredicate** is introduced alongside the existing AgentPolicy circuit. It operates in the PLONK proving system (agent-side, universal setup, no per-circuit ceremony). The construction has three layers:

1. **Issuer-anonymous credential verification** — EdDSA signature check + Merkle membership in an issuer registry tree, all on private inputs.
2. **Predicate evaluation** — a compiled Boolean expression over credential attribute fields, evaluated inside the circuit against private attribute values.
3. **Revocation non-membership** — Merkle non-membership proof against a sparse Merkle tree of revoked credential commitments.

### Circuit: IssuerBlindPredicate

**Proving system:** PLONK (universal setup via pot16.ptau)

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `attrValues[MAX_ATTRS]` | Field[16] | Credential attribute values (padded to 16 slots) |
| `attrCount` | Field | Actual number of populated attributes |
| `issuerPubkeyAx` | Field | Issuer EdDSA public key x-coordinate (Baby Jubjub) |
| `issuerPubkeyAy` | Field | Issuer EdDSA public key y-coordinate (Baby Jubjub) |
| `sigR8x, sigR8y, sigS` | Field[3] | Issuer EdDSA signature over credential digest |
| `issuerMerkleIndex` | Field | Leaf index in issuer registry tree |
| `issuerMerkleProofSiblings[ISSUER_DEPTH]` | Field[16] | Merkle siblings (depth 16 → up to 65,536 issuers) |
| `issuerMerkleProofLength` | Field | Actual depth |
| `credentialSalt` | Field | Per-credential randomness for commitment binding |
| `revocationMerkleProof[REV_DEPTH]` | Field[20] | Sparse Merkle non-membership proof (depth 20) |
| `revocationProofHelper` | Field | Non-membership witness (adjacent leaf value) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `issuerRegistryRoot` | Field | Merkle root of the issuer public key registry |
| `predicateHash` | Field | Poseidon hash of the compiled predicate bytecode (identifies which predicate is being evaluated) |
| `revocationRoot` | Field | Root of the sparse Merkle revocation tree |
| `sessionNonce` | Field | Binds to handshake session |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `predicateResult` | Field | Constrained to equal 1 (predicate satisfied) |
| `credentialCommitment` | Field | Poseidon hash binding attributes + issuer + salt |
| `blindNullifier` | Field | Poseidon2(credentialCommitment, sessionNonce) — replay prevention |

### Gadgets

**Gadget 1: Credential Digest & Commitment**

```
credentialDigest = PoseidonN(attrValues[0], ..., attrValues[MAX_ATTRS-1])
credentialCommitment = Poseidon4(credentialDigest, issuerPubkeyAx, issuerPubkeyAy, credentialSalt)
```

The commitment binds the attribute values to the issuer identity and a blinding salt. The salt prevents offline brute-force of low-entropy attributes.

**Gadget 2: Issuer EdDSA Verification (inside circuit)**

```
EdDSAPoseidonVerifier(
  pubkey: (issuerPubkeyAx, issuerPubkeyAy),
  message: credentialDigest,
  signature: (sigR8x, sigR8y, sigS)
)
```

This proves that the credential digest was signed by the issuer whose key is `(Ax, Ay)` — but that key is a *private input*, so the verifier never sees it.

**Gadget 3: Issuer Registry Membership**

```
issuerLeaf = Poseidon2(issuerPubkeyAx, issuerPubkeyAy)
computedIssuerRoot = BinaryMerkleRoot(ISSUER_DEPTH, issuerLeaf, issuerMerkleIndex, issuerMerkleProofSiblings)
computedIssuerRoot === issuerRegistryRoot   // public input equality constraint
```

The issuer's key is proven to belong to the registry without revealing which leaf.

**Gadget 4: Predicate Evaluation Engine**

The predicate is encoded as a fixed-width Boolean expression tree over attribute indices, compiled to constraints at circuit generation time. The circuit supports a universal predicate template:

```
// Predicate template: up to 8 clauses, each is (attrIndex, comparator, threshold)
// comparator ∈ {EQ, NEQ, LT, GT, LTE, GTE}
// Clauses combined with AND/OR/NOT via a 3-level Boolean tree

for each clause c_i in predicate:
    evaluate comparator(attrValues[c_i.attrIndex], c_i.threshold) → bit_i

combine bits via Boolean tree → predicateResult
predicateResult === 1  // constrained
```

The `predicateHash = PoseidonN(clause_0, ..., clause_7, booleanTreeEncoding)` is a public input so the verifier knows *which* predicate was proven without seeing the attribute values. Different predicates (NCUA membership, FINRA license, KYB jurisdiction) reuse the same circuit with different `predicateHash` values — no per-schema circuit compilation needed.

**Concrete example** — `chartered_by_NCUA == true`:
- Clause 0: `(attrIndex=3, comparator=EQ, threshold=1)`
- All other clauses: identity (always true)
- Boolean tree: AND of all clauses
- `predicateHash = Poseidon(3, EQ, 1, ..., AND_TREE)`

**Gadget 5: Revocation Non-Membership**

```
SparseMerkleNonMembership(REV_DEPTH, credentialCommitment, revocationMerkleProof, revocationProofHelper)
computedRevRoot === revocationRoot  // public input
```

This proves the credential has not been revoked without revealing which credential or issuer is being checked.

**Gadget 6: Blind Nullifier**

```
blindNullifier = Poseidon2(credentialCommitment, sessionNonce)
```

Prevents replay. The nullifier is deterministic per credential per session but reveals nothing about the issuer.

### Predicate Compilation (off-chain)

A predicate compiler takes a schema-annotated Boolean expression and produces:

1. A clause vector `[(attrIndex, comparator, threshold), ...]` (max 8 clauses)
2. A Boolean combination tree (max 3 levels of AND/OR/NOT)
3. The `predicateHash` for public verification

This compiler is a pure function — no trusted setup, no per-schema circuit. The same IssuerBlindPredicate circuit handles all schemas.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model: two classes

The construction must resist two distinct adversary classes, reflecting the two parties that see protocol messages in any credential-verification deployment:

**Class 1 — Malicious Verifier (Resource Server analogue).** This is the party that receives and checks the proof. In OAuth/RFC 7662 terms, this is the Resource Server (RS). The RS adversary `A_RS` is PPT and:

- Sees all public inputs and outputs of the proof (issuerRegistryRoot, predicateHash, revocationRoot, sessionNonce, predicateResult, credentialCommitment, blindNullifier)
- Knows the full issuer registry (all issuer public keys and their Merkle tree)
- Can request proofs from honest provers adaptively
- Can choose the predicate to be evaluated
- Controls the session nonce
- Does NOT control the proving key or the prover's private inputs

**Class 2 — Honest-but-Curious Intermediary (Authorization Server analogue).** In deployments with a relay, proof aggregator, or registry-update service — any entity that routes, caches, or processes proofs on behalf of verifiers — the intermediary sees the same public signals as the verifier, and additionally may observe:

- Timing and ordering of proof submissions (traffic analysis)
- Multiple proofs across sessions from different provers against the same registry root (cross-session correlation)
- The on-chain transaction calldata containing the proof and public signals

The AS adversary `A_AS` is honest-but-curious (follows the protocol but attempts to extract issuer identity from its view) and PPT. Crucially, `A_AS` has the same formal view as `A_RS` — both see exactly the public signals and nothing more — but `A_AS` aggregates observations across many sessions, making cross-session linkage its primary attack vector.

### Two hiding properties

**Property 1: RS-blind issuer hiding (verifier-facing).** The verifier (RS) cannot determine which issuer signed a credential from a single proof. This is the property captured by the IND-ISS game below. RFC 7662 filtered introspection can *simulate* this property at the RS level by having the AS strip `iss` / `client_id` from the introspection response (RFC 7662 §2.2 permits the AS to omit fields). However, this is a policy decision by the AS, not a cryptographic guarantee — the AS can choose to include or leak the issuer at any time, and the RS must trust the AS to filter correctly.

**Property 2: AS-blind issuer hiding (intermediary-facing).** No intermediary in the protocol — relay, proof aggregator, registry operator, or on-chain indexer — can determine which issuer signed a credential, even across multiple sessions. This is the property that RFC 7662 *cannot* provide: the AS is the party that issued or validated the token and therefore *inherently knows* the issuer identity. Filtered introspection hides the issuer from the RS by relying on the AS as a trusted filter; it does not and cannot hide the issuer from the AS itself. In the IssuerBlindPredicate construction, there is no AS-equivalent party. The proof is self-contained: the prover generates it locally, the verifier checks it on-chain, and no intermediary ever handles the raw credential or issuer key. The issuer identity is a private circuit input that never appears in any protocol message, on-chain calldata, or emitted event.

**AS-blind issuer hiding is the strictly novel property.** RS-blind hiding is achievable (with trust assumptions) via filtered introspection or a privacy-proxy architecture. AS-blind hiding is achievable only when no party in the protocol possesses the issuer identity in cleartext — which requires the credential verification itself to occur inside a zero-knowledge proof.

### IND-ISS Game Definition (covering both adversary classes)

**Game IND-ISS(λ, A)** — parameterized by adversary `A` instantiated as either `A_RS` or `A_AS`:

1. **Setup.** Challenger generates PLONK CRS. Challenger enrolls `n ≥ 2` issuers with keys `{(Ax_j, Ay_j)}_{j=1}^{n}` in the issuer registry tree, producing `issuerRegistryRoot`.

2. **Phase 1 (adaptive queries).** Adversary `A` makes adaptive queries: for any issuer index `j`, predicate `φ`, and attribute vector `attrs` satisfying `φ(attrs) = true`, the challenger returns a valid IssuerBlindPredicate proof along with all public signals. When `A = A_AS`, the adversary additionally receives the session nonce, on-chain transaction calldata, and timing metadata for each query (modeling the intermediary's aggregated view). `A` may make polynomially many such queries.

3. **Challenge.** `A` selects two issuer indices `j_0, j_1` and an attribute vector `attrs*` such that `φ(attrs*) = true` under both issuers' signatures. Challenger flips coin `b ←$ {0,1}`, produces a proof using issuer `j_b`'s signature over `attrs*` with a fresh `credentialSalt`.

4. **Phase 2 (post-challenge queries).** `A` makes more adaptive queries (excluding the challenge issuers with `attrs*` under the challenge predicate).

5. **Guess.** `A` outputs `b'`. `A` wins if `b' = b`.

**Definition.** The IssuerBlindPredicate construction is **(t, ε)-IND-ISS secure** if for all PPT adversaries `A` (in either class) running in time `t`:

```
|Pr[b' = b] - 1/2| ≤ ε(λ)
```

**Note on the AS adversary's extra view.** The `A_AS` adversary's additional observations (timing, calldata, cross-session correlation) do not help because:

- **Calldata** contains only the public signals and the PLONK proof `π` — exactly what `A_RS` sees. The on-chain transaction adds no issuer-correlated side channel beyond the public signals already analyzed in the game.
- **Timing** is outside the algebraic model. The proof generation time is dominated by the PLONK prover's FFT and MSM operations over the full constraint system; it does not vary measurably with the issuer's position in the Merkle tree (the tree traversal is < 0.1% of proving time for 16-level trees). Implementations SHOULD add constant-time padding to proof generation to foreclose microarchitectural timing channels, but this is an implementation-level concern, not a protocol-level one.
- **Cross-session correlation** via `credentialCommitment` is defeated by the fresh `credentialSalt` per proof. Two proofs from the same issuer for the same attributes produce distinct, unlinkable commitments and nullifiers.

### Issuer-set anonymity bound

The anonymity set is exactly the set of issuer leaves in the registry tree. An adversary's advantage in IND-ISS (under either adversary class) is bounded by their advantage in breaking zero-knowledge of the PLONK proof system plus their advantage in finding Poseidon collisions (to distinguish commitments):

```
Adv^{IND-ISS}(A) ≤ Adv^{ZK}_{PLONK}(A) + Adv^{CR}_{Poseidon}(A)
```

This bound holds identically for `A_RS` and `A_AS` because their algebraic views are identical — the AS adversary's extra metadata does not contribute algebraic distinguishing advantage.

## 4. Security argument (named assumption + reduction sketch)

**Named assumptions:**

1. **Knowledge soundness of PLONK** (in the algebraic group model + random oracle model): A valid PLONK proof implies the prover knows a witness satisfying all circuit constraints.
2. **Collision resistance of Poseidon** over BN254 scalar field: No PPT adversary can find `(x, x')` with `x ≠ x'` and `Poseidon(x) = Poseidon(x')` with non-negligible probability.
3. **Discrete logarithm hardness on Baby Jubjub**: Given `(Ax, Ay) = s·G`, no PPT adversary can recover `s`.
4. **Zero-knowledge property of PLONK** (simulation extractability): The proof reveals nothing about the witness beyond the public outputs.

**Reduction sketch for IND-ISS (covering both A_RS and A_AS):**

*Claim:* If PLONK is zero-knowledge and Poseidon is collision-resistant, then IssuerBlindPredicate is IND-ISS secure against both adversary classes.

*Proof sketch:*

Suppose adversary `A` (instantiated as either `A_RS` or `A_AS`) wins IND-ISS with advantage `ε`. We construct a distinguisher `D` that breaks PLONK zero-knowledge:

1. `D` receives the challenge: either a real proof `π` (using issuer `j_b`) or a simulated proof `π_sim` (from the PLONK simulator, which knows no witness).

2. The real proof and the simulated proof are indistinguishable by the ZK property. The public outputs are:
   - `predicateResult = 1` (same for both issuers)
   - `credentialCommitment` — differs between `j_0` and `j_1`, but is randomized by `credentialSalt`.

3. **Key step (salt-based indistinguishability):** The `credentialSalt` is fresh uniform randomness per proof. Therefore:
   ```
   credentialCommitment = Poseidon4(credentialDigest, Ax_{j_b}, Ay_{j_b}, salt_b)
   ```
   Since `salt_b` is uniform over `F_p` and private, `credentialCommitment` is computationally indistinguishable from random under Poseidon's PRF assumption (a consequence of collision resistance in the ROM). The adversary cannot distinguish `credentialCommitment` for `j_0` from `credentialCommitment` for `j_1` without knowing the salt.

4. The `blindNullifier = Poseidon2(credentialCommitment, sessionNonce)` is similarly randomized by the salt, defeating cross-session linkage even for `A_AS` who observes multiple sessions.

5. All other public signals (`issuerRegistryRoot`, `predicateHash`, `revocationRoot`, `sessionNonce`, `predicateResult`) are identical across both issuers by construction.

6. **AS-adversary extra view.** For `A_AS`, the additional observations (transaction calldata, timing, cross-session data) are addressed:
   - Calldata is a deterministic encoding of `(π, publicSignals)` — already covered by steps 1–5.
   - Cross-session correlation requires linking two `credentialCommitment` values to the same issuer. By step 3, each commitment is independently randomized by a fresh salt, so two commitments from the same issuer are indistinguishable from two commitments from different issuers under Poseidon CR.
   - Timing side channels are outside the algebraic model. Implementations SHOULD use constant-time proof generation (standard for PLONK FFT-based provers).

7. Therefore `A`'s view is computationally indistinguishable between `b=0` and `b=1` for both adversary classes, and:
   ```
   ε ≤ ε_ZK + ε_CR
   ```
   where `ε_ZK` is the PLONK ZK advantage and `ε_CR` is the Poseidon collision-resistance advantage.

**Soundness argument:** By PLONK knowledge soundness, a valid proof implies the prover knows:
- An issuer key `(Ax, Ay)` that is a leaf in the registry (Gadget 3)
- A valid EdDSA signature over the credential digest under that key (Gadget 2)
- Attribute values satisfying the predicate (Gadget 4)
- A non-membership witness for the revocation tree (Gadget 5)

Forging any of these requires breaking EdDSA unforgeability (DL on Baby Jubjub), Poseidon collision resistance (for Merkle forgery), or PLONK knowledge soundness.

## 5. Bolyra primitive mapping

| Construction component | Bolyra primitive | Spec reference |
|---|---|---|
| Credential digest hash | Poseidon (multi-input, BN128 scalar field) | §2 Cryptographic Primitives |
| Credential commitment | Poseidon4 (analogous to existing Poseidon5 credential commitment) | §4.2 Credential Commitment |
| Issuer signature verification | EdDSAPoseidonVerifier on Baby Jubjub (a=168700, d=168696) | §2 Signature Scheme |
| Issuer registry tree | Lean Incremental Merkle Tree with Poseidon2 node hash, depth 16 | §2 Merkle Tree (depth adapted) |
| Blind nullifier | Poseidon2(credentialCommitment, sessionNonce) — identical form to agent nullifier | §3.2 Agent Proof, nullifier definition |
| Session binding | sessionNonce public input, checked on-chain | §3.1 Protocol Flow, step 5b |
| Proving system | PLONK with universal setup (pot16.ptau) — permitted for agent-side circuits | §2.3 Proving Systems |
| Revocation tree | Sparse Merkle Tree with Poseidon2, depth 20 — extends existing tree infrastructure | §2 Merkle Tree |
| Scope commitment for delegation chain entry | `Poseidon2(predicateHash, credentialCommitment)` — analogous to existing scope commitment | §4.2 Scope Commitment |

No new cryptographic primitives are introduced. Every component maps to an existing Bolyra building block.

## 6. Circuit cost estimate

### Constraint breakdown

| Gadget | Constraints | Notes |
|---|---|---|
| Poseidon hash (credential digest, 16 inputs) | ~4,800 | ~300 constraints per Poseidon round, ~16 rounds for multi-input |
| Poseidon4 (credential commitment) | ~1,200 | 4-input Poseidon |
| EdDSA Poseidon Verifier | ~14,000 | Standard Baby Jubjub scalar mul + Poseidon-based EdDSA |
| Poseidon2 (issuer leaf hash) | ~600 | 2-input Poseidon |
| Binary Merkle Root (depth 16, issuer tree) | ~9,600 | 16 × Poseidon2 (~600 each) |
| Predicate evaluation (8 clauses × comparator) | ~4,000 | 8 × LessThan(64) + equality checks + Boolean tree |
| Range checks (Num2Bits) | ~1,500 | Various 64-bit decompositions |
| Sparse Merkle non-membership (depth 20) | ~12,000 | 20 × Poseidon2 + ordering constraint |
| Poseidon2 (blind nullifier) | ~600 | 2-input |
| **Total** | **~48,300** | Well within 2^16 = 65,536 constraint budget |

### Proving time targets

| Metric | Target | Rationale |
|---|---|---|
| PLONK proving time (agent) | < 4 seconds | Agent-side, PLONK universal setup, ~48K constraints. PLONK at 2^16 on snarkjs: ~3-5s on modern hardware; rapidsnark: ~0.8s |
| PLONK verification time (on-chain) | < 300K gas | Single pairing check, constant regardless of issuer set size |
| Proof size | 768 bytes | Standard PLONK proof (3 group elements + field elements) |

The circuit fits within the existing `pot16.ptau` (2^16 constraints) universal SRS. No new ceremony is required.

## 7. Concrete deployment scenario

### Cross-CU NCUA Membership Proof

**Stakeholder:** Pentagon Federal Credit Union (PenFed, $36B assets) operating an AI-powered loan origination agent that needs to prove NCUA charter status to partner credit unions without revealing PenFed's identity.

**Setup:**
1. The NCUA (National Credit Union Administration) publishes an **issuer registry Merkle tree** containing the EdDSA public keys of all 4,600+ federally insured credit unions authorized to issue NCUA membership credentials. The root `issuerRegistryRoot` is published on-chain and updated quarterly.

2. PenFed's compliance officer signs an attribute credential for PenFed's AI loan origination agent:
   ```
   attrValues = [
     charter_number,        // attr[0] = 12345 (hidden)
     chartered_by_NCUA,     // attr[1] = 1 (true)
     total_assets_tier,     // attr[2] = 5 (>$10B, hidden)
     jurisdiction,          // attr[3] = "US" encoded (hidden)
     enforcement_actions,   // attr[4] = 0 (hidden)
     ...
   ]
   ```
   PenFed's compliance key `(Ax_penfed, Ay_penfed)` signs `credentialDigest = PoseidonN(attrValues)`.

3. PenFed's key is enrolled as a leaf in the NCUA issuer registry tree.

**Proof generation:**
- PenFed's agent generates an IssuerBlindPredicate proof with:
  - Predicate: `chartered_by_NCUA == 1` (predicateHash published)
  - All attribute values private
  - Issuer key private
  - Fresh `credentialSalt` ensures unlinkability across sessions

**Verification (by partner CU or DeFi lending pool):**
- Verifier checks:
  1. `issuerRegistryRoot` matches the on-chain NCUA registry root
  2. `predicateHash` matches the agreed "NCUA membership" predicate
  3. `predicateResult == 1`
  4. `revocationRoot` is current
  5. PLONK proof verifies
  6. `blindNullifier` is fresh (not replayed)

**What the verifier learns:** An NCUA-chartered credit union's agent holds a valid, unrevoked credential satisfying the NCUA membership predicate. **Nothing else** — not which credit union, not the charter number, not the asset tier, not the jurisdiction.

**What BBS+ would leak:** The issuer public key (identifying PenFed), the status list URL (identifying PenFed's revocation endpoint), and the schema-specific claim indices.

**What RFC 7662 filtered introspection would leak to the AS:** Even if the AS strips `iss` and `client_id` from the introspection response to the RS (achieving RS-blind hiding), the AS itself — typically operated by the NCUA or a CUSO (Credit Union Service Organization) — knows exactly which credit union's token is being introspected. In regulated environments where the NCUA is simultaneously the registry operator and the supervisory authority, this creates an information asymmetry: the NCUA learns real-time transaction patterns of individual credit unions. The IssuerBlindPredicate construction eliminates this asymmetry entirely — the on-chain registry stores only the Merkle root, and no party (including the registry operator) ever sees which leaf was used.

### Extension: Cross-Country KYB with Hidden Jurisdiction

The same circuit handles the KYB scenario by changing only the predicate and issuer registry:
- Issuer registry: KYB-authorized signers across US, EU, UK, Singapore
- Predicate: `kyb_verified == 1 AND incorporation_year < 2025`
- Jurisdiction is an attribute that stays hidden; the issuer key (which would encode jurisdiction) is also hidden
- The intermediary routing KYB verification requests (analogous to a cross-border AS) learns nothing about the originating jurisdiction

No new circuit deployment is needed — only a new `predicateHash` and `issuerRegistryRoot`.

## 8. Why the baseline cannot match

### Gap 1: Issuer anonymity is structurally impossible in BBS+

BBS+ derived proofs are verified against a *specific, named* issuer public key. The `VerifyProof` algorithm (draft-irtf-cfrg-bbs-signatures §3.5.2) takes the issuer's public key as an explicit input. There is no mechanism to verify against "some key in a set" without iterating over the set (O(|S|) verification) or introducing a fundamentally different proof system. The IssuerBlindPredicate circuit verifies the issuer's EdDSA signature *inside* the ZK circuit with the key as a private input, then proves Merkle membership — a construction BBS+ cannot replicate without becoming a ZK circuit itself.

### Gap 2: Constant-size proof is impossible for issuer-set hiding in BBS+

Even with a hypothetical ring-signature extension over BBS+, proof size grows as O(|S|) for Pedersen-style ring constructions or O(log|S|) for tree-based ring signatures. The IssuerBlindPredicate proof is exactly 768 bytes regardless of whether the issuer registry contains 10 or 100,000 issuers, because the Merkle membership proof is verified *inside* the PLONK circuit and compressed into the constant-size PLONK proof.

### Gap 3: Arbitrary predicate compilation requires a circuit, not a signature scheme

BBS+ is a multi-message signature with selective disclosure — it can reveal or hide individual messages, and with extensions, prove simple range predicates. It cannot evaluate arbitrary Boolean expressions like `(chartered_by_NCUA == 1) AND (enforcement_actions == 0) AND (total_assets_tier >= 3)` in a single atomic proof. Each new predicate type requires a separate composition layer (Bulletproofs for ranges, equality proofs for comparisons) with distinct setup and proof-size overhead. The IssuerBlindPredicate circuit compiles any Boolean expression over up to 8 clauses into the same circuit, distinguished only by the `predicateHash` public input.

### Gap 4: Revocation breaks issuer anonymity in BBS+

W3C StatusList2021 and Bitstring Status List require the holder to reference a status list URL controlled by the issuer. Consulting this URL reveals the issuer's identity to the verifier (or to any network observer). The IssuerBlindPredicate circuit proves non-revocation via a sparse Merkle non-membership proof against a *unified* revocation tree (all issuers share one tree), so no issuer-specific endpoint is ever contacted.

### Gap 5: No formal IND-ISS security exists for BBS+

The BBS+ security proofs (draft-irtf-cfrg-bbs-signatures §7) cover EUF-CMA unforgeability and zero-knowledge of derived proofs relative to a fixed issuer key. They do not define, model, or prove security against issuer indistinguishability. The IND-ISS game defined in §3 above is provably satisfied by the IssuerBlindPredicate construction under PLONK zero-knowledge and Poseidon collision resistance — assumptions already present in Bolyra's security model. BBS+ would need to be redesigned from scratch to achieve this property.

### Gap 6: RFC 7662 filtered introspection achieves RS-blind hiding but not AS-blind hiding

RFC 7662 §2.2 permits the AS to omit fields from the introspection response, enabling the AS to strip `iss`, `client_id`, and other issuer-identifying metadata before returning the response to the RS. This achieves **RS-blind issuer hiding** — the RS (verifier) does not learn which issuer is behind the token. However, this is a *trust-based* property, not a *cryptographic* property:

- **The AS always knows the issuer.** The AS issued or validated the token; the issuer identity is in its database. Filtered introspection hides the issuer from the RS by making the AS a trusted privacy proxy. If the AS is compromised, colluding, subpoenaed, or simply misconfigured, RS-blind hiding fails silently.
- **The AS can correlate across sessions.** An honest-but-curious AS observing introspection requests from multiple RSs can build a complete graph of which issuers are transacting with which verifiers, at what frequency, and at what times. This is precisely the cross-session linkage attack that `A_AS` models in the IND-ISS game.
- **No cryptographic enforcement.** There is no proof that the AS actually filtered the response. The RS cannot verify that the AS is not selectively leaking issuer identity to favored parties. The privacy guarantee is a policy promise, not a mathematical one.

The IssuerBlindPredicate construction provides **AS-blind issuer hiding**: no party in the protocol — not the verifier, not the relay, not the registry operator, not the on-chain indexer — ever possesses the issuer identity in cleartext. The issuer key is a private circuit input, consumed inside the PLONK proof and never emitted. This is a strictly stronger property than filtered introspection can provide, regardless of trust assumptions about the AS.

### Summary comparison

| Property | IssuerBlindPredicate | BBS+ VC | RFC 7662 Filtered Introspection |
|---|---|---|---|
| RS-blind issuer hiding (verifier cannot identify issuer) | Yes (cryptographic) | No | Yes (trust-based, AS policy) |
| AS-blind issuer hiding (no intermediary can identify issuer) | Yes (cryptographic) | No | **No** (AS inherently knows issuer) |
| Proof size vs. issuer set | O(1) — 768 bytes always | O(|S|) or O(log|S|) with extensions | N/A (no proof, token-based) |
| Arbitrary Boolean predicates | Yes (8-clause template, single circuit) | No (per-predicate composition layer) | No (AS returns fixed claim fields) |
| Revocation without issuer leak | Yes (unified sparse Merkle tree) | No (status list URL leaks issuer) | No (AS revocation lookup identifies issuer) |
| IND-ISS formal security (both A_RS and A_AS) | Yes (proven under PLONK ZK + Poseidon CR) | Undefined and unproven | Undefined; AS is outside the hiding guarantee |
| Cross-session unlinkability for intermediary | Yes (fresh credentialSalt per proof) | No (issuer key visible) | No (AS sees all introspection requests) |
| Per-schema circuit work | None (same circuit, different predicateHash) | Per-schema message index mapping | Per-schema AS configuration |
