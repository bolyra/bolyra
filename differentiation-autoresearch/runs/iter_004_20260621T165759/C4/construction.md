# Construction

## 1. Statement of claim

An AI agent proves that a predicate `φ` over its credential attributes evaluates to `true`, that the credential was signed by *some* issuer whose public key belongs to a published issuer registry (a Merkle tree of issuer keys), and that the credential has not been revoked — all without the verifier learning *which* issuer signed the credential, which specific attribute values the credential contains (beyond what `φ` implies), or which leaf in the issuer tree was used. The proof is constant-size (a single PLONK proof ≈ 768 bytes) regardless of the number of issuers in the registry or the complexity of the predicate, and the construction is formally secure under an IND-ISS game defined below.

## 2. Construction (gadgets, circuits, public/private inputs)

### Overview

A new circuit **IssuerBlindPredicate** is introduced alongside the existing AgentPolicy circuit. It operates in the PLONK proving system (agent-side, universal setup, no per-circuit ceremony). The construction has three layers:

1. **Issuer-anonymous credential verification** — EdDSA signature check + Merkle membership in an issuer registry tree, all on private inputs.
2. **Predicate evaluation** — a compiled Boolean expression over credential attribute fields, evaluated inside the circuit against private attribute values.
3. **Revocation non-membership** — Merkle non-membership proof against a sparse Merkle tree of revoked credential identifiers, checked against a *stable* credential identifier that never appears as a public output.

### Dual-commitment architecture

The prior construction used a single `credentialCommitment` that served both as the revocation-tree leaf and as the per-proof public output, blinded by a fresh `credentialSalt`. This creates a contradiction: the revocation tree requires a stable, deterministic identifier so the issuer can revoke a credential by inserting a known value, while unlinkability requires a fresh, randomized commitment per proof so the verifier cannot correlate proofs across sessions. This revision splits the two roles:

- **`credentialId`** (stable, deterministic, private): computed as `Poseidon3(credentialDigest, issuerPubkeyAx, issuerPubkeyAy)`. This is the value the issuer knows and inserts into the revocation tree to revoke a credential. It never appears as a public output — the circuit checks revocation non-membership against it internally.

- **`blindedCredCommitment`** (per-proof, randomized, public output): computed as `Poseidon2(credentialId, proofSalt)` where `proofSalt` is fresh uniform randomness per proof. This is the only credential-linked value the verifier sees. Two proofs from the same credential produce unrelated `blindedCredCommitment` values.

The circuit proves the link between these two values internally: it computes `credentialId` from private inputs, checks revocation against `credentialId`, then blinds it to produce `blindedCredCommitment` as a public output. The verifier is cryptographically assured that revocation was checked against the real credential without ever seeing the stable identifier.

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
| `proofSalt` | Field | Fresh per-proof randomness for blinding |
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
| `blindedCredCommitment` | Field | Poseidon2(credentialId, proofSalt) — per-proof randomized commitment |
| `blindNullifier` | Field | Poseidon2(credentialId, sessionNonce) — replay prevention |

### Gadgets

**Gadget 1: Credential Digest & Stable Identifier**

```
credentialDigest = PoseidonN(attrValues[0], ..., attrValues[MAX_ATTRS-1])
credentialId = Poseidon3(credentialDigest, issuerPubkeyAx, issuerPubkeyAy)
```

The `credentialId` is deterministic — same credential always produces the same identifier. This is the value the issuer computes at issuance and inserts into the revocation tree if the credential is later revoked. It is a private intermediate signal: the circuit uses it internally for revocation checking and then blinds it before producing any public output.

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

**Gadget 5: Revocation Non-Membership (against stable credentialId)**

```
SparseMerkleNonMembership(REV_DEPTH, credentialId, revocationMerkleProof, revocationProofHelper)
computedRevRoot === revocationRoot  // public input
```

This proves the credential has not been revoked. The revocation tree is keyed by `credentialId` — the stable, deterministic identifier that the issuer can compute from the credential fields and their own key. When an issuer revokes a credential, they insert `credentialId = Poseidon3(credentialDigest, Ax, Ay)` into the sparse Merkle tree. The prover must then demonstrate non-membership of this value to generate a valid proof.

Crucially, `credentialId` is a *private intermediate signal* — it is computed inside the circuit from private inputs and consumed by the non-membership gadget, but never emitted as a public output. The verifier sees only `revocationRoot` (the tree root) and the PLONK proof that non-membership holds. The verifier cannot determine which `credentialId` was checked, preserving issuer anonymity even during revocation verification.

**Gadget 6: Blinded Commitment (per-proof unlinkability)**

```
blindedCredCommitment = Poseidon2(credentialId, proofSalt)
```

The `proofSalt` is fresh uniform randomness generated by the prover for each proof. This ensures that two proofs from the same credential produce unrelated public commitments, defeating cross-session correlation by any observer (verifier, relay, on-chain indexer).

**Gadget 7: Blind Nullifier**

```
blindNullifier = Poseidon2(credentialId, sessionNonce)
```

Prevents replay within a session. The nullifier is deterministic per credential per session nonce: the same credential used with the same session nonce always produces the same nullifier, so the on-chain registry can reject duplicates. However, across sessions (different nonces), nullifiers from the same credential are unlinkable under the Poseidon PRF assumption.

Note that `blindNullifier` depends on `credentialId` (stable) rather than `blindedCredCommitment` (randomized). This is intentional: replay prevention requires that the same credential maps to the same nullifier within a session, which is impossible if the nullifier input is randomized per proof. The adversary controls `sessionNonce` (it is a public input chosen by the verifier), but under the Poseidon PRF assumption, observing `Poseidon2(credentialId, nonce_1)` and `Poseidon2(credentialId, nonce_2)` for adversarially chosen nonces does not reveal `credentialId` or allow linking the two values. This is formally: for any PPT adversary with oracle access to `f(·) = Poseidon2(credentialId, ·)`, distinguishing `f` from a random function has negligible advantage under Poseidon PRF security.

### Predicate Compilation (off-chain)

A predicate compiler takes a schema-annotated Boolean expression and produces:

1. A clause vector `[(attrIndex, comparator, threshold), ...]` (max 8 clauses)
2. A Boolean combination tree (max 3 levels of AND/OR/NOT)
3. The `predicateHash` for public verification

This compiler is a pure function — no trusted setup, no per-schema circuit. The same IssuerBlindPredicate circuit handles all schemas.

### Revocation workflow (issuer-side)

The dual-commitment architecture requires the following issuer-side workflow for revocation:

1. **At issuance:** The issuer computes `credentialId = Poseidon3(credentialDigest, Ax, Ay)` from the same values used to produce the signed credential. The issuer stores `credentialId` alongside the credential record in their local database.

2. **At revocation:** The issuer submits `credentialId` to the revocation tree operator (which may be the on-chain registry or a separate service). The operator inserts `credentialId` as a leaf in the sparse Merkle tree and publishes the updated `revocationRoot`.

3. **Privacy property:** The revocation tree contains `credentialId` values, which are Poseidon hashes binding attributes to an issuer key. An observer of the revocation tree can enumerate revoked `credentialId` values but cannot determine which issuer revoked which credential unless they independently know the issuer's key and the credential's attributes (enabling them to recompute the hash). In the typical case — where the observer is the verifier or an intermediary who does not possess the credential's plaintext attributes — the revocation tree reveals only the count of revoked credentials, not their provenance.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model: two classes

The construction must resist two distinct adversary classes, reflecting the two parties that see protocol messages in any credential-verification deployment:

**Class 1 — Malicious Verifier (Resource Server analogue).** This is the party that receives and checks the proof. In OAuth/RFC 7662 terms, this is the Resource Server (RS). The RS adversary `A_RS` is PPT and:

- Sees all public inputs and outputs of the proof (issuerRegistryRoot, predicateHash, revocationRoot, sessionNonce, predicateResult, blindedCredCommitment, blindNullifier)
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

**Class 3 — Revocation-tree observer.** A new sub-class relevant to the dual-commitment architecture. The revocation-tree observer `A_REV` sees the contents of the sparse Merkle revocation tree — i.e., the set of revoked `credentialId` values. `A_REV` may be the revocation tree operator itself, an on-chain indexer, or any party that reads the tree's leaves. `A_REV` is PPT and:

- Knows all revoked `credentialId` values
- Knows the full issuer registry (all issuer public keys)
- Does NOT know the credential attribute values (the `credentialDigest` input to `credentialId`)

`A_REV` wins by linking a revoked `credentialId` to a specific issuer. Since `credentialId = Poseidon3(credentialDigest, Ax, Ay)`, this requires inverting Poseidon3 given the output and candidate `(Ax, Ay)` pairs but without `credentialDigest`. Under Poseidon preimage resistance, this is infeasible: for each candidate issuer key, `A_REV` must find `credentialDigest` such that `Poseidon3(credentialDigest, Ax, Ay)` matches the revoked value, which is a preimage search over the full field `F_p`. Even with knowledge of all issuer keys in the registry, `A_REV` cannot test whether a given `credentialId` was produced by a specific issuer without knowing the credential's attributes.

**Caveat (low-entropy attribute defense):** If the attribute space is small (e.g., a credential with only a single Boolean attribute), `A_REV` who knows all issuer keys could enumerate `credentialDigest = Poseidon1(0)` and `Poseidon1(1)`, compute `Poseidon3(d, Ax, Ay)` for all issuers, and match against the revocation tree. This is a brute-force attack over `|attributes| × |issuers|` candidates. The attack is mitigated by the `credentialId` construction itself: the `credentialDigest` is a Poseidon hash over all 16 attribute slots (including padding), so even a single-attribute credential has `credentialDigest = Poseidon16(attr_0, 0, 0, ..., 0)` — but this alone may not provide sufficient entropy if the attribute domain is small. For deployments where credential attribute spaces are small and issuer-anonymity of revoked credentials is required, issuers SHOULD include a per-credential secret nonce as one of the attribute slots (e.g., `attrValues[15] = random_nonce`). This nonce is part of the signed credential, contributes to `credentialDigest`, and makes `credentialId` preimage-resistant even against an adversary who knows the schema and all non-nonce attribute values. This is an application-layer mitigation, not a circuit change — the circuit already hashes all 16 attribute slots.

### Two hiding properties

**Property 1: RS-blind issuer hiding (verifier-facing).** The verifier (RS) cannot determine which issuer signed a credential from a single proof. This is the property captured by the IND-ISS game below. RFC 7662 filtered introspection can *simulate* this property at the RS level by having the AS strip `iss` / `client_id` from the introspection response (RFC 7662 §2.2 permits the AS to omit fields). However, this is a policy decision by the AS, not a cryptographic guarantee — the AS can choose to include or leak the issuer at any time, and the RS must trust the AS to filter correctly.

**Property 2: AS-blind issuer hiding (intermediary-facing).** No intermediary in the protocol — relay, proof aggregator, registry operator, or on-chain indexer — can determine which issuer signed a credential, even across multiple sessions. This is the property that RFC 7662 *cannot* provide: the AS is the party that issued or validated the token and therefore *inherently knows* the issuer identity. Filtered introspection hides the issuer from the RS by relying on the AS as a trusted filter; it does not and cannot hide the issuer from the AS itself. In the IssuerBlindPredicate construction, there is no AS-equivalent party. The proof is self-contained: the prover generates it locally, the verifier checks it on-chain, and no intermediary ever handles the raw credential or issuer key. The issuer identity is a private circuit input that never appears in any protocol message, on-chain calldata, or emitted event.

**Property 3: Revocation-tree issuer hiding.** The revocation tree does not reveal which issuer revoked which credential, under Poseidon preimage resistance and the low-entropy caveat above.

**AS-blind issuer hiding is the strictly novel property.** RS-blind hiding is achievable (with trust assumptions) via filtered introspection or a privacy-proxy architecture. AS-blind hiding is achievable only when no party in the protocol possesses the issuer identity in cleartext — which requires the credential verification itself to occur inside a zero-knowledge proof.

### IND-ISS Game Definition (covering both adversary classes)

**Game IND-ISS(λ, A)** — parameterized by adversary `A` instantiated as either `A_RS` or `A_AS`:

1. **Setup.** Challenger generates PLONK CRS. Challenger enrolls `n ≥ 2` issuers with keys `{(Ax_j, Ay_j)}_{j=1}^{n}` in the issuer registry tree, producing `issuerRegistryRoot`.

2. **Phase 1 (adaptive queries).** Adversary `A` makes adaptive queries: for any issuer index `j`, predicate `φ`, and attribute vector `attrs` satisfying `φ(attrs) = true`, the challenger returns a valid IssuerBlindPredicate proof along with all public signals. When `A = A_AS`, the adversary additionally receives the session nonce, on-chain transaction calldata, and timing metadata for each query (modeling the intermediary's aggregated view). `A` may make polynomially many such queries.

3. **Challenge.** `A` selects two issuer indices `j_0, j_1` and an attribute vector `attrs*` such that `φ(attrs*) = true` under both issuers' signatures. Challenger flips coin `b ←$ {0,1}`, produces a proof using issuer `j_b`'s signature over `attrs*` with a fresh `proofSalt`.

4. **Phase 2 (post-challenge queries).** `A` makes more adaptive queries (excluding the challenge issuers with `attrs*` under the challenge predicate).

5. **Guess.** `A` outputs `b'`. `A` wins if `b' = b`.

**Definition.** The IssuerBlindPredicate construction is **(t, ε)-IND-ISS secure** if for all PPT adversaries `A` (in either class) running in time `t`:

```
|Pr[b' = b] - 1/2| ≤ ε(λ)
```

**Note on the AS adversary's extra view.** The `A_AS` adversary's additional observations (timing, calldata, cross-session correlation) do not help because:

- **Calldata** contains only the public signals and the PLONK proof `π` — exactly what `A_RS` sees. The on-chain transaction adds no issuer-correlated side channel beyond the public signals already analyzed in the game.
- **Timing** is outside the algebraic model. The proof generation time is dominated by the PLONK prover's FFT and MSM operations over the full constraint system; it does not vary measurably with the issuer's position in the Merkle tree (the tree traversal is < 0.1% of proving time for 16-level trees). Implementations SHOULD add constant-time padding to proof generation to foreclose microarchitectural timing channels, but this is an implementation-level concern, not a protocol-level one.
- **Cross-session correlation** via `blindedCredCommitment` is defeated by the fresh `proofSalt` per proof. Two proofs from the same credential produce distinct `blindedCredCommitment` values. Cross-session correlation via `blindNullifier` is defeated by the unique `sessionNonce` per session: `blindNullifier = Poseidon2(credentialId, sessionNonce)` produces unlinkable values across sessions under the Poseidon PRF assumption.

### Issuer-set anonymity bound

The anonymity set is exactly the set of issuer leaves in the registry tree. An adversary's advantage in IND-ISS (under either adversary class) is bounded by their advantage in breaking zero-knowledge of the PLONK proof system plus their advantage in breaking Poseidon's PRF property (to distinguish blinded commitments or nullifiers from random):

```
Adv^{IND-ISS}(A) ≤ Adv^{ZK}_{PLONK}(A) + Adv^{PRF}_{Poseidon}(A)
```

This bound holds identically for `A_RS` and `A_AS` because their algebraic views are identical — the AS adversary's extra metadata does not contribute algebraic distinguishing advantage.

## 4. Security argument (named assumption + reduction sketch)

**Named assumptions:**

1. **Knowledge soundness of PLONK** (in the algebraic group model + random oracle model): A valid PLONK proof implies the prover knows a witness satisfying all circuit constraints.
2. **Collision resistance of Poseidon** over BN254 scalar field: No PPT adversary can find `(x, x')` with `x ≠ x'` and `Poseidon(x) = Poseidon(x')` with non-negligible probability.
3. **Preimage resistance of Poseidon** over BN254 scalar field: Given `y = Poseidon(x)`, no PPT adversary can find `x` with non-negligible probability. (Used specifically for revocation-tree issuer hiding.)
4. **PRF security of Poseidon** (keyed by the first argument): For a uniform random key `k ∈ F_p`, the function `x ↦ Poseidon2(k, x)` is computationally indistinguishable from a random function. (This is a standard consequence of CR + preimage resistance in the ideal permutation model for Poseidon.)
5. **Discrete logarithm hardness on Baby Jubjub**: Given `(Ax, Ay) = s·G`, no PPT adversary can recover `s`.
6. **Zero-knowledge property of PLONK** (simulation extractability): The proof reveals nothing about the witness beyond the public outputs.

**Reduction sketch for IND-ISS (covering both A_RS and A_AS):**

*Claim:* If PLONK is zero-knowledge and Poseidon is a PRF (keyed by credentialId), then IssuerBlindPredicate is IND-ISS secure against both adversary classes.

*Proof sketch:*

Suppose adversary `A` (instantiated as either `A_RS` or `A_AS`) wins IND-ISS with advantage `ε`. We show `ε` is negligible via a hybrid argument over the two issuer-dependent public outputs:

**Hybrid 0:** Real game with `b = 0` (issuer `j_0`).

**Hybrid 1:** Replace `blindedCredCommitment` in the challenge proof with a uniformly random field element `r_1 ←$ F_p`.

The distinguishing advantage between Hybrid 0 and Hybrid 1 is bounded by `Adv^{PRF}_{Poseidon}(A)`. In Hybrid 0, `blindedCredCommitment = Poseidon2(credentialId_0, proofSalt)` where `proofSalt` is uniform and independent. By the PRF assumption on `Poseidon2` keyed by `credentialId_0`, this output is indistinguishable from random to any PPT adversary who does not know `credentialId_0`. The adversary does not know `credentialId_0` because it is a private circuit input, and the PLONK proof is zero-knowledge.

**Hybrid 2:** Additionally replace `blindNullifier` in the challenge proof with a uniformly random field element `r_2 ←$ F_p`.

The distinguishing advantage between Hybrid 1 and Hybrid 2 is bounded by `Adv^{PRF}_{Poseidon}(A)`. In Hybrid 1, `blindNullifier = Poseidon2(credentialId_0, sessionNonce)` where `sessionNonce` is chosen by the adversary — but `credentialId_0` is unknown to the adversary and serves as the PRF key. By the PRF assumption, the output is indistinguishable from random even for adversarially chosen inputs, as long as the key is hidden.

**Hybrid 3:** In Hybrid 2, both issuer-dependent public outputs have been replaced with random values. Now switch from issuer `j_0` to issuer `j_1` inside the PLONK proof witness.

The distinguishing advantage between Hybrid 2 and Hybrid 3 is bounded by `Adv^{ZK}_{PLONK}(A)`. Since both issuer-dependent public outputs are now random (independent of the issuer), the only remaining issuer-dependent information is inside the PLONK proof `π` itself. By the zero-knowledge property of PLONK, `π` reveals nothing about the witness beyond the public signals, so switching the issuer in the witness is undetectable.

**Hybrid 4:** Reverse the substitutions — replace the random values with the real `blindedCredCommitment` and `blindNullifier` computed from issuer `j_1`'s `credentialId_1`.

By the same PRF arguments (now applied to `credentialId_1`), the distinguishing advantage is bounded by `2 · Adv^{PRF}_{Poseidon}(A)`.

**Hybrid 4 is the real game with `b = 1`.** Therefore:

```
ε = |Pr[A wins | b=0] - Pr[A wins | b=1]|
  ≤ Adv^{ZK}_{PLONK}(A) + 4 · Adv^{PRF}_{Poseidon}(A)
```

For `A_AS`, the extra observations (calldata, timing, cross-session data) do not affect the hybrid argument:
- Calldata is a deterministic encoding of `(π, publicSignals)` — already covered.
- Cross-session proofs use independent `proofSalt` values, so each `blindedCredCommitment` is independently randomized. Cross-session `blindNullifier` values use different `sessionNonce` values; under the PRF assumption, outputs at distinct inputs are jointly indistinguishable from independent random values.

**Soundness argument:** By PLONK knowledge soundness, a valid proof implies the prover knows:
- An issuer key `(Ax, Ay)` that is a leaf in the registry (Gadget 3)
- A valid EdDSA signature over the credential digest under that key (Gadget 2)
- Attribute values satisfying the predicate (Gadget 4)
- A non-membership witness proving `credentialId` is absent from the revocation tree (Gadget 5)
- A `credentialId` that is correctly derived from the credential digest and issuer key (Gadget 1)

Forging any of these requires breaking EdDSA unforgeability (DL on Baby Jubjub), Poseidon collision resistance (for Merkle forgery), or PLONK knowledge soundness.

**Revocation-tree issuer hiding argument:** An observer of the revocation tree sees `credentialId` values. To link a revoked `credentialId` to issuer `j`, the observer must find `credentialDigest` such that `Poseidon3(credentialDigest, Ax_j, Ay_j) = credentialId`. This is a preimage search with the issuer key partially known. Under Poseidon preimage resistance, this is infeasible when `credentialDigest` has sufficient min-entropy (ensured by the per-credential nonce recommendation in the low-entropy caveat above).

## 5. Bolyra primitive mapping

| Construction component | Bolyra primitive | Spec reference |
|---|---|---|
| Credential digest hash | Poseidon (multi-input, BN128 scalar field) | §2 Cryptographic Primitives |
| Stable credential identifier | Poseidon3 (new arity, same primitive as existing PoseidonN family) | §2 Cryptographic Primitives |
| Blinded credential commitment | Poseidon2 (same as nullifier construction pattern) | §4.2 Credential Commitment |
| Issuer signature verification | EdDSAPoseidonVerifier on Baby Jubjub (a=168700, d=168696) | §2 Signature Scheme |
| Issuer registry tree | Lean Incremental Merkle Tree with Poseidon2 node hash, depth 16 | §2 Merkle Tree (depth adapted) |
| Blind nullifier | Poseidon2(credentialId, sessionNonce) — identical form to agent nullifier | §3.2 Agent Proof, nullifier definition |
| Session binding | sessionNonce public input, checked on-chain | §3.1 Protocol Flow, step 5b |
| Proving system | PLONK with universal setup (pot16.ptau) — permitted for agent-side circuits | §2.3 Proving Systems |
| Revocation tree | Sparse Merkle Tree with Poseidon2, depth 20 — extends existing tree infrastructure | §2 Merkle Tree |
| Scope commitment for delegation chain entry | `Poseidon2(predicateHash, blindedCredCommitment)` — analogous to existing scope commitment | §4.2 Scope Commitment |

No new cryptographic primitives are introduced. Every component maps to an existing Bolyra building block.

## 6. Circuit cost estimate

### Constraint breakdown

| Gadget | Constraints | Notes |
|---|---|---|
| Poseidon hash (credential digest, 16 inputs) | ~4,800 | ~300 constraints per Poseidon round, ~16 rounds for multi-input |
| Poseidon3 (stable credentialId) | ~900 | 3-input Poseidon |
| Poseidon2 (blinded credential commitment) | ~600 | 2-input Poseidon |
| EdDSA Poseidon Verifier | ~14,000 | Standard Baby Jubjub scalar mul + Poseidon-based EdDSA |
| Poseidon2 (issuer leaf hash) | ~600 | 2-input Poseidon |
| Binary Merkle Root (depth 16, issuer tree) | ~9,600 | 16 × Poseidon2 (~600 each) |
| Predicate evaluation (8 clauses × comparator) | ~4,000 | 8 × LessThan(64) + equality checks + Boolean tree |
| Range checks (Num2Bits) | ~1,500 | Various 64-bit decompositions |
| Sparse Merkle non-membership (depth 20) | ~12,000 | 20 × Poseidon2 + ordering constraint |
| Poseidon2 (blind nullifier) | ~600 | 2-input |
| **Total** | **~49,200** | Well within 2^16 = 65,536 constraint budget |

### Proving time targets

| Metric | Target | Rationale |
|---|---|---|
| PLONK proving time (agent) | < 4 seconds | Agent-side, PLONK universal setup, ~49K constraints. PLONK at 2^16 on snarkjs: ~3-5s on modern hardware; rapidsnark: ~0.8s |
| PLONK verification time (on-chain) | < 300K gas | Single pairing check, constant regardless of issuer set size |
| Proof size | 768 bytes | Standard PLONK proof (3 group elements + field elements) |

The circuit fits within the existing `pot16.ptau` (2^16 constraints) universal SRS. No new ceremony is required. The additional Poseidon3 gadget (~900 constraints) over the prior construction is well within margin.

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
     credential_nonce,      // attr[15] = random (hidden, ensures credentialId entropy)
   ]
   ```
   PenFed's compliance key `(Ax_penfed, Ay_penfed)` signs `credentialDigest = PoseidonN(attrValues)`.

3. PenFed's key is enrolled as a leaf in the NCUA issuer registry tree.

4. PenFed's compliance system stores `credentialId = Poseidon3(credentialDigest, Ax_penfed, Ay_penfed)` for future revocation capability.

**Proof generation:**
- PenFed's agent generates an IssuerBlindPredicate proof with:
  - Predicate: `chartered_by_NCUA == 1` (predicateHash published)
  - All attribute values private (including `credential_nonce` in slot 15)
  - Issuer key private
  - Revocation non-membership checked against `credentialId` (private intermediate signal)
  - Fresh `proofSalt` ensures unlinkability of `blindedCredCommitment` across sessions
  - `blindNullifier = Poseidon2(credentialId, sessionNonce)` ensures replay prevention within the session while remaining unlinkable across sessions

**Verification (by partner CU or DeFi lending pool):**
- Verifier checks:
  1. `issuerRegistryRoot` matches the on-chain NCUA registry root
  2. `predicateHash` matches the agreed "NCUA membership" predicate
  3. `predicateResult == 1`
  4. `revocationRoot` is current
  5. PLONK proof verifies
  6. `blindNullifier` is fresh (not replayed in this session)

**What the verifier learns:** An NCUA-chartered credit union's agent holds a valid, unrevoked credential satisfying the NCUA membership predicate. **Nothing else** — not which credit union, not the charter number, not the asset tier, not the jurisdiction.

**Revocation flow:** If PenFed's credential is later compromised, PenFed's compliance officer submits `credentialId` to the revocation tree. Subsequent proofs by the compromised credential fail the non-membership check (Gadget 5). The revocation tree observer sees a new `credentialId` leaf but cannot link it to PenFed without knowing PenFed's attribute values (including the random `credential_nonce`).

**What BBS+ would leak:** The issuer public key (identifying PenFed), the status list URL (identifying PenFed's revocation endpoint), and the schema-specific claim indices.

**What RFC 7662 filtered introspection would leak to the AS:** Even if the AS strips `iss` and `client_id` from the introspection response to the RS (achieving RS-blind hiding), the AS itself — typically operated by the NCUA or a CUSO (Credit Union Service Organization) — knows exactly which credit union's token is being introspected. In regulated environments where the NCUA is simultaneously the registry operator and the supervisory authority, this creates an information asymmetry: the NCUA learns real-time transaction patterns of individual credit unions. The IssuerBlindPredicate construction eliminates this asymmetry entirely — the on-chain registry stores only the Merkle root, and no party (including the registry operator) ever sees which leaf was used.

### Extension: Cross-Country KYB with Hidden Jurisdiction

The same circuit handles the KYB scenario by changing only the predicate and issuer registry:
- Issuer registry: KYB-authorized signers across US, EU, UK, Singapore
- Predicate: `kyb_verified == 1 AND incorporation_year < 2025`
- Jurisdiction is an attribute that stays hidden; the issuer key (which would encode jurisdiction) is also hidden
- The intermediary routing KYB verification requests (analogous to a cross-border AS) learns nothing about the originating jurisdiction
- Revocation of a KYB credential inserts the `credentialId` into the shared revocation tree without revealing the jurisdiction of the revoked entity

No new circuit deployment is needed — only a new `predicateHash` and `issuerRegistryRoot`.

## 8. Why the baseline cannot match

### Gap 1: Issuer anonymity is structurally impossible in BBS+

BBS+ derived proofs are verified against a *specific, named* issuer public key. The `VerifyProof` algorithm (draft-irtf-cfrg-bbs-signatures §3.5.2) takes the issuer's public key as an explicit input. There is no mechanism to verify against "some key in a set" without iterating over the set (O(|S|) verification) or introducing a fundamentally different proof system. The IssuerBlindPredicate circuit verifies the issuer's EdDSA signature *inside* the ZK circuit with the key as a private input, then proves Merkle membership — a construction BBS+ cannot replicate without becoming a ZK circuit itself.

### Gap 2: Constant-size proof is impossible for issuer-set hiding in BBS+

Even with a hypothetical ring-signature extension over BBS+, proof size grows as O(|S|) for Pedersen-style ring constructions or O(log|S|) for tree-based ring signatures. The IssuerBlindPredicate proof is exactly 768 bytes regardless of whether the issuer registry contains 10 or 100,000 issuers, because the Merkle membership proof is verified *inside* the PLONK circuit and compressed into the constant-size PLONK proof.

### Gap 3: Arbitrary predicate compilation requires a circuit, not a signature scheme

BBS+ is a multi-message signature with selective disclosure — it can reveal or hide individual messages, and with extensions, prove simple range predicates. It cannot evaluate arbitrary Boolean expressions like `(chartered_by_NCUA == 1) AND (enforcement_actions == 0) AND (total_assets_tier >= 3)` in a single atomic proof. Each new predicate type requires a separate composition layer (Bulletproofs for ranges, equality proofs for comparisons) with distinct setup and proof-size overhead. The IssuerBlindPredicate circuit compiles any Boolean expression over up to 8 clauses into the same circuit, distinguished only by the `predicateHash` public input.

### Gap 4: Revocation breaks issuer anonymity in BBS+

W3C StatusList2021 and Bitstring Status List require the holder to reference a status list URL controlled by the issuer. Consulting this URL reveals the issuer's identity to the verifier (or to any network observer). The IssuerBlindPredicate circuit proves non-revocation via a sparse Merkle non-membership proof against a *unified* revocation tree (all issuers share one tree), keyed by `credentialId` — a stable but issuer-hiding identifier. No issuer-specific endpoint is ever contacted, and the revocation tree itself does not reveal issuer provenance (under Poseidon preimage resistance with the per-credential nonce).

### Gap 5: No formal IND-ISS security exists for BBS+

The BBS+ security proofs (draft-irtf-cfrg-bbs-signatures §7) cover EUF-CMA unforgeability and zero-knowledge of derived proofs relative to a fixed issuer key. They do not define, model, or prove security against issuer indistinguishability. The IND-ISS game defined in §3 above is provably satisfied by the IssuerBlindPredicate construction under PLONK zero-knowledge and Poseidon PRF security — assumptions already present in Bolyra's security model. BBS+ would need to be redesigned from scratch to achieve this property.

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
| Revocation without issuer leak | Yes (unified tree, stable credentialId, Poseidon preimage resistance) | No (status list URL leaks issuer) | No (AS revocation lookup identifies issuer) |
| Revocation-unlinkability (same credential, multiple proofs) | Yes (revocation checked against private credentialId; public outputs use fresh proofSalt) | No (status list index is stable and visible) | No (token identifier is stable) |
| Proof size vs. issuer set | O(1) — 768 bytes always | O(|S|) or O(log|S|) with extensions | N/A (no proof, token-based) |
| Arbitrary Boolean predicates | Yes (8-clause template, single circuit) | No (per-predicate composition layer) | No (AS returns fixed claim fields) |
| IND-ISS formal security (both A_RS and A_AS) | Yes (proven under PLONK ZK + Poseidon PRF) | Undefined and unproven | Undefined; AS is outside the hiding guarantee |
| Cross-session unlinkability for intermediary | Yes (fresh proofSalt per proof; PRF-secure nullifiers) | No (issuer key visible) | No (AS sees all introspection requests) |
| Per-schema circuit work | None (same circuit, different predicateHash) | Per-schema message index mapping | Per-schema AS configuration |
