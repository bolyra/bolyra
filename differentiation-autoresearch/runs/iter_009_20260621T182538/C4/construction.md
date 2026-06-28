# Construction

## 1. Statement of claim

Agent proves a predicate over credential attributes (e.g. `chartered_by_NCUA == true`) without the verifier learning which issuer signed, with constant-size proof and arbitrary-schema support.

## 2. Construction (gadgets, circuits, public/private inputs)

### Primary circuit: IssuerBlindPredicate (PLONK agent, ~53K constraints)

**Private inputs:**
- `issuerPubkeyAx`, `issuerPubkeyAy`: Issuer EdDSA public key (Baby Jubjub)
- `issuerSigR8x`, `issuerSigR8y`, `issuerSigS`: Issuer signature over attribute vector
- `attrValues[MAX_ATTRS]`: Credential attribute vector (up to 16 field elements)
- `expiryTimestamp`: Credential expiry
- `issuerMerkleProofIndex`, `issuerMerkleProofSiblings[ISSUER_DEPTH]`: Merkle path in issuer registry tree (depth 10, supporting up to 1024 issuers)
- `predicateInstructions[MAX_OPS]`: Compiled Boolean expression (op, operandA, operandB, result register) — up to 32 instructions

**Public inputs:**
- `issuerRegistryRoot`: Root of the issuer registry Merkle tree
- `predicateHash`: Poseidon hash of the instruction vector (commits to the predicate being evaluated)
- `currentTimestamp`: For expiry check
- `sessionNonce`: Session binding

**Public outputs:**
- `predicateResult`: 1 if predicate satisfied, 0 otherwise (constrained to equal 1)
- `credNullifier`: `Poseidon2(credCommitmentBlind, sessionNonce)` where `credCommitmentBlind = Poseidon2(attrHash, expiryTimestamp)` — issuer-free
- `issuerRegistryRoot` (echo): Enables verifier to check against on-chain registry

**Key design — issuer-blind commitment:**
```
attrHash = PoseidonN(attrValues[0..N-1])
credCommitmentBlind = Poseidon2(attrHash, expiryTimestamp)
```
The nullifier is derived from `credCommitmentBlind`, which excludes issuer identity. This ensures the nullifier cannot be correlated across presentations to de-anonymize the issuer.

**Predicate evaluation gadget:**
Instructions are `(opcode, src1, src2, dst)` tuples compiled from Boolean expressions. Supported opcodes: EQ (field equality), NEQ, AND, OR, NOT, LT (via LessThan(64)), IN_SET (membership in a committed set). The instruction vector is hashed to `predicateHash` so the verifier knows which predicate was evaluated without seeing the attribute values.

### Designated-Verifier Disclosure Circuit: IssuerReveal (PLONK agent, ~12K constraints)

This circuit provides a **regulatory escape hatch** — the prover can selectively reveal the issuer identity to a designated verifier (examiner) without breaking issuer-blindness for ordinary verifiers.

**Private inputs:**
- `issuerPubkeyAx`, `issuerPubkeyAy`: Same issuer key from the blind proof
- `attrValues[MAX_ATTRS]`: Same attribute vector
- `expiryTimestamp`: Same expiry
- `examinerPubkeyAx`, `examinerPubkeyAy`: Public key of the designated examiner (NCUA examiner, FINRA auditor, etc.)
- `examinerEncNonce`: Fresh randomness for ElGamal-style encryption

**Public inputs:**
- `credNullifier`: Links this disclosure to a prior IssuerBlindPredicate proof
- `examinerPubkeyHash`: `Poseidon2(examinerPubkeyAx, examinerPubkeyAy)` — identifies the designated examiner
- `encIssuerC1x`, `encIssuerC1y`, `encIssuerC2x`, `encIssuerC2y`: ElGamal ciphertext of `(issuerPubkeyAx, issuerPubkeyAy)` under the examiner's key

**Public outputs:**
- `credNullifierCheck`: Must equal `credNullifier` public input (binding to the prior proof)
- `disclosureTag`: `Poseidon3(credNullifier, examinerPubkeyHash, encIssuerC1x)` — unique per disclosure event

**Circuit constraints:**
1. **Nullifier binding**: Recompute `credCommitmentBlind = Poseidon2(PoseidonN(attrValues), expiryTimestamp)`, then verify `credNullifierCheck = Poseidon2(credCommitmentBlind, sessionNonce)` equals the provided `credNullifier`. This proves the disclosure pertains to the same credential as the blind proof.
2. **ElGamal correctness**: The ciphertext `(C1, C2)` is a valid Baby Jubjub ElGamal encryption of `(issuerPubkeyAx, issuerPubkeyAy)` under the examiner's public key with nonce `examinerEncNonce`:
   - `C1 = examinerEncNonce * G`
   - `C2 = (issuerPubkeyAx, issuerPubkeyAy) + examinerEncNonce * examinerPubkey`
3. **Examiner designation**: `Poseidon2(examinerPubkeyAx, examinerPubkeyAy) == examinerPubkeyHash`

**Operational model:** The IssuerReveal proof is generated **only** when the prover elects to cooperate with a regulatory examination. It is never required for ordinary verification. The examiner decrypts `(encIssuerC1, encIssuerC2)` with their private key to recover the issuer's public key, then looks it up in the issuer registry for attribution.

## 3. Threat model (adversary capabilities, game definition)

### Game 1: IND-ISS (Issuer Indistinguishability) — unchanged

**Setup:** Challenger maintains an issuer registry tree with N issuers. Adversary A receives the registry root and all issuer public keys.

**Challenge phase:**
1. A chooses two issuers `(iss_0, iss_1)` from the registry, an attribute vector `attrs` satisfying some predicate P, and a session nonce.
2. Challenger flips coin `b ← {0,1}`, issues a credential under `iss_b`, generates an IssuerBlindPredicate proof π.
3. A receives π and all public signals.
4. A outputs guess `b'`.

**Advantage:** `Adv_IND-ISS(A) = |Pr[b' = b] - 1/2|`

**Claim:** For any PPT adversary A, `Adv_IND-ISS(A) ≤ Adv_ZK(B)` where B is an adversary against the zero-knowledge property of the proving system.

### Game 2: DV-SOUND (Designated-Verifier Soundness)

**Setup:** Challenger maintains an issuer registry tree. Adversary A receives the registry root, all issuer public keys, and a designated examiner public key `pk_E`.

**Challenge phase:**
1. A produces an IssuerReveal proof π_dv with public signals including `credNullifier`, `examinerPubkeyHash`, and ciphertext `(C1, C2)`.
2. Challenger decrypts `(C1, C2)` using `sk_E` to recover a claimed issuer key `pk_iss*`.
3. Challenger verifies that `pk_iss*` is in the issuer registry AND that the credential with nullifier `credNullifier` was actually signed by `pk_iss*`.

**Win condition:** A wins if the proof verifies but either (a) `pk_iss*` is not in the registry, or (b) the original credential was signed by a different issuer.

**Claim:** For any PPT adversary A, `Adv_DV-SOUND(A) ≤ Adv_KS(B) + Adv_DL(C)` where B attacks knowledge soundness of PLONK and C attacks discrete log on Baby Jubjub.

### Game 3: DV-PRIV (Designated-Verifier Privacy)

**Setup:** Same as IND-ISS, but adversary also sees IssuerReveal proofs directed to examiner key `pk_E` (whose secret key A does NOT hold).

**Claim:** Without `sk_E`, the ElGamal ciphertext is semantically secure under DDH on Baby Jubjub. The IssuerReveal proof reveals nothing about the issuer to anyone other than the designated examiner.

### Regulatory compliance model

The escape hatch is **prover-initiated, not verifier-extractable**:

- **12 CFR Part 748** (NCUA Records Preservation): Credit unions must maintain records sufficient for examination. The IssuerReveal circuit satisfies this because the CU (prover) can generate the disclosure proof on demand during an NCUA examination. The CU retains its credential material (private inputs) as part of its records under §748.1(b). The examiner receives a ZK proof that the disclosed issuer is the true signer — not merely an assertion.

- **FINRA Rule 4511** (Books and Records): Broker-dealers must produce records upon regulatory request. An agent operating under a FINRA-licensed credential generates IssuerReveal when FINRA requests identification of the licensing firm. The `disclosureTag` provides an audit trail entry (unique, non-replayable, linked to the original blind proof via `credNullifier`).

- **FATF Recommendation 10** (Customer Due Diligence): Requires that institutions be able to identify their customers to competent authorities. The designated-verifier model satisfies R.10 because: (i) the institution knows its own issuer (it holds the credential), (ii) it can prove this to the authority via IssuerReveal, (iii) the authority can verify the proof cryptographically rather than relying on self-attestation.

**Critical invariant:** Ordinary verifiers never receive IssuerReveal proofs. The `examinerPubkeyHash` is a public input — if an ordinary verifier's key were substituted, the prover would see this and refuse to generate the proof. The prover controls disclosure.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

1. **Zero-Knowledge of PLONK** (simulation extractability under AGM + ROM)
2. **Knowledge Soundness of PLONK** (under AGM + ROM)
3. **Collision Resistance of Poseidon** over BN254 scalar field
4. **Discrete Log hardness on Baby Jubjub** (subgroup of order l ≈ 2^251)
5. **DDH on Baby Jubjub** (for ElGamal semantic security in IssuerReveal)

### Reduction sketch — IND-ISS

1. Suppose adversary A breaks IND-ISS with non-negligible advantage ε.
2. Construct simulator S that, given A's challenge issuers `(iss_0, iss_1)` and attributes, invokes the ZK simulator to produce a simulated proof π* (which is independent of the witness, hence independent of which issuer signed).
3. If A distinguishes π* from a real proof, A breaks the ZK property — contradiction.
4. Therefore A's advantage is bounded by `Adv_ZK(B)`.

**Key insight:** The issuer-blind nullifier (`credCommitmentBlind` excludes issuer key) ensures even the public signals carry no issuer information. Without this, the nullifier would differ between issuers for the same attributes, breaking the simulation.

### Reduction sketch — DV-SOUND

1. Suppose adversary A produces a verifying IssuerReveal proof that decrypts to a wrong issuer.
2. By knowledge soundness of PLONK, extract witness containing `issuerPubkeyAx, issuerPubkeyAy` and `examinerEncNonce`.
3. The circuit constrains ElGamal correctness: `C2 = (issuerPubkeyAx, issuerPubkeyAy) + examinerEncNonce * examinerPubkey`.
4. If decryption yields a different key, then either (a) the extracted witness doesn't match the public ciphertext (contradicting knowledge soundness), or (b) ElGamal decryption is incorrect (contradicting group law).
5. The nullifier binding constraint ensures the credential matches the prior blind proof — breaking this requires a Poseidon collision.

### Reduction sketch — DV-PRIV

1. The ciphertext `(C1, C2)` is standard ElGamal on Baby Jubjub.
2. Semantic security reduces to DDH: distinguish `(g^a, g^b, g^{ab})` from `(g^a, g^b, g^c)`.
3. Without `sk_E`, the adversary sees a DDH tuple and cannot recover the encrypted issuer key.
4. The ZK proof reveals nothing beyond what the public signals show (by ZK property), and public signals contain only the ciphertext (which is semantically secure) and hashes that don't encode issuer identity.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive |
|---|---|
| Issuer registry tree | Lean Incremental Merkle Tree, Poseidon2 node hash, depth 10 |
| Issuer credential signature | EdDSA on Baby Jubjub (same as operator signature in AgentPolicy) |
| Attribute hash | PoseidonN (N ≤ 16 attributes) |
| Credential commitment (blind) | Poseidon2(attrHash, expiryTimestamp) |
| Nullifier | Poseidon2(credCommitmentBlind, sessionNonce) — standard Bolyra agent nullifier pattern |
| Predicate hash | PoseidonN over instruction vector |
| Scope commitment | Poseidon2(permissionBitmask, credCommitmentBlind) — links to delegation chain |
| Proving system (IssuerBlindPredicate) | PLONK agent (universal setup, pot16.ptau) |
| Proving system (IssuerReveal) | PLONK agent (same SRS) |
| ElGamal encryption | Baby Jubjub point arithmetic (reuses BabyPbk scalar mul already in Circom stdlib) |
| Examiner key commitment | Poseidon2(Ax, Ay) — same pattern as identity commitment |
| On-chain registry | Extends existing BolyraRegistry with `examinerKeyRegistry` mapping and `DisclosureVerified` event |

## 6. Circuit cost estimate

### IssuerBlindPredicate (unchanged)

| Gadget | Constraints |
|---|---|
| EdDSA signature verification (Poseidon) | ~14,000 |
| Poseidon hashes (attrHash, credCommitment, nullifier, predicateHash) | ~4,800 |
| Merkle inclusion (depth 10, Poseidon2) | ~6,400 |
| Predicate evaluation (32 instruction slots) | ~22,000 |
| Range checks (expiry, timestamp) | ~1,200 |
| Scope satisfaction (64-bit mask) | ~640 |
| **Total** | **~53,000** |

**Proving time:** < 4.5s (PLONK, snarkjs WASM); < 0.8s (rapidsnark native)

### IssuerReveal (new — designated-verifier disclosure)

| Gadget | Constraints |
|---|---|
| PoseidonN (attribute hash recomputation, N=16) | ~2,400 |
| Poseidon2 (credCommitmentBlind, nullifier binding) | ~1,200 |
| Baby Jubjub scalar mul (ElGamal C1 = nonce * G) | ~3,200 |
| Baby Jubjub scalar mul (ElGamal shared = nonce * pk_E) | ~3,200 |
| Baby Jubjub point addition (C2 = issuerPK + shared) | ~200 |
| Poseidon2 (examiner key hash) | ~600 |
| Poseidon3 (disclosure tag) | ~900 |
| **Total** | **~11,700** |

**Proving time:** < 1.5s (PLONK, snarkjs WASM); < 0.3s (rapidsnark native)

**Combined workflow (blind proof + disclosure when required):** Still under the 5s PLONK agent budget even in the worst case of both proofs generated sequentially in WASM.

## 7. Concrete deployment scenario

### Scenario 1: Cross-CU NCUA Membership Proof (with examination compliance)

**Stakeholder:** Pentagon Federal Credit Union (PenFed) operating an AI agent that interacts with Navy Federal Credit Union's (NavyFed) lending API.

**Ordinary operation (issuer-blind):**
1. PenFed's agent holds a credential attesting `chartered_by_NCUA == true`, signed by PenFed's operator key, enrolled in the Bolyra agent Merkle tree.
2. The issuer registry tree contains public keys of all 4,500+ NCUA-chartered credit unions.
3. PenFed's agent generates an IssuerBlindPredicate proof: "I hold a valid credential signed by SOME key in the NCUA issuer registry with `chartered_by_NCUA == true`."
4. NavyFed verifies the proof. It learns the predicate holds but NOT that PenFed is the specific issuer. NavyFed cannot distinguish PenFed from any of the 4,500 other NCUA-chartered CUs.

**Regulatory examination (selective disclosure):**
5. NCUA Region III examiner initiates a routine safety-and-soundness examination of PenFed under 12 CFR §741.
6. Examiner presents their registered examiner public key (pre-enrolled in the on-chain `examinerKeyRegistry` by NCUA).
7. PenFed's compliance system generates an IssuerReveal proof linking the prior blind proof (via `credNullifier`) to a ciphertext encrypting PenFed's issuer key under the examiner's key.
8. Examiner decrypts, confirms PenFed is the issuer, verifies the ZK proof on-chain. The `disclosureTag` is logged as an immutable audit record satisfying 12 CFR §748.1(b) records requirements.
9. No other party (including NavyFed, other CUs, or the public) gains any information about which CU was disclosed — only the designated examiner can decrypt.

### Scenario 2: Cross-Country KYB with FATF R.10 Compliance

**Stakeholder:** A German fintech agent proving EU-KYB status to a Singapore MAS-regulated entity.

**Ordinary operation:** Agent proves `kyb_jurisdiction IN {EU member states}` without revealing whether it's German, French, or Estonian — issuer key (national registry authority) stays hidden within the EU issuer set.

**FATF compliance:** When Singapore MAS or BaFin requests identification under FATF R.10 mutual legal assistance, the German fintech generates IssuerReveal directed to the requesting FIU's designated-verifier key. The FIU learns the specific national jurisdiction; no other market participant does.

### Scenario 3: FINRA-Licensed Agent with Rule 4511 Audit Trail

**Stakeholder:** A robo-advisory agent at Schwab proving FINRA Series 65 licensing to a clearing firm.

**Ordinary operation:** Agent proves `finra_licensed == true AND series == 65` without revealing Schwab as the employing firm (issuer). The clearing firm verifies the predicate against the FINRA issuer registry root.

**FINRA Rule 4511 compliance:** Upon FINRA examination or arbitration discovery, Schwab generates IssuerReveal. The `disclosureTag` serves as the books-and-records entry linking the anonymous proof to Schwab's identity, satisfying the 6-year retention requirement under Rule 4511(c). The proof is cryptographically verifiable — FINRA need not trust Schwab's assertion.

## 8. Why the baseline cannot match

### BBS+ structural impossibilities (5 unchanged + 1 new)

1. **Issuer key visibility** — BBS+ verification requires the issuer's public key as a verification input. There is no mechanism to prove "signed by some key in set S" without revealing which key. Ring signatures over BBS+ keys have no published specification.

2. **Proof size scales with issuer set** — Even hypothetical ring-BBS+ constructions produce O(|S|) proofs. IssuerBlindPredicate is O(1) regardless of issuer registry size (Merkle path is constant-depth).

3. **No arbitrary predicate compilation** — BBS+ supports reveal/hide per message slot. Composing `(A == x) AND (B IN set) AND NOT (C > threshold)` requires separate proof system integrations per predicate type, with no unified constant-size output.

4. **No IND-ISS game definition** — draft-irtf-cfrg-bbs-signatures §7 proves unforgeability and zero-knowledge relative to a FIXED, KNOWN issuer key. Issuer-set anonymity is undefined and unproven in the BBS+ security model.

5. **Revocation leaks issuer** — StatusList2021 URLs encode issuer identity. Checking revocation breaks any issuer-hiding property that might be bolted on.

6. **No designated-verifier selective disclosure of issuer identity** — BBS+ has no mechanism for the holder to selectively reveal the issuer to a specific designated party while keeping it hidden from others. The issuer key is either visible (standard BBS+ verification) or hidden (hypothetical extension) — there is no per-verifier granularity. Regulatory compliance (12 CFR §748, FINRA Rule 4511, FATF R.10) requires exactly this: hide from counterparties, reveal to examiners. BBS+ cannot express this requirement within its algebraic framework because the issuer key is a verification parameter, not a witness that can be selectively encrypted to a designated recipient.

**Summary:** The Bolyra IssuerBlindPredicate + IssuerReveal construction provides the unique combination of (i) issuer anonymity for ordinary verifiers, (ii) formally proven IND-ISS security, (iii) designated-verifier disclosure for regulatory compliance, and (iv) constant-size proofs — a combination that is structurally impossible in BBS+ or any VC-DI profile.
