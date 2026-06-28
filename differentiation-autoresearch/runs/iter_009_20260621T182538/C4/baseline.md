# Baseline for C4 — Issuer-Blind Attribute Predicates

## Best Alternative: W3C VC Data Model 2.0 + BBS+ Signatures (with issuer-set hiding via accumulator extension)

The strongest non-ZK construction for C4 combines three specifications:

1. **W3C VC Data Model 2.0** ([https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)) — the envelope and trust-model layer.
2. **draft-irtf-cfrg-bbs-signatures** ([https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)) — multi-message signature scheme supporting selective disclosure with derived, unlinkable proofs.
3. **VC-DI BBS+ 2023** ([https://www.w3.org/TR/vc-di-bbs/](https://www.w3.org/TR/vc-di-bbs/)) — the proof suite binding BBS+ to W3C VCs.

No RFC 7662 / OAuth introspection variant can approach issuer-blind predicates at all — the AS that signs the introspection JWT is always visible to the relying party (see RFC 7662 §2, [https://datatracker.ietf.org/doc/html/rfc7662](https://datatracker.ietf.org/doc/html/rfc7662)). SPIFFE/WIMSE is similarly excluded: the SPIFFE ID encodes the trust domain in plain text, making issuer visibility a structural property, not a configuration choice (draft-ietf-wimse-arch, [https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)). The BBS+ VC profile is the only mainstream published construction that even attempts per-claim hiding, so it is the correct and only competitor for this candidate.

---

## What VC + BBS+ CAN Do Against C4

### 1. Selective claim disclosure with multi-presentation unlinkability

A holder with a BBS+ credential bearing claims `{chartered_by_NCUA: true, institution_id: CU-4892, jurisdiction: US, issuer_key: K_ncua}` can generate a derived presentation revealing only `chartered_by_NCUA: true` while keeping all other messages hidden. The derived proof is unlinkable across presentations of the same credential (BBS+ §6 — PoK of a signature). The proof size is O(|disclosed messages|), not O(n) for the full credential.

This covers the **cross-CU NCUA membership** scenario partially: a verifier learns that *some* BBS+-capable issuer attested `chartered_by_NCUA == true`, and learns nothing about institution identity. That is a genuine capability.

### 2. Range proofs and equality predicates over hidden claims

BBS+ derived proofs can be composed with Pedersen-commitment-based range proofs (e.g., Bulletproofs) to prove inequalities over hidden claim values — for example, proving `expiry_date > 2026-06-21` without disclosing the exact date. Equality checks across two credentials ("this claim equals that claim") are achievable via shared blinding factors in the commitment layer.

### 3. Schema-flexible credential structure

W3C VC 2.0 places no schema constraint on credential subjects. BBS+ signs an ordered message vector; the verifier only needs to know which indices correspond to which claim names. Multiple credential schemas (NCUA charter, FINRA license, KYB jurisdiction) can be handled with the same BBS+ signature suite.

### 4. Multi-issuer trust registries (directory-based, non-ZK)

A verifier can maintain a registry of known BBS+ issuer public keys (e.g., all NCUA-recognized keys, all FINRA-recognized keys) and verify that the credential's issuer key is a member of that set — by exhaustive check against the directory. This is O(|registry|) linear verification, not constant-time, and it is not blind: the verifier learns which key signed once it finds the match.

---

## What VC + BBS+ CANNOT Do Against C4

### 1. Issuer anonymity within a set (the central gap)

**BBS+ does not hide the issuer's public key from the verifier.** The BBS+ signature is verified against a specific issuer key; the derived proof proves knowledge of a valid signature under a *named* key. To prove "this attribute was signed by *some* key in set S without revealing which one," you need either:
- A group-signature or ring-signature construction over the issuer key set (no IETF-published standard for VC profiles exists for this as of June 2026), or
- A ZK proof that the issuer key is a member of a committed set.

Neither is part of BBS+ or VC-DI BBS+ 2023. The **cross-country KYB scenario** (jurisdiction must stay hidden) is explicitly out of scope: the issuer's public key implicitly encodes the jurisdiction, and BBS+ reveals it.

### 2. Constant-size proof independent of issuer-set size

Even if a ring-signature extension were bolted onto BBS+, proof size would grow with the size of the anonymity set (O(|S|) for Pedersen ring constructions). BBS+ itself has no mechanism for O(1) issuer-hiding across a variable-cardinality issuer registry. This is a fundamental algebraic constraint of the scheme.

### 3. Arbitrary Boolean predicates over claim schemas in a single proof

BBS+ supports selective disclosure (reveal/hide per message index) and, with extension, range proofs over scalar values. It does not natively compile arbitrary Boolean expressions over claim schemas — for example, `(chartered_by_NCUA == true) AND (jurisdiction IN {US, CA}) AND NOT (enforcement_action_count > 0)` — into a single atomic proof. Each predicate type requires a separate composition layer with its own trusted setup or proof system integration. There is no published VC-DI profile that delivers this. The **cross-firm regulated-professional proof** (FINRA-licensed agent) requires exactly this kind of multi-predicate composition under schema variance.

### 4. Schema-agnostic predicate compilation without per-schema circuit work

BBS+ is a signature scheme, not a predicate compiler. Adapting it to a new credential schema (e.g., NCUA Form 4012 vs. FINRA BrokerCheck fields) requires manually specifying which message indices carry which semantics. There is no general-purpose intermediate representation (IR) that compiles a claim schema into a BBS+ selective-disclosure policy. Arbitrary-schema support as stated in C4 — "constant-size predicate circuit that handles arbitrary Boolean expressions over claim schemas" — is not achievable within BBS+ without per-schema engineering effort equivalent to building a custom circuit anyway.

### 5. Proof of non-membership in a revocation set with issuer hiding intact

BBS+ status lists (e.g., W3C StatusList2021, [https://www.w3.org/TR/vc-bitstring-status-list/](https://www.w3.org/TR/vc-bitstring-status-list/)) require the holder to reference a status list URL, which encodes issuer identity. Any revocation check against a published status list leaks which issuer's list was consulted, breaking issuer anonymity even when the BBS+ proof hides the claim values.

### 6. Formal IND-ISS security game compliance

No published BBS+ specification or IETF draft defines or proves security against the Issuer Indistinguishability (IND-ISS) adversarial game — the game in which an adversary tries to distinguish which of two issuers signed a given credential. BBS+ proofs of security (draft-irtf-cfrg-bbs-signatures §7) cover unforgeability and zero-knowledge of the derived proof relative to a *fixed, known* issuer key. Issuer-set anonymity is out of scope and unproven.

---

## Scenario-by-Scenario Gap Summary

| Scenario | BBS+ capability | Gap |
|---|---|---|
| Cross-CU NCUA membership proof | Hides institution claims; does not hide NCUA issuer key | Issuer key reveals which NCUA-affiliated signer, breaking anonymity within the NCUA issuer set |
| Cross-firm FINRA regulated-professional proof | Selective disclosure of license status; cannot compose multi-predicate across FINRA schema variants | Per-schema BBS+ adaptation required; no general Boolean predicate compiler |
| Cross-country KYB where jurisdiction must stay hidden | Can hide jurisdiction *claim value*; cannot hide issuer key | Issuer public key encodes jurisdiction implicitly; full issuer anonymity impossible in BBS+ |

---

## Sources

- RFC 7662 (Token Introspection): [https://datatracker.ietf.org/doc/html/rfc7662](https://datatracker.ietf.org/doc/html/rfc7662)
- W3C VC Data Model 2.0: [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
- draft-irtf-cfrg-bbs-signatures: [https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- VC-DI BBS+ 2023: [https://www.w3.org/TR/vc-di-bbs/](https://www.w3.org/TR/vc-di-bbs/)
- W3C Bitstring Status List: [https://www.w3.org/TR/vc-bitstring-status-list/](https://www.w3.org/TR/vc-bitstring-status-list/)
- WIMSE Architecture: [https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)

---

**Bar to beat:** Prove that a credential attribute predicate (e.g. `chartered_by_NCUA == true`) holds under a signature from *some* key in a published issuer set, in O(1) proof size, without revealing which key signed, formally secure under the IND-ISS game — a capability BBS+ explicitly does not define, prove, or support.
