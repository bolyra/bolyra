# Baseline for C4 — Issuer-Blind Attribute Predicates

## Best Alternative: W3C VC Data Model 2.0 + BBS+ Selective Disclosure (VC-DI BBS+ 2023)

The strongest non-ZK construction that can plausibly approximate C4 combines three specifications:

1. **W3C Verifiable Credentials Data Model 2.0** ([https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)) — the credential envelope and presentation protocol.
2. **draft-irtf-cfrg-bbs-signatures** ([https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)) — multi-message signature scheme over pairing-friendly curves enabling selective disclosure and NIZK proof of knowledge of a signature.
3. **VC-DI BBS+ 2023 Cryptosuite** ([https://www.w3.org/TR/vc-di-bbs/](https://www.w3.org/TR/vc-di-bbs/)) — the normative profile binding BBS+ to the W3C VC framework, including derived proof generation for holder-side selective disclosure.

A secondary layer from **RFC 7517 / RFC 7519 (JSON Web Keys / JWTs)** ([https://datatracker.ietf.org/doc/html/rfc7517](https://datatracker.ietf.org/doc/html/rfc7517), [https://datatracker.ietf.org/doc/html/rfc7519](https://datatracker.ietf.org/doc/html/rfc7519)) would provide the transport envelope and issuer key publication mechanism. No other non-ZK standard meaningfully competes: OAuth 2.0 introspection (RFC 7662) requires live AS contact that trivially reveals issuer identity; SPIFFE/WIMSE encodes issuer in the SPIFFE ID structurally and provides no predicate mechanism.

---

## What This Baseline CAN Do

**1. Selective disclosure of individual claims without revealing the full credential.**
BBS+ allows a holder to generate a derived proof revealing only the specific claim fields chosen at presentation time (e.g., `chartered_by_NCUA: true`) while keeping all other claims hidden. The verifier receives a NIZK proof-of-knowledge of the issuer's BBS+ signature over the full message set, together with the disclosed subset. This is standardized behavior in VC-DI BBS+ 2023, Section 3.

**2. Multi-presentation unlinkability.**
Each call to the derived proof algorithm produces a fresh, independently randomized proof. Two presentations of the same credential to two different verifiers (or the same verifier at different times) are cryptographically unlinkable. This covers the cross-CU NCUA scenario at the presentation-unlinkability level: a credit union verifier cannot correlate two presentations.

**3. Range proofs and equality predicates over hidden messages.**
BBS+ can compose with auxiliary NIZK gadgets (e.g., Bulletproofs or Sigma-protocol range proofs) to prove arithmetic predicates over hidden message values — for instance, `membership_since < 2020` without revealing the exact date. This is acknowledged in the BBS+ draft as a composable extension, though it is not standardized in the VC-DI profile.

**4. Holder binding.**
The VC-DI BBS+ profile supports binding a derived proof to a holder's key, preventing credential theft and reuse by an adversary who obtains the credential but not the holder's private key.

**5. Cross-schema compatibility within the W3C VC envelope.**
Because claims are JSON-LD properties, any schema that maps to JSON-LD can be expressed in a VC, and BBS+ signs over the canonical N-Quads serialization of those claims. In principle, credentials from NCUA-chartered issuers, FINRA licensing systems, or jurisdictional KYB authorities can all be expressed as VCs with different schemas and presented using the same BBS+ machinery.

---

## What This Baseline Fundamentally CANNOT Do

**1. Hide the issuer's public key from the verifier.**
This is the central, non-negotiable failure of VC+BBS+ against C4. A BBS+ derived proof includes, or is cryptographically bound to, the issuer's BBS+ public key. The verifier must have that key to verify the proof. The verifier therefore knows exactly which entity issued the credential. There is no mechanism within BBS+ or the VC-DI profile to prove "some issuer in a set of issuers signed this" without revealing which one. Issuer anonymity within a set — the precise claim of C4 — is absent. The BBS+ draft (draft-irtf-cfrg-bbs-signatures, Section 1) explicitly scopes itself to single-issuer proofs; multi-issuer anonymity is not in scope.

**2. Prove a Boolean predicate over attributes of arbitrary schema in constant proof size.**
While BBS+ selective disclosure proofs are O(|disclosed messages|) in size, composing arbitrary Boolean expressions over hidden claims — including disjunctions, conjunctions, and negations across multiple claim fields from an unknown schema — requires circuit compilation external to BBS+. The VC-DI BBS+ profile provides no circuit layer. Each new predicate type requires bespoke Sigma-protocol or Bulletproof composition, and proof size grows with predicate complexity. C4 requires a constant-size proof for arbitrary Boolean expressions; VC+BBS+ has no such guarantee.

**3. Support arbitrary schema without per-schema issuer key registration.**
For a verifier to accept a BBS+ derived proof, it must already know the issuer's public key. In C4's cross-CU or cross-country scenarios, this requires the verifier to maintain a registry of all possible issuer public keys for all schemas it might accept. This is operationally equivalent to a PKI, and the verifier can trivially enumerate which issuer signed by testing its registry — defeating issuer-hiding even if the proof itself is zero-knowledge over the signature value.

**4. Prove jurisdiction-hiding KYB.**
For the cross-country KYB scenario in C4, where jurisdiction must remain hidden, VC+BBS+ cannot prevent the verifier from inferring jurisdiction from the issuer's public key alone. Even if all KYB credential claims are hidden, the issuer key identifies the jurisdiction's regulatory body. This is a structural impossibility, not a configuration failure.

**5. Provide a security reduction for issuer-hiding.**
The BBS+ draft provides security proofs for message-hiding (NIZK proof of knowledge of signature) and for multi-presentation unlinkability. It provides no IND-ISS (issuer indistinguishability) game or reduction, because the construction does not target that property. There is no hardness assumption in the BBS+ literature that would support an issuer-hiding claim.

**6. Compose with an anonymous issuer set without exiting the standard.**
Some research constructions (e.g., group signatures over BBS+, or accumulator-based membership proofs for issuer keys) could extend VC+BBS+ toward issuer anonymity within a set. None of these are standardized, none are part of VC-DI BBS+ 2023, and none achieve the constant-size proof property over arbitrary Boolean expressions claimed by C4. Deploying them would constitute a custom ZK construction, which is precisely what Tier 2 addresses.

---

## Additional Standards Consulted and Ruled Out

- **SD-JWT (draft-ietf-oauth-selective-disclosure-jwt)** ([https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)): Supports selective disclosure via salted hash commitments, but the issuer's JWT signature is fully visible to verifiers. Issuer-hiding is impossible by construction.
- **RFC 8693 Token Exchange** ([https://datatracker.ietf.org/doc/html/rfc8693](https://datatracker.ietf.org/doc/html/rfc8693)): Issuer AS is on the hot path and visible to all parties.
- **SPIFFE/WIMSE** ([https://datatracker.ietf.org/wg/wimse/about/](https://datatracker.ietf.org/wg/wimse/about/)): SPIFFE ID encodes trust domain (issuer) structurally; predicate proofs and issuer anonymity are both out of scope.
- **ISO/IEC 18013-5 mdoc (mDL)**: Issuer signing authority is required in the DeviceResponse structure; issuer-hiding is not supported.

---

**Bar to beat:** W3C VC+BBS+ achieves selective claim disclosure and multi-presentation unlinkability but structurally reveals the issuer's public key to every verifier — C4 must demonstrate constant-size proofs with a formal IND-ISS reduction showing issuer identity is computationally hidden within an issuer set, which no standardized non-ZK construction can express.
