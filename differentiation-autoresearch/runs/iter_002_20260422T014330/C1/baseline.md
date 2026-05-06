# Baseline: Strongest Non-ZK Alternative for Selective Scope Proof (C1)

## Best Alternative: W3C VC + BBS+ Selective Disclosure, Anchored by RFC 8707 Audience Binding

The strongest non-ZK construction for C1 is **W3C Verifiable Credentials with BBS+ signatures (draft-irtf-cfrg-bbs-signatures)**, combined with **RFC 8707 resource indicators** for audience binding and **draft-ietf-oauth-jwt-introspection-response** as the offline-verifiable token substrate when the AS is in the trust model. This is a layered stack, not a single protocol, and each layer is load-bearing.

The RFC 7662 family alone is insufficient for C1 and is explicitly excluded from the claim — this analysis confirms why, while establishing the BBS+ alternative as the correct comparison point.

---

## What This Baseline CAN Do Against C1

### 1. Selective claim disclosure without revealing the full credential

BBS+ ([draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/), [VC-DI BBS+](https://www.w3.org/TR/vc-di-bbs/)) allows a holder to present a **derived proof** that reveals an arbitrary subset of signed claims while cryptographically concealing the rest. Applied to permissions: if the issuer encodes each permission scope as a distinct claim (`m_1 = read:accounts`, `m_2 = write:transfers`, …), the agent can selectively disclose only the subset of permissions required for a given RS call while proving knowledge of a valid issuer signature over the full set. The RS sees only what was disclosed; it cannot enumerate undisclosed claims.

This directly addresses the surface-level framing of C1 — "prove you have permission X without revealing the full permission set" — at the claim-granularity level.

### 2. Multi-presentation unlinkability

BBS+ derived proofs are unlinkable: multiple presentations of the same underlying credential produce computationally unlinkable proof transcripts. An RS that logs every interaction cannot correlate two calls from the same agent unless the agent re-discloses a stable identifier. This is stronger than PPID ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) + OIDC pairwise identifiers), which only breaks RS-vs-RS correlation, not temporal correlation at a single RS.

### 3. Offline RS verification, no AS on hot path

A BBS+-signed VC can be verified by the RS using only the issuer's public key. Combined with [draft-ietf-oauth-jwt-introspection-response](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/)-style offline verification semantics, the AS need not be reachable at call time. The RS validates the derived proof against the issuer's published BBS+ key; no introspection call is required.

### 4. Audience binding

Resource indicators ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)) can be encoded as a claim within the VC. A derived proof that discloses the `resource` claim and conceals all other permission claims gives the RS cryptographic assurance that the credential was issued for it specifically, without exposing scope breadth.

### 5. Holder key binding

BBS+ VCs support holder binding: the issuer signs a commitment to the holder's public key. The holder proves knowledge of the corresponding private key during presentation. Combined with DPoP-style per-request key proofs ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)), this prevents credential theft and replay across key compromise.

---

## What This Baseline Fundamentally CANNOT Do

### 1. Boolean predicate evaluation over a hidden bitmask

C1's first-order requirement is: **prove `permissionBitmask & requiredMask == requiredMask` without disclosing `permissionBitmask`**. BBS+ selective disclosure operates at claim granularity — it can hide or reveal whole claims, but it cannot evaluate an arithmetic predicate over a hidden integer-valued claim. Proving that a 64-bit integer satisfies a bitmask intersection requires a circuit-level constraint (bit decomposition, AND gate per bit position, equality check on the result). BBS+ has no such primitive; adding it requires an external NIZK composition that is, by definition, a ZK construction. **BBS+ cannot prove bitmask predicates over concealed integer claims without a ZK extension.**

This is the structural gap for C1's scenario 1 (2^64 permission space): encoding 2^64 permissions as individual BBS+ claims is computationally intractable. The issuer cannot produce a signature over 2^64 messages, and the holder cannot present a derived proof over them. Bitmask encoding is the only scalable representation, and BBS+ cannot reason over it.

### 2. Adversarial-AS model: cryptographic assurance that the AS did not lie about scope membership

BBS+ VCs are issued by an AS (or issuer). The AS must correctly encode the permission set into the credential at issuance time. In C1's scenario 2 (semi-trusted AS), the RS requires cryptographic assurance that the agent's permission claim is correct **independent of AS cooperation**. BBS+ does not provide this: the AS controls the credential content. A malicious AS can issue a credential claiming the agent has a permission it was never granted. The RS's BBS+ verification only proves that the credential contents are internally consistent with the issuer's signature — it cannot prove that the claimed permissions accurately reflect the underlying policy state. **BBS+ provides no protection against an issuer that lies about what it signs.**

### 3. Runtime-adaptive predicate — scope assertions not fixed at issuance

BBS+ is a static signing scheme. All claims are committed at issuance time. C1 requires the ability to prove a predicate that the agent satisfies **at the moment of use**, where the required permission set is specified by the RS at call time (not known to the issuer in advance). BBS+ selective disclosure can reveal pre-issued claims on demand, but it cannot prove satisfaction of a predicate whose structure is not determined until the RS presents it at runtime. **BBS+ cannot prove runtime-adaptive predicates over permissions; the credential contents are fixed at issuance.**

### 4. Constant-size proof independent of permission space width

BBS+ derived proof size is O(|disclosed claims| + |hidden claims with proof contribution|). For a large permission space encoded as N individual claims, proof size grows with N even when only one permission is disclosed (the remaining N−1 hidden messages still contribute to the signature randomization). A constant-size proof regardless of permission space width — which would be required for C1's 2^64 scenario — is not achievable with BBS+. **BBS+ proof size is linear in the number of claims in the underlying credential.**

### 5. AS-blind presentation — agent chooses disclosure at use time with no AS involvement

BBS+ requires the issuer (AS) to be involved at credential issuance with full knowledge of all claims. While the AS is not on the hot path during presentation, it was necessarily present at issuance and encoded the full permission set. C1's "AS-blind" property — where the AS does not learn which predicate the agent is about to prove, or even that a proof is occurring — is partially addressed (offline presentation), but the AS retains a complete picture of the agent's capabilities from issuance. **BBS+ does not achieve AS-blindness at the capability-encoding layer; the AS that issues the credential sees and sets the full permission set.**

---

## Specification References

- **BBS+ signatures**: [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- **W3C VC Data Model 2.0**: [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
- **VC Data Integrity BBS+ 2023**: [https://www.w3.org/TR/vc-di-bbs/](https://www.w3.org/TR/vc-di-bbs/)
- **RFC 7662 (Token Introspection)**: [https://datatracker.ietf.org/doc/html/rfc7662](https://datatracker.ietf.org/doc/html/rfc7662)
- **draft-ietf-oauth-jwt-introspection-response**: [https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/)
- **RFC 8707 (Resource Indicators)**: [https://datatracker.ietf.org/doc/html/rfc8707](https://datatracker.ietf.org/doc/html/rfc8707)
- **RFC 9449 (DPoP)**: [https://datatracker.ietf.org/doc/html/rfc9449](https://datatracker.ietf.org/doc/html/rfc9449)
- **RFC 8693 (Token Exchange)**: [https://datatracker.ietf.org/doc/html/rfc8693](https://datatracker.ietf.org/doc/html/rfc8693)

---

**Bar to beat:** Prove that `permissionBitmask & requiredMask == requiredMask` for an RS-specified `requiredMask`, without revealing `permissionBitmask`, without an AS roundtrip, with proof size independent of bitmask width, and with cryptographic assurance that the AS cannot have fabricated the underlying permission grant — none of which BBS+ selective disclosure can achieve simultaneously or individually in the bitmask case.
