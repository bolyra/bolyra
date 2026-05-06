# Baseline — W3C Verifiable Credentials + BBS+ Selective Disclosure

The strongest non-Bolyra ZK-ish baseline for selective disclosure and issuer-blind predicates.

## Core

**W3C VC Data Model 2.0**
- Issuer signs a credential with N claims
- Holder presents a Verifiable Presentation (VP) to a verifier
- VP may contain derived proofs revealing a subset of claims

**BBS+ Signatures (draft-irtf-cfrg-bbs-signatures)**
- Multi-message signature scheme on pairing-friendly curves
- Supports selective disclosure: prove knowledge of signature over messages m_1..m_n while revealing only a subset
- Supports predicates over hidden messages via range-proof / NIZK compositions
- Size: O(n) for signature, O(|disclosed|) for derived proof

**BBS+ VC profile (VC-DI BBS+ 2023)**
- Uses BBS+ as the signature suite for VCs
- Holder can generate derived VP revealing arbitrary subset of claims
- Unlinkability: multiple presentations of the same credential are unlinkable to each other

## What the best VC+BBS+ baseline can do

1. Holder proves knowledge of issuer signature over credential without revealing the signature
2. Selective disclosure of individual claims
3. Multi-presentation unlinkability (same credential → N unlinkable presentations)
4. Range proofs and equality checks over hidden claims (via extensions)
5. Holder binding (signature binds to a holder key to prevent credential sharing)

## What VC+BBS+ cannot do (that Bolyra could)

1. **Issuer anonymity within a set** — BBS+ reveals the issuer's public key in the presentation. To hide the issuer, need a separate anonymous-credential construction (group signatures, CL signatures with issuer anonymity, or ZK over a registry of issuers).
2. **Delegation chain narrowing proofs** — BBS+ signs static claims; it does not natively prove that one credential is a narrowed derivative of another without exposing the narrowing.
3. **Mutual authentication in one atomic step** — BBS+ is holder → verifier one-way. Human + agent simultaneous proof bound to session nonce requires custom circuitry.
4. **Scope-bitmask predicate (permissionBitmask & requiredMask == requiredMask)** — BBS+ supports equality and range; Boolean bitmask predicates require circuit compilation on top.
5. **Cryptographic binding to runtime model identity** — VC is about attribute claims; binding to a model_hash + operator_pk + permission bitmask at call time is out of scope.

## Sources

- W3C VC 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- BBS+ draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- VC-DI BBS+: https://www.w3.org/TR/vc-di-bbs/
