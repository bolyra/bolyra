# Baseline: Cross-Scope Unlinkability for Agent Authorizations

## Candidate Summary

**C2 — Cross-scope unlinkability:** The same agent accessing different Resource Servers (RSes) produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that actively tries to reconstruct per-agent traffic graphs across scopes.

Concrete threat scenarios: a credit union acting as AS that must not learn the merchant graph of a member's agent; a healthcare delegation chain where the issuer must not infer referral network topology from authorization requests.

---

## Strongest Non-ZK Baseline

The best available combination is **OIDC Pairwise Subject Identifiers (PPID) + RFC 8707 Resource Indicators + RFC 9449 DPoP + BBS+ Selective Disclosure VCs**, layered as follows:

- RFC 8707 audience-binds each token to a single RS, preventing cross-RS replay.
- RFC 9449 DPoP sender-constrains each token to a per-request agent keypair proof, preventing bearer-token theft.
- OIDC PPIDs assign a distinct `sub` per RS, preventing RS-to-RS correlation on the subject identifier field.
- BBS+ Verifiable Credentials (draft-irtf-cfrg-bbs-signatures, VC-DI BBS+ 2023) allow the agent to present derived proofs to each RS that reveal only the subset of claims needed, with multiple presentations of the same credential being mutually unlinkable at the RS layer.

This stack represents the strongest honest baseline. Each component is deployed in production settings today. None individually achieves cross-scope unlinkability; the combination is the best available approximation.

---

## What This Baseline CAN Do

**1. RS-layer subject unlinkability via PPID**
OIDC PPIDs (OpenID Connect Core §8.1) assign a different `sub` value per RS (identified by `sector_identifier_uri` or `redirect_uri` sector). RS-A and RS-B receive different `sub` values for the same agent and cannot correlate by subject alone.

Spec: [OpenID Connect Core 1.0, §8.1](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)

**2. Audience-bound, scope-specific tokens**
RFC 8707 Resource Indicators allow the AS to issue tokens with `aud` bound to a single RS. An agent requesting access to RS-A and RS-B obtains two separate tokens. Presented credentials do not cross RS boundaries.

Spec: [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)

**3. Per-request key proof**
RFC 9449 DPoP binds each token presentation to a proof-of-possession over an ephemeral keypair. An eavesdropping RS cannot replay the token elsewhere. Each DPoP proof includes `htm`, `htu`, and a fresh `jti`, making cross-RS proof reuse detectable.

Spec: [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)

**4. Selective claim disclosure at the RS layer**
BBS+ signatures (draft-irtf-cfrg-bbs-signatures) allow the agent to derive a presentation revealing only the claims RS-A requires, then a separate presentation for RS-B, without correlatable proof artifacts. Two derived proofs from the same BBS+ credential are computationally unlinkable to each other and to the underlying signature.

Specs: [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/), [VC-DI BBS+ 2023](https://www.w3.org/TR/vc-di-bbs/)

**5. Offline RS verification**
draft-ietf-oauth-jwt-introspection-response allows RS to verify a signed JWT offline, removing the AS from the per-request hot path. This reduces the surface on which the AS observes individual RS calls — but only when no introspection is performed.

Spec: [draft-ietf-oauth-jwt-introspection-response](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/)

---

## What This Baseline Fundamentally CANNOT Do

**1. Hide from the AS itself — unlinkability against an adversarial issuer is absent.**
This is the central structural failure. Every token in the OAuth/OIDC stack is issued by the AS. The AS knows: which agent requested a token, for which RS, at what time, with what scope. PPID hides the `sub` from RSes but not from the AS, which holds the PPID mapping table. An AS colluding with one or more RSes can trivially reconstruct the agent's full cross-RS traffic graph. This is not a configuration flaw — it is definitional. The threat model in C2 explicitly names an adversarial AS; the entire OAuth/OIDC family assumes AS trustworthiness.

Absence named explicitly: **no OAuth/OIDC mechanism hides per-agent authorization requests from the issuing AS.**

**2. Issuer anonymity within a set — the signing key is always visible.**
BBS+ presentations expose the issuer's public key to the verifier. To hide which of N issuers signed a credential, you need a group-signature scheme or a ZK proof over an issuer set membership witness. Neither is part of the W3C VC + BBS+ specification. A colluding AS that is also the issuer can trivially self-identify.

Absence named explicitly: **BBS+ does not provide issuer anonymity; the issuer public key is a mandatory disclosed element in every derived proof.**

**3. Scope-separation as a cryptographic object — scope correlation at the AS is free.**
RFC 8707 binds the token to one RS, but the AS still sees the requested scope at token-issuance time for every RS the agent contacts. An adversarial AS observing scope=`merchant-read` for RS-A and scope=`pharmacy-read` for RS-B can infer the agent's behavioral graph without reading any token content. There is no mechanism in OAuth/OIDC to prevent the AS from logging and correlating scope sequences across requests. Scope blinding is not expressible.

Absence named explicitly: **no RFC prevents an AS from constructing a per-agent scope-access timeline across RS instances.**

**4. Delegation narrowing without AS visibility into the chain.**
RFC 8693 Token Exchange is the delegation primitive. Every hop requires an AS roundtrip, at which the AS sees the actor token, subject token, requested scope, and issued scope. In the healthcare scenario, the AS sees the full referral chain as it is constructed. There is no mechanism to prove "this is a narrowed derivative of credential X" without the AS learning X's scope.

Absence named explicitly: **RFC 8693 delegation is AS-observable at every hop; chain topology is not private from the issuer.**

**5. Formal unlinkability guarantee — no security definition exists in this stack.**
No RFC or W3C specification defines an IND-UNL-AS game or equivalent adversarial model for authorization unlinkability. BBS+ defines multi-show unlinkability only at the holder-to-verifier layer. DPoP defines token binding security, not traffic-graph privacy. There is no security proof in this baseline that bounds an adversarial AS's advantage in distinguishing which RS an agent contacted from a sequence of authorization events.

Absence named explicitly: **the baseline provides no formal unlinkability security definition against an adversarial AS; only informal separation at the RS layer.**

**6. Timing and nonce side channels — no mitigation.**
Even if all token-level correlation were blocked (which it is not), an AS that observes the timing of token issuance requests can correlate agent activity across RSes by timing alone. RFC 9449 DPoP requires a fresh `jti` and timestamps, which leaks request timing to the AS. No specification in this baseline mandates batching, padding, or oblivious issuance to resist timing analysis.

Absence named explicitly: **no RFC provides timing-side-channel resistance against an AS-level adversary.**

---

## Specification Sources

| Specification | URL |
|---|---|
| RFC 7662 Token Introspection | https://datatracker.ietf.org/doc/html/rfc7662 |
| draft-ietf-oauth-jwt-introspection-response | https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/ |
| RFC 8693 Token Exchange | https://datatracker.ietf.org/doc/html/rfc8693 |
| RFC 8707 Resource Indicators | https://datatracker.ietf.org/doc/html/rfc8707 |
| RFC 9449 DPoP | https://datatracker.ietf.org/doc/html/rfc9449 |
| OpenID Connect Core §8.1 PPID | https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes |
| draft-irtf-cfrg-bbs-signatures | https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ |
| W3C VC Data Model 2.0 | https://www.w3.org/TR/vc-data-model-2.0/ |
| VC-DI BBS+ 2023 | https://www.w3.org/TR/vc-di-bbs/ |
| WIMSE Architecture | https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ |

---

**Bar to beat:** The strongest baseline (PPID + RFC 8707 + DPoP + BBS+) achieves RS-layer subject unlinkability only — it provides zero cryptographic protection against an adversarial AS correlating per-agent cross-RS traffic by token issuance events, scope sequences, or request timing.
