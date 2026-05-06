# Baseline for C2: Cross-Scope Unlinkability

## Best Alternative: OIDC Pairwise Subject Identifiers + RFC 8707 Resource Indicators + DPoP (RFC 9449)

The strongest non-ZK baseline against cross-scope unlinkability is a combination of OIDC Pairwise Subject Identifiers (PPID), RFC 8707 audience binding, and DPoP sender-constraint. No single spec addresses the full claim; the combination represents the practical ceiling of what the OAuth/OIDC stack can deliver without a ZK layer.

W3C VC+BBS+ multi-presentation unlinkability is the secondary candidate, but it addresses holder-to-verifier unlinkability, not agent-to-AS unlinkability. Since C2's adversary is explicitly an AS trying to correlate cross-RS traffic, BBS+ does not move the needle on the core threat.

---

## What the Baseline CAN Do

### 1. RS-to-RS Subject Correlation Resistance (OIDC PPID)

OIDC Pairwise Subject Identifiers ([OpenID Connect Core §8](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)) issue a different `sub` value per (agent, sector_identifier) pair. RS-A and RS-B receive distinct `sub` values derived from the same underlying identity. Passive RS-vs-RS correlation on `sub` is broken without AS involvement.

Concrete capability: if two RS instances are in different sectors and do not share logs or collude with the AS, they cannot link the agent's activity by subject claim alone.

### 2. Audience-Scoped Token Binding (RFC 8707)

[RFC 8707 Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707) binds each access token to a specific `resource` URI at issuance. Tokens issued for `https://rs-a.example/` carry `aud: rs-a` and are rejected by RS-B. This eliminates cross-RS token replay as a correlation vector — an adversary who intercepts a token at RS-A cannot present it to RS-B and use the response to confirm the agent's identity across scopes.

### 3. Per-Request Key Binding with Fresh Nonces (RFC 9449 DPoP)

[RFC 9449 DPoP](https://datatracker.ietf.org/doc/html/rfc9449) binds each token to an ephemeral key via a signed proof-of-possession header. Each DPoP proof includes a `jti` nonce and `htm`/`htu` binding, meaning no two RS requests share an identical bearer artifact. DPoP prevents replay-based linkage across scopes if the agent rotates its DPoP keypair between scope contexts — this is not required by the spec but is operationally achievable.

### 4. Introspection Response Filtering (draft-ietf-oauth-jwt-introspection-response)

The [JWT Introspection Response draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/) allows the AS to issue per-RS signed introspection responses that reveal only the claims relevant to that RS. RS-A receives `{active: true, scope: "read:accounts"}` while RS-B receives `{active: true, scope: "read:records"}` — no RS learns the full scope surface of the agent. This is an AS-policy control, not a cryptographic guarantee.

### 5. BBS+ Multi-Presentation Unlinkability (VC-DI BBS+ 2023)

[BBS+ Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) enable a credential holder to generate multiple derived presentations of the same credential such that no two presentations are linkable by a passive verifier. If the agent holds a VC issued by a credential issuer (separate from the AS), presentations to RS-A and RS-B are unlinkable at the presentation layer. This addresses the RS-side linkage vector.

---

## What the Baseline CANNOT Do

### 1. Hide Cross-RS Traffic from the AS Itself

This is the central impossibility. In every OAuth 2.0 flow — authorization code, client credentials, token exchange, and introspection — the AS issues and tracks every token. An AS that issues tokens for both RS-A (scope `merchant:read`) and RS-B (scope `provider:read`) sees both issuance events, their timestamps, the agent's `client_id`, and often a stable subject identifier. PPID protects only RS-vs-RS correlation; it does nothing against the AS correlating its own issuance log. **An AS acting as an adversary in C2's IND-UNL-AS game wins trivially under all OAuth/OIDC variants.**

RFC 8707 and DPoP are both AS-visible. The AS signs audience-bound tokens and receives DPoP-bound token requests. Neither spec provides any mechanism for the agent to obtain an authorization credential without the AS observing which RS is being accessed.

### 2. Provide Unlinkability Under Colluding AS+RS

The baseline has no mechanism to prevent an AS that shares data with RS-A from correlating RS-A's access pattern with the agent's identity. Since PPIDs are computed deterministically by the AS, the AS can reverse-map any RS's `sub` to the underlying agent. There is no blinding step. Collusion between a single RS and the issuing AS fully breaks PPID's guarantee.

### 3. Prove Scope Separation Without Disclosing Scope

Introspection response filtering is an AS-side policy claim. A malicious AS can include unfiltered scope, emit timing signals correlated to scope transitions, or embed a hidden correlation token in the `jti` of the signed JWT. The RS has no cryptographic proof that the AS has not leaked scope information to a colluder. **There is no non-interactive proof that the AS's view of the agent's scope graph is constrained.**

### 4. Nullifier Separation Per Scope

The concept of per-scope nullifiers — a commitment scheme where the agent can prove freshness and non-reuse within a scope without producing a linkable identifier across scopes — is not expressible in any OAuth, OIDC, SPIFFE, or BBS+ primitive. RFC 9449 DPoP nonces provide per-request freshness against the individual RS but are visible to the AS, defeating nullifier separation under the IND-UNL-AS game.

### 5. Formal IND-UNL-AS Security Definition

No RFC or W3C specification provides a formal unlinkability security definition against an adversarial authorization server. The PPID specification states a practical privacy goal in prose ([OpenID Connect Core §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)) but does not define an adversarial game, a distinguishing advantage bound, or a reduction to a hardness assumption. BBS+ provides a formal unlinkability proof for holder-verifier presentations ([draft-irtf-cfrg-bbs-signatures §6](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)) but this proof does not cover issuer-side correlation.

### 6. Side-Channel Resistance (Timing, Nonce Freshness)

OAuth and OIDC are silent on timing side channels. Introspection latency, token issuance timestamp granularity, and DPoP `iat` claim resolution all provide sub-second correlation signals to an adversary monitoring the AS. The baseline provides no normative treatment of timing side channels as a linkage vector.

---

## Relevant Specifications

| Spec | URL |
|---|---|
| RFC 7662 Token Introspection | https://datatracker.ietf.org/doc/html/rfc7662 |
| draft-ietf-oauth-jwt-introspection-response | https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/ |
| RFC 8707 Resource Indicators | https://datatracker.ietf.org/doc/html/rfc8707 |
| RFC 9449 DPoP | https://datatracker.ietf.org/doc/html/rfc9449 |
| OpenID Connect Core §8 (PPID) | https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes |
| BBS+ Signatures | https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ |
| W3C VC-DI BBS+ 2023 | https://www.w3.org/TR/vc-di-bbs/ |
| RFC 8693 Token Exchange | https://datatracker.ietf.org/doc/html/rfc8693 |
| WIMSE Architecture | https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ |

---

**Bar to beat:** Provide a cryptographically binding, formally provable IND-UNL-AS guarantee — where an adversarial AS colluding with any subset of resource servers cannot distinguish which scopes a single agent accessed, even given the full AS issuance log — a property no OAuth/OIDC/BBS+ construction can express because all require the AS to observe the scope-to-RS mapping at token issuance time.
