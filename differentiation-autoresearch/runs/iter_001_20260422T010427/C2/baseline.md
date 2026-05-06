# Baseline for C2 — Cross-Scope Unlinkability
## Candidate: Same agent, different RS instances, adversarial AS cannot reconstruct per-agent traffic graphs

---

## 1. Best Alternative: W3C VC + BBS+ with OIDC PPID token delivery (RFC 8707 + RFC 9449)

The strongest non-ZK construction combines three layers:

- **W3C VC Data Model 2.0** with **BBS+ signatures** (draft-irtf-cfrg-bbs-signatures) as the credential core — enabling per-presentation unlinkability at the holder layer.
- **OIDC Pairwise Pseudonymous Identifiers (PPID)** per RS — different `sub` values per resource server, preventing RS-vs-RS correlation on stable identifiers.
- **RFC 8707 Resource Indicators** — audience-binding each token to exactly one RS, so a token obtained for RS-A cannot be replayed against RS-B.
- **RFC 9449 DPoP** — sender-constraining each token to a per-request proof-of-possession key, so raw bearer tokens cannot be re-used even if intercepted.

This is the most aggressive non-ZK stack that can be assembled from existing standards. Each piece has a specific role against the unlinkability threat:

| Layer | Role | Spec |
|---|---|---|
| BBS+ derived VP | RS-to-RS unlinkability (same credential → N unlinkable presentations) | draft-irtf-cfrg-bbs-signatures |
| OIDC PPID | RS-to-RS `sub` unlinkability | OIDC Core §8 |
| RFC 8707 Resource Indicators | Prevents token replay across RS | RFC 8707 |
| RFC 9449 DPoP | Constrains bearer token to agent keypair | RFC 9449 |
| VC-DI BBS+ 2023 | VC presentation profile using BBS+ | W3C VC-DI BBS+ |

---

## 2. What This Baseline CAN Do Against C2

**RS-to-RS correlation on `sub`:** PPID issues distinct `sub` per RS. A colluding RS-A and RS-B observing their respective tokens cannot link them on `sub` alone, because the AS assigns each RS a different pseudonym for the same agent.

**RS-to-RS correlation via credential presentation:** BBS+ derived VPs are unconditionally unlinkable at the cryptographic level between presentations. RS-A and RS-B each see a distinct derived proof from the same underlying credential; those proofs cannot be linked without the holder's secret or the issuer's cooperation.

**Token replay across RS:** RFC 8707 audience-binding ensures a token scoped to RS-A is rejected at RS-B. This closes the trivial cross-RS replay vector.

**Bearer token theft enabling cross-RS activity:** RFC 9449 DPoP binds each token to a proof-of-possession keypair, so stolen bearer tokens are useless without the corresponding private key.

**Selective claim disclosure per RS:** BBS+ selective disclosure allows the agent to reveal only the claims each RS is entitled to see, so RS-A does not learn the scopes RS-B was granted.

---

## 3. What This Baseline Fundamentally CANNOT Do

**3.1 Hide the agent's activity graph from the AS.**
This is the core failure. The AS issues every token and processes every introspection request. Under RFC 7662 introspection (https://datatracker.ietf.org/doc/html/rfc7662) or its JWT variant (draft-ietf-oauth-jwt-introspection-response), every RS-bound token request arrives at the AS with the requesting agent's identity and the target RS as `resource` or `aud`. An adversarial AS trivially reconstructs: *agent X accessed RS-A at T1, RS-B at T2, RS-C at T3*. PPIDs prevent RS-RS linkage; they do not prevent AS-internal linkage. The AS generated all the PPIDs — it holds the mapping table.

**3.2 Provide a formal unlinkability security definition binding the AS.**
BBS+ unlinkability is defined as a property between a holder and a verifier, assuming an honest issuer. No existing spec formalizes an IND-UNL game in which the issuer/AS is the adversary. The BBS+ draft (https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) defines unlinkability as: no PPT adversary can link two derived proofs without the holder secret. This game explicitly excludes the issuer as an adversary. When the AS is adversarial, the game is silent.

**3.3 Separate nullifiers per scope.**
There is no notion of nullifier, scope-commitment, or scope-epoch in any of these standards. An AS that logs `{agent_id, scope_set, resource_indicator, timestamp}` on every token issuance sees the full scope graph regardless of BBS+ at the presentation layer. Nullifier separation — where each scope access produces a fresh, scope-keyed, one-time token that cannot be linked back to an agent serial by the issuer — has no analog in RFC 8707, RFC 9449, or BBS+.

**3.4 Prevent timing side-channel correlation.**
None of these specifications address timing. An AS logging request timestamps with sub-second resolution can correlate cross-RS accesses by timing proximity, even when `sub` is pseudonymized per RS. This is absent from RFC 7662, RFC 8707, RFC 9449, and the BBS+ draft.

**3.5 Provide nonce freshness guarantees that resist AS-supplied nonce correlation.**
RFC 9449 nonces are AS-issued. An adversarial AS can assign structured nonces that encode agent identity, negating DPoP's unlinkability benefit. The spec (https://datatracker.ietf.org/doc/html/rfc9449 §8) acknowledges AS-supplied nonces but does not constrain how the AS generates or patterns them.

**3.6 Prove that the agent did NOT access a given RS.**
None of these standards can produce a proof of non-access. An agent cannot demonstrate to a regulator or auditor that it did not touch a particular RS during a time window, without relying on the AS's log — the same AS whose trustworthiness is in question.

---

## 4. Specification References

- RFC 7662 OAuth 2.0 Token Introspection: https://datatracker.ietf.org/doc/html/rfc7662
- draft-ietf-oauth-jwt-introspection-response: https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/
- RFC 8707 Resource Indicators: https://datatracker.ietf.org/doc/html/rfc8707
- RFC 9449 DPoP: https://datatracker.ietf.org/doc/html/rfc9449
- OIDC Core §8 (Pairwise Identifiers): https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
- draft-irtf-cfrg-bbs-signatures (BBS+): https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- W3C VC-DI BBS+ 2023: https://www.w3.org/TR/vc-di-bbs/
- WIMSE Architecture (for layering context): https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/

---

## 5. Scenario-Specific Assessment

**Cross-credit-union member agent (CU-as-AS must not see member merchant graph):** The baseline fails completely. The credit union operating as AS sees every token request to every merchant RS. PPID hides the `sub` from merchants comparing notes; it does nothing against the CU itself. BBS+ presentations are unlinkable between merchants; the CU issued them all and logged the issuance.

**Healthcare agent delegation across providers (issuer must not learn referral network):** The baseline fails on the same axis. RFC 8693 Token Exchange (https://datatracker.ietf.org/doc/html/rfc8693) requires an AS roundtrip per delegation hop, and the AS sees actor, subject, requested scope, and issued scope for each hop. The referral network is reconstructed from the delegation log.

---

**Bar to beat:** A construction must make it computationally infeasible for the issuing AS — even with full logs of every token issuance — to reconstruct which agent accessed which RS, while still allowing each RS to verify the agent's authorization for its specific scope.
