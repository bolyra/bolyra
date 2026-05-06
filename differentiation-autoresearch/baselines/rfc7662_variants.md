# Baseline — RFC 7662 + Variants

The strongest non-ZK OAuth/OIDC baseline any ZK construction must beat.

## Core

**RFC 7662 OAuth 2.0 Token Introspection**
- RS posts opaque token to AS `/introspect`
- AS returns JSON: `{active, scope, client_id, sub, aud, exp, iat, nbf, username, token_type, ...}`
- AS is fully trusted: it sees every RS call and can correlate
- AS may filter the response per RS based on policy

## Extensions that tighten the baseline

**draft-ietf-oauth-jwt-introspection-response**
- AS returns signed JWT instead of JSON
- RS verifies offline with AS's public key
- Removes AS from the hot path (RS can cache)
- Content is fixed at introspection time, not adaptive per RS-RS call

**RFC 8693 OAuth 2.0 Token Exchange**
- Delegation primitive: exchange subject_token + actor_token for new token with narrowed scope
- Requires AS roundtrip per hop
- AS sees the full chain: actor, subject, requested scope, issued scope
- Chain is visible to final RS

**RFC 8707 Resource Indicators**
- Tokens bound to specific audience (RS identifier)
- Prevents cross-RS replay
- Does NOT prevent AS from correlating the agent's cross-RS traffic

**RFC 9449 DPoP (Demonstrating Proof of Possession)**
- Sender-constrained tokens via agent keypair signing per request
- Protects against bearer-token theft
- Does NOT hide scope, does NOT hide issuer, does NOT prevent AS correlation

**RFC 9728 PRM (Protected Resource Metadata)**
- RS publishes `.well-known/oauth-protected-resource` listing its authorization servers
- Enables dynamic discovery; does not change confidentiality properties

**OIDC Pairwise Subject Identifiers (PPID)**
- Different `sub` per RS, prevents RS-vs-RS correlation on `sub`
- Does NOT prevent AS from correlating (AS generates all PPIDs)

## What the best baseline can do

Combining everything above, a well-configured AS can:
1. Issue RS-audience-bound tokens (8707)
2. Sign introspection responses as JWTs (jwt-introspection-response)
3. Filter introspection response per RS via AS-side policy
4. Use PPIDs so RSes cannot correlate
5. Delegate via token exchange (8693) with per-hop scope narrowing
6. Bind tokens to agent keys via DPoP (9449)

## What the best baseline fundamentally cannot do

1. **Hide from the AS itself** — the AS issues every token and sees every introspection call. Cross-RS correlation at the AS is free.
2. **Prove predicates over scope without disclosing scope** — the AS can filter what it returns, but a malicious AS can lie about filtering. RS must trust AS's word.
3. **Hide issuer identity** — the AS that signs the introspection response is visible to RS. Issuer-blind attribute proofs are not expressible.
4. **Narrow scope without AS roundtrip per hop** — RFC 8693 is an AS-mediated exchange.
5. **Provide forward secrecy on prior sessions** — bearer tokens are replayable; key compromise exposes history.
6. **Prove runtime model identity** — `client_id` is a static string, not a cryptographic binding to a specific model+operator+permission state.

## Sources

- RFC 7662: https://datatracker.ietf.org/doc/html/rfc7662
- draft-ietf-oauth-jwt-introspection-response: https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/
- RFC 8693: https://datatracker.ietf.org/doc/html/rfc8693
- RFC 8707: https://datatracker.ietf.org/doc/html/rfc8707
- RFC 9449: https://datatracker.ietf.org/doc/html/rfc9449
- RFC 9728: https://datatracker.ietf.org/doc/html/rfc9728
