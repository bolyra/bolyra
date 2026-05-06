# Baseline: Strongest Non-ZK Alternative for Bolyra as General MCP Auth

**Candidate:** C5 — Bolyra as MCP auth, generally
**Bar setter:** RFC 9449 DPoP + RFC 8707 Resource Indicators + RFC 8693 Token Exchange + RFC 9728 Protected Resource Metadata, deployed on a well-configured commercial AS (Auth0/WorkOS/Stytch/Cloudflare Access)

---

## 1. The Best Alternative

The strongest non-ZK baseline is a **DPoP-bound, audience-restricted OAuth 2.1 stack**, specifically:

- **RFC 9449 DPoP** — sender-constrained tokens, one keypair per agent instance
- **RFC 8707 Resource Indicators** — tokens bound to a specific RS audience, preventing cross-RS replay
- **RFC 8693 Token Exchange** — delegation primitive for narrowed-scope sub-tokens per hop
- **RFC 9728 Protected Resource Metadata** — RS-published `.well-known/oauth-protected-resource` enabling zero-config RS discovery without pre-registration by the client
- **OIDC Pairwise Subject Identifiers (PPID)** — different `sub` per RS, preventing RS-vs-RS correlation on the subject claim
- **draft-ietf-oauth-jwt-introspection-response** — signed JWT introspection responses, removing the AS from the hot path and enabling offline RS verification

This is not theoretical. Auth0, WorkOS, and Cloudflare Access ship substantial subsets of this stack today. RFC 9728 is the closest thing to "zero-config" RS discovery in the current OAuth ecosystem.

---

## 2. What This Baseline CAN Do Against C5's Hypotheses

**Against H1 (Mutual ZK handshake):**
DPoP (RFC 9449) binds each token to an agent keypair via a per-request proof-of-possession header. The agent signs a `dpop` JWT over the HTTP method and request URI on every call. This is not a ZK proof, but it is a cryptographic mutual posture: the RS verifies that the token presenter holds the private key bound at issuance. Combined with mTLS (RFC 8705), this achieves sender-constrained token binding without ZK.

**Against H3 (Zero-config identity portability):**
RFC 9728 lets any compliant RS publish its authorization server endpoint in `.well-known/oauth-protected-resource`. A client that discovers this endpoint can attempt dynamic client registration (RFC 7591) or use a pre-issued token with an audience claim matching the RS identifier (RFC 8707). In the Anthropic connector scenario, a single AS-issued DPoP token with broad resource indicator coverage can authenticate at multiple RSes without per-RS registration at the client level. This is not truly zero-registration — RFC 7591 dynamic registration requires one AS roundtrip — but it eliminates the manual configuration burden that characterizes vanilla OAuth.

**Against H5 (Agent-economy-native delegation):**
RFC 8693 Token Exchange allows a Claude agent to exchange a subject token for a narrowed-scope actor token targeting a specific downstream RS. The exchange is one AS call per hop. For a linear two-hop chain (Claude → tool → sub-tool), this is two AS roundtrips. The resulting token carries both `sub` (original subject) and `act` (actor) claims, giving the RS a complete delegation chain without client-side credential construction.

**Against H4 (Post-compromise resilience):**
DPoP tokens are sender-constrained: a stolen bearer token is not replayable without the corresponding private key. Short-lived access tokens (sub-60s expiry) further limit the window of compromise. This is not forward secrecy, but it closes the simplest bearer-token exfiltration attack that vanilla OAuth exposes.

---

## 3. What This Baseline Fundamentally CANNOT Do

These are hard limitations of the RFC stack, not implementation gaps.

**Cannot hide from the AS (H1, H4):**
Every token issuance, every token exchange (RFC 8693), and every introspection call (RFC 7662) is visible to the AS. The AS can correlate every cross-RS session for every agent, by design. OIDC PPIDs prevent RS-vs-RS correlation on `sub`, but the AS generates all PPIDs and retains the mapping. There is no mechanism in the RFC stack for an AS-blind credential presentation. Absence: **issuer-blind attribute proof is not expressible.**

**Cannot prove runtime model identity (H2):**
`client_id` in an OAuth token is a static string registered at the AS. It identifies an application, not a specific model checkpoint, operator keypair, or permission bitmask active at call time. There is no OAuth extension that binds `{model_hash, operator_pk, permission_bitmask}` to a specific RS invocation as a cryptographic commitment. The AS would have to take these values on trust from the client at registration. Absence: **cryptographic binding of runtime model state to a tool call is not expressible.**

**Cannot prove scope predicates without disclosing scope (H1, H2):**
The AS can filter what it returns in an introspection response, but a malicious or compromised AS can lie about what it filtered. The RS must trust the AS's word on scope. There is no way for a holder to prove "I hold a credential satisfying permission_bitmask & requiredMask == requiredMask" without the AS computing and attesting that result. Predicate proofs over hidden claims require a zero-knowledge construction. Absence: **scope-bitmask predicate over a hidden claim is not expressible.**

**Cannot provide forward secrecy for prior sessions (H4):**
DPoP protects against token theft, but does not provide forward secrecy. If an agent's long-term key is compromised, an adversary who recorded past DPoP proofs can verify which tokens were used, and an adversary who held the token can now replay it (since the check is on the key the token was bound to, which is now compromised). RFC 9449 §9.3 explicitly acknowledges this: DPoP does not prevent an attacker who has both the DPoP key and the access token from using them. Absence: **forward-secure session unlinkability after key compromise is not expressible.**

**Cannot do mutual identity proof in one atomic step (H1):**
DPoP + mTLS proves the agent holds a key bound to a token. It does not simultaneously prove that a human identity is cryptographically bound to the same session nonce. Human-in-the-loop binding requires a separate OIDC id_token flow (or a FIDO2 assertion) concatenated at the application layer, not cryptographically composed. There is no OAuth primitive for "one atomic proof that simultaneously binds human identity + agent identity + session nonce." Absence: **atomic mutual human+agent identity proof is not expressible.**

**Cannot narrow delegation scope without AS roundtrip (H5):**
RFC 8693 requires an AS call per hop. There is no offline delegation primitive in the RFC stack. Absence: **single-proof per-hop scope narrowing without AS roundtrip is not expressible.**

---

## 4. Cited Specifications

| Spec | Link |
|------|------|
| RFC 7662 OAuth 2.0 Token Introspection | https://datatracker.ietf.org/doc/html/rfc7662 |
| draft-ietf-oauth-jwt-introspection-response | https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/ |
| RFC 8693 OAuth 2.0 Token Exchange | https://datatracker.ietf.org/doc/html/rfc8693 |
| RFC 8705 OAuth 2.0 mTLS Client Auth | https://datatracker.ietf.org/doc/html/rfc8705 |
| RFC 8707 Resource Indicators | https://datatracker.ietf.org/doc/html/rfc8707 |
| RFC 9449 DPoP | https://datatracker.ietf.org/doc/html/rfc9449 |
| RFC 9728 Protected Resource Metadata | https://datatracker.ietf.org/doc/html/rfc9728 |
| RFC 7591 Dynamic Client Registration | https://datatracker.ietf.org/doc/html/rfc7591 |
| OIDC Core §8 (Pairwise Subject Identifiers) | https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg |

---

## 5. Assessment Against the Five Hypotheses

| Hypothesis | Baseline coverage | Gap |
|---|---|---|
| H1 Mutual ZK handshake | Partial — DPoP proves agent key possession; no atomic human+agent composition | Human binding is a separate flow, not cryptographically composed |
| H2 Model-instance binding | None | `client_id` is a static string; no runtime model_hash commitment |
| H3 Zero-config portability | Partial — RFC 9728 + RFC 7591 reduces to one AS roundtrip | Not truly registration-free; one roundtrip per AS still required |
| H4 Forward-secure nullifiers | None — DPoP closes bearer-token theft but not key compromise | Forward secrecy is architecturally absent from the RFC stack |
| H5 Single-proof delegation | None — RFC 8693 requires AS call per hop | Offline delegation primitive does not exist in OAuth |

H2 and H4 are the cleanest gaps: no RFC extension closes them, even in theory, without changing the trust model. H1 is partially covered for the agent half but not the human-binding half. H3 and H5 are reduced but not eliminated.

---

**Bar to beat:** A Bolyra construction must close H2 (runtime model-hash binding) and H4 (forward-secure session unlinkability) in a single credential presentation that does not require AS involvement at verification time — the RFC 9449 + RFC 8707 stack cannot reach either property regardless of configuration.
