# Baseline: Selective Scope Proof — Strongest Non-ZK Alternative

**Candidate C1 — Agent proves it satisfies a required permission predicate without revealing the full permission set to the resource server.**

---

## Best Alternative: RFC 7662 + JWT Introspection Response + RFC 8707 + W3C VC/BBS+ (Composed Stack)

No single specification matches C1's claim. The strongest plausible non-ZK baseline is a composed stack:

1. **RFC 7662** (Token Introspection) with **AS-side scope filtering policy** as the primary gate
2. **draft-ietf-oauth-jwt-introspection-response** to remove the AS from the hot path via signed JWT caching
3. **RFC 8707** (Resource Indicators) to bind tokens to a specific RS audience, preventing cross-RS replay
4. **RFC 9449** (DPoP) to sender-constrain tokens to the agent's keypair
5. **W3C VC Data Model 2.0 + BBS+ Selective Disclosure** (draft-irtf-cfrg-bbs-signatures) layered as a credential envelope, allowing the holder to present only the subset of claims the RS needs

This is the ceiling of the non-ZK art. Each component is described below.

---

## What This Baseline CAN Do

### AS-Side Scope Filtering (RFC 7662 + jwt-introspection-response)

The AS can be configured with per-RS policies that return only the scopes relevant to a given resource server. When combined with a signed JWT introspection response ([draft-ietf-oauth-jwt-introspection-response](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/)), the RS verifies the response offline using the AS's public key. This means:

- The RS sees only the scopes the AS chooses to reveal in the filtered introspection JWT.
- The AS need not be in the hot path for each RS call after the first introspection.
- The response is integrity-protected: the RS knows the filtered scope set is AS-attested.

### Audience Binding (RFC 8707)

[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) binds the issued token to a specific RS URI via the `resource` parameter. This prevents an agent from presenting the same token to a different RS, giving the RS cryptographic assurance that the token was scoped for it specifically.

### Sender Constraint (RFC 9449 DPoP)

[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) binds tokens to the agent's private key. Each request includes a DPoP proof — a signed JWT covering the HTTP method and target URI — ensuring bearer-token theft is insufficient for replay. The RS verifies the DPoP proof independently of the AS.

### Selective Claim Disclosure (W3C VC + BBS+)

If the permission set is modeled as a W3C VC credential with individual permission claims, [BBS+ signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) allow the holder to derive a presentation that reveals only the subset of permission claims required by the RS. The derived proof is unlinkable across presentations: two BBS+ presentations of the same credential cannot be correlated by an RS comparing notes with another RS. Range proofs and equality checks over hidden claims are supported via NIZK extensions to BBS+ (see [VC-DI BBS+](https://www.w3.org/TR/vc-di-bbs/)).

### Combined Capability Summary

- RS receives only the permission claims it requested, with AS-attested integrity.
- Token is audience-bound (RFC 8707) and sender-constrained (DPoP).
- If BBS+ VCs are used as the credential envelope, presentations are unlinkable across RS endpoints.
- AS can enforce delegation narrowing at issuance via [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchange, with each hop receiving a strictly narrowed scope.

---

## What This Baseline Fundamentally CANNOT Do

### 1. AS-Blind Presentation

**Cannot achieve.** In every RFC 7662 variant, the AS issues the token and controls what the introspection response contains. Even with jwt-introspection-response caching, the AS was present at issuance and at first introspection. The agent cannot present a selective scope proof to a new RS without the AS having been involved. An agent choosing at runtime — without an AS roundtrip — which subset of a previously-issued bitmask to prove satisfies a given predicate is not expressible in this stack. The closest analog is BBS+ holder-driven selective disclosure, but BBS+ operates over discrete claims, not over a bitmask with implication-closure semantics.

### 2. Runtime-Adaptive Predicate Over a Bitmask

**Cannot achieve.** The introspection response scope is a fixed string set determined at introspection time, not a runtime-evaluated predicate. The RS receives `scope: "read write"` — it cannot receive a proof that `permissionBitmask & requiredMask == requiredMask` holds without the AS having computed and attested to that specific conjunction. BBS+ supports equality and range predicates over hidden attributes, but Boolean bitwise AND over a multi-bit field with implication closure (bit 4 implies bits 2 and 3) requires circuit-level evaluation. No BBS+ extension in the current draft covers this.

### 3. Adversarial-AS Model

**Cannot achieve.** The entire RFC 7662 stack rests on AS trustworthiness. A malicious or compromised AS can lie in its introspection response — asserting that an agent does not hold a scope it actually holds, or asserting it holds a scope it does not. The RS has no cryptographic recourse: the signed introspection JWT proves only that the AS said what it said, not that the AS's representation of the agent's actual permission state is accurate. In the adversarial-AS model — where the RS needs assurance independent of AS cooperation — this stack provides no guarantee.

### 4. Constant-Size Proof Regardless of Bitmask Width

**Cannot achieve.** A jwt-introspection-response scales linearly with the number of scopes disclosed. A BBS+ derived proof scales with the number of disclosed messages (`O(|disclosed|)`). For a 64-bit permission space with fine-grained individual scope names (2^64 theoretical permissions), a scope string enumeration is computationally and bandwidth infeasible. No RFC 7662 variant addresses this cardinality problem. BBS+ handles it better than scope strings but still grows with disclosed claim count rather than producing a constant-size predicate witness.

### 5. Cryptographic Binding to Runtime Model Identity

**Cannot achieve.** `client_id` in a token is a static string registered at the AS. Neither RFC 7662, DPoP, nor BBS+ VCs bind the token to a specific model hash, operator public key, and permission bitmask at the moment of a specific inference call. The agent's runtime identity — what model is executing, under whose operator key, with what permission state committed at call time — is entirely outside the expressive scope of this stack.

### 6. Cross-RS Unlinkability at the AS

**Partially achieved, not fully.** BBS+ presentations are unlinkable at the RS layer. But the AS that issued the credential and signed the original BBS+ credential knows the holder's full permission set and can correlate issuance events across RSes. PPID ([OIDC Core §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)) prevents RS-vs-RS `sub` correlation but explicitly does not prevent AS-level correlation.

---

## Specification Index

| Spec | Function in Baseline | Link |
|---|---|---|
| RFC 7662 | Core introspection | https://datatracker.ietf.org/doc/html/rfc7662 |
| draft-ietf-oauth-jwt-introspection-response | Signed offline introspection | https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/ |
| RFC 8693 | Token exchange / delegation | https://datatracker.ietf.org/doc/html/rfc8693 |
| RFC 8707 | Audience binding | https://datatracker.ietf.org/doc/html/rfc8707 |
| RFC 9449 | DPoP sender constraint | https://datatracker.ietf.org/doc/html/rfc9449 |
| W3C VC Data Model 2.0 | Credential envelope | https://www.w3.org/TR/vc-data-model-2.0/ |
| draft-irtf-cfrg-bbs-signatures | BBS+ selective disclosure | https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ |
| W3C VC-DI BBS+ | BBS+ VC profile | https://www.w3.org/TR/vc-di-bbs/ |

---

**Bar to beat:** Prove, in a single constant-size presentation and without any AS roundtrip, that an agent's permission bitmask satisfies a verifier-specified mask predicate — in a setting where the AS is adversarial and cannot be trusted to attest to the agent's actual permission state.
