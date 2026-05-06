# Baseline for C3: Delegation Audit Without Exposure

## Best Alternative: RFC 8693 Token Exchange + JWT Introspection Response + BBS+ Selective Disclosure VCs

No single standard covers C3's claim. The strongest non-ZK construction layers three specifications: **RFC 8693 OAuth 2.0 Token Exchange** as the delegation primitive, **draft-ietf-oauth-jwt-introspection-response** as the auditable proof artifact, and **W3C VC + BBS+ (draft-irtf-cfrg-bbs-signatures)** for selective disclosure over credential attributes. A WIMSE workload identity layer (draft-ietf-wimse-s2s-protocol) provides hop-level binding for the AI pipeline scenario. Together these represent the current ceiling for non-ZK delegation audit.

---

## What the Baseline CAN Do

### 1. Represent a delegation chain with scope narrowing

RFC 8693 §4.4 defines the `may_act` and `act` claims for actor tokens. Each hop POSTs a `subject_token` (the prior-hop token) plus an `actor_token` (the requesting workload's identity) to the Authorization Server (AS). The AS issues a new token whose `scope` is the intersection of what was requested and what the subject held. This is a chain: each token in the chain references its predecessor via the `act` claim (a nested JSON object encoding the full actor chain).

A final token in a three-hop chain carries a nested `act` structure like:
```
act: { sub: "tool-B", act: { sub: "tool-C" } }
```

This chain is machine-readable and auditable by any party who receives the final token.

**Spec:** RFC 8693 §4.4 — https://datatracker.ietf.org/doc/html/rfc8693#section-4.4

### 2. Produce a signed, offline-verifiable audit artifact

Using draft-ietf-oauth-jwt-introspection-response, the AS returns a signed JWT for each hop's token. An auditor can collect the sequence of signed JWTs — one per hop — and verify the chain offline without querying the AS again. Each JWT carries the `iss`, `sub`, `scope`, `act`, `iat`, and `exp` of that delegation step. The AS signature on each JWT provides cryptographic non-repudiation: the AS attested to the scope at that hop.

**Spec:** draft-ietf-oauth-jwt-introspection-response — https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/

### 3. Selectively disclose individual scope strings to the auditor

The VC+BBS+ profile (W3C VC-DI BBS+) can encode the scope of each delegation step as a credential claim, with BBS+ selective disclosure allowing the auditor to see only the claims relevant to their mandate — for example, whether `scope_at_hop_3 ⊆ scope_at_hop_2` — while the holder conceals other claims.

BBS+ derived proofs are unlinkable across presentations of the same credential, so re-auditing does not correlate to a specific internal log entry.

**Specs:** W3C VC 2.0 — https://www.w3.org/TR/vc-data-model-2.0/ | BBS+ — https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ | VC-DI BBS+ — https://www.w3.org/TR/vc-di-bbs/

### 4. Bind each hop to a workload identity

WIMSE draft-ietf-wimse-s2s-protocol provides per-hop cryptographic workload identity (SPIFFE SVIDs or equivalent) bound to the delegation token at each step. An auditor verifying the chain can confirm that each hop was executed by a legitimate, attested workload. This addresses the AI pipeline scenario where each hop is a tool invocation rather than an organizational boundary.

**Spec:** draft-ietf-wimse-s2s-protocol — https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/

### 5. Scope-narrow at each hop without final-token holder seeing prior scopes

The AS can be configured with RS-specific introspection filtering: per draft-ietf-oauth-jwt-introspection-response, the AS tailors the JWT response to the requesting RS. An auditor-RS sees only what the AS policy allows it to see. This is AS-enforced, not cryptographically enforced.

---

## What the Baseline Fundamentally CANNOT Do

### 1. Hide intermediate participants from the auditor

The `act` chain in RFC 8693 §4.4 is fully disclosed to any party holding the final token — including the auditor. Intermediate `sub` values (tool identities, user identities, organizational identities) are in plaintext. There is no mechanism to prove "a chain of N hops existed and narrowed" without enumerating all N actors. For C3's journalist/source scenario — where intermediate nodes must stay hidden — RFC 8693 has no capability here at all.

**Absence explicitly named:** RFC 8693 provides no participant-hiding primitive. The `act` nesting is disclosure-by-design.

### 2. Prove monotonic narrowing without disclosing the scopes

The baseline can reveal all scopes (full disclosure) or hide them (zero disclosure). It cannot prove the predicate `scope[i+1] ⊆ scope[i]` for all i without revealing `scope[i]` and `scope[i+1]`. BBS+ selective disclosure operates at claim granularity — it can reveal or hide a scope string as a whole, but it has no native predicate logic for set containment. Proving containment would require the auditor to see both scopes.

**Absence explicitly named:** No RFC or BBS+ extension supports proving set-containment over hidden attribute values. The BBS+ range proof extension addresses numeric ranges, not semantic scope sets or permission bitmasks.

### 3. Prove chain integrity without AS participation or AS trust

The entire baseline is AS-mediated. The AS sees every `token_exchange` call, knows every intermediate scope, and knows every actor identity. A compliant AS can enforce narrowing and generate the audit trail — but the auditor's assurance is only as strong as their trust in the AS. If the AS is compromised or adversarial, it can fabricate narrowing proofs. There is no cryptographic construction in RFC 8693, JWT introspection response, or BBS+ that makes the narrowing proof AS-independent.

**Absence explicitly named:** The baseline produces AS-attested audit artifacts, not verifier-checkable proofs of narrowing.

### 4. Provide unlinkability across audit events

OIDC Pairwise Subject Identifiers prevent RS-to-RS correlation on `sub`, but the AS generates all PPIDs and can correlate freely. BBS+ presentations are unlinkable holder-to-verifier, but in a delegation audit the AS is always the issuer and sees the full chain at issuance time. An auditor performing repeat audits, or two auditors comparing notes, can correlate chain-level identifiers because the audit artifact (the signed JWT chain) is deterministic — the same delegation event produces the same signed tokens.

**Absence explicitly named:** BBS+ unlinkability applies to re-presentation of a held credential, not to independently-issued audit tokens from RFC 8693.

### 5. Enforce narrowing in-circuit at hop execution time

The baseline enforces narrowing at the AS as a policy decision: the AS simply refuses to issue a token whose scope exceeds the subject's scope. This is correct-if-AS-is-honest. There is no mechanism by which the auditor, after the fact, can verify that AS enforcement occurred without trusting the AS's logs. In-circuit enforcement — where the math itself proves that the delegation could not have been constructed without narrowing — is not possible without a ZK construction.

**Absence explicitly named:** RFC 8693's narrowing guarantee is an AS policy obligation, not a cryptographic invariant checkable by a third party.

### 6. Support the whistleblower/journalist scenario in any form

The journalist/source scenario requires that intermediate nodes in the delegation chain be hidden from the auditor while the auditor still gains assurance that the chain is legitimate and narrowing. This is structurally impossible in RFC 8693 — the `act` claim is the audit record, and hiding it defeats the purpose. BBS+ can hide claims but cannot prove predicates over hidden claims that span multiple linked credentials without revealing the linking. WIMSE binds workload identity but does not anonymize it. No combination of these standards approaches this use case.

**Absence explicitly named:** None of RFC 8693, draft-ietf-oauth-jwt-introspection-response, BBS+, or WIMSE has a participant-hiding delegation proof model. This use case has no non-ZK standard addressing it.

---

## Sources

- RFC 7662 Token Introspection: https://datatracker.ietf.org/doc/html/rfc7662
- RFC 8693 Token Exchange: https://datatracker.ietf.org/doc/html/rfc8693
- RFC 8707 Resource Indicators: https://datatracker.ietf.org/doc/html/rfc8707
- RFC 9449 DPoP: https://datatracker.ietf.org/doc/html/rfc9449
- draft-ietf-oauth-jwt-introspection-response: https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/
- W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- BBS+ Signatures: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- VC-DI BBS+: https://www.w3.org/TR/vc-di-bbs/
- WIMSE WG: https://datatracker.ietf.org/wg/wimse/about/
- draft-ietf-wimse-arch: https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
- draft-ietf-wimse-s2s-protocol: https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/

---

**Bar to beat:** Prove that every hop in a delegation chain narrowed monotonically, without revealing any intermediate scope value or participant identity to the auditor, and without requiring the auditor to trust the Authorization Server's word.
