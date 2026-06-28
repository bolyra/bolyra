# Baseline — C3: Delegation Audit Without Exposure

## Best Non-ZK Baseline: RFC 8693 Token Exchange + W3C VC/BBS+ Derived Proofs + WIMSE Workload Identity

No single specification handles all dimensions of C3. The strongest plausible non-ZK construction combines three layers:

1. **RFC 8693 OAuth 2.0 Token Exchange** ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)) as the delegation chain primitive — each hop exchanges a `subject_token` plus `actor_token` for a narrowed `access_token`, with `may_act` claims recording the acting party at each step.
2. **W3C VC Data Model 2.0** ([VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/)) with **BBS+ selective disclosure** ([draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/), [VC-DI-BBS](https://www.w3.org/TR/vc-di-bbs/)) as the credential layer — holders reveal only a chosen subset of claims in derived proofs without exposing the underlying signature.
3. **WIMSE s2s protocol** ([draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/)) as the workload binding layer — each agent hop attaches a short-lived JWT SVID cryptographically tied to node attestation, so the chain of participants is at least machine-verifiable even if not hidden.

The auditor-facing artifact would be a WIMSE-attested RFC 8693 delegation token tree, optionally wrapped as a W3C VP with BBS+ selective disclosure to hide individual scope values from the auditor.

---

## What This Baseline CAN Do Against C3

### 1. Reconstruct the delegation chain structure

RFC 8693 embeds a nested `act` claim tree in the final token:
```json
{ "sub": "agent-C", "act": { "sub": "agent-B", "act": { "sub": "agent-A" } } }
```
An auditor with access to the final token sees the full participation chain from root delegator to terminal actor. Each hop is traceable. This satisfies audit trail requirements in regulatory contexts where *who delegated to whom* must be logged.

### 2. Verify that scope was bounded at each hop

RFC 8693 §4 requires the Authorization Server (AS) to enforce that the requested scope on an exchange does not exceed the subject token's scope. The AS rejects expansions. An auditor who trusts the AS policy log can verify, after the fact, that each issued token was a subset of the token it derived from — the AS keeps that record.

### 3. Selective claim disclosure to the auditor via BBS+

A VC issued over the delegation event (scope granted, hop index, timestamp) can be presented to an auditor via BBS+ derived proof. The auditor learns only the claims the holder chooses to reveal — e.g., "scope was narrower than parent" without seeing the numeric scope value, via a range predicate extension.

### 4. Workload-level participant attestation (WIMSE)

Each AI agent hop attaches a WIMSE JWT SVID bound to its host environment. An auditor can verify that each participant was a cryptographically attested workload, not a spoofed identity, without trusting a shared PKI. Federation across trust domains ([draft-ietf-wimse-arch](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)) extends this to cross-org agent handoffs.

### 5. Token binding to prevent replay across hops

RFC 9449 DPoP ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) sender-constrains each token to the agent key that holds it. An auditor can confirm that the token was used only by the attested holder at each hop, preventing a delegated agent from relaying its token to a third party without detection.

---

## What This Baseline Fundamentally CANNOT Do

### 1. Prove monotonic narrowing without disclosing the scopes themselves

The AS policy log records that narrowing happened, but communicating *proof of narrowing* to an auditor without revealing the actual scope values at each hop requires disclosing the token contents or trusting the AS's signed attestation. BBS+ can hide individual claim values, but it cannot prove an ordering relationship (`scope_n ⊆ scope_{n-1}`) over hidden sets without circuit-level set-containment arithmetic. **The baseline has no native mechanism for a zero-knowledge containment proof over hidden bitmasks or scope sets.** An auditor must either see the scope values or trust an AS assertion.

### 2. Hide intermediate participants from the auditor

The RFC 8693 `act` claim tree is plaintext in the token payload. BBS+ can selectively disclose claims within a single credential, but the delegation chain is a *chain of credentials*, not a single multi-message signature. There is no standard mechanism to prove "the chain has N hops and each hop's identity is hidden" without collapsing to a single issuer and re-signing — which destroys the multi-party audit trail. **Intermediate node anonymity in a multi-issuer chain is out of scope for BBS+ as currently specified.**

### 3. Provide auditor assurance without the Authorization Server

RFC 8693 narrowing enforcement lives at the AS. An auditor who does not trust — or cannot query — the AS must take the final token's `act` tree at face value. There is no offline-verifiable proof that each exchange was legitimately narrowed without AS involvement. **The AS is a mandatory trusted third party; its compromise or absence breaks the narrowing guarantee.**

### 4. Prove chain integrity across organizations without a shared AS

Cross-org delegation (e.g., tool calls hopping from an OpenAI agent to an Anthropic agent to a Mistral agent) requires either a shared AS or a federation trust anchor per RFC 8693. WIMSE federation helps with workload attestation but does not provide a unified narrowing-proof authority. **There is no standard that produces a single auditable artifact proving cross-org monotonic narrowing without a common trust anchor that sees all scopes.**

### 5. Support journalist/source-style anonymity in the chain

The WIMSE SPIFFE ID (`spiffe://trust-domain/path`) is a stable identifier visible to any verifier. OIDC Pairwise Subject Identifiers (PPIDs) prevent RS-vs-RS correlation on `sub` but do not prevent the AS or the auditor from correlating via the `act` chain. **There is no mechanism in RFC 8693, BBS+, or WIMSE to prove "a legitimate credential holder participated at hop k" without identifying that holder to the auditor, even probabilistically.**

### 6. Enforce narrowing in-circuit at runtime

The AS enforces narrowing at issuance time. After issuance, a token can be presented to any RS that accepts it — there is no runtime check that the token is being used within its narrowed scope unless the RS independently validates scope against the nested `act` chain. **In-circuit enforcement binding the narrowing proof to the credential's use at presentation time is not a capability of any of these standards.**

---

## Concrete Specifications

| Spec | Function in Baseline | Link |
|---|---|---|
| RFC 8693 | Delegation chain with `act`/`may_act`, AS-enforced narrowing | https://datatracker.ietf.org/doc/html/rfc8693 |
| RFC 7662 | Token introspection for auditor verification | https://datatracker.ietf.org/doc/html/rfc7662 |
| draft-ietf-oauth-jwt-introspection-response | Signed introspection responses for offline audit | https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/ |
| RFC 9449 DPoP | Sender-constraining tokens per hop | https://datatracker.ietf.org/doc/html/rfc9449 |
| RFC 8707 | Audience-bound tokens per tool/service | https://datatracker.ietf.org/doc/html/rfc8707 |
| W3C VC 2.0 | Credential layer for delegation events | https://www.w3.org/TR/vc-data-model-2.0/ |
| draft-irtf-cfrg-bbs-signatures | Selective claim disclosure to auditor | https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ |
| VC-DI-BBS | BBS+ signature suite for VCs | https://www.w3.org/TR/vc-di-bbs/ |
| draft-ietf-wimse-arch | Cross-org workload identity architecture | https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ |
| draft-ietf-wimse-s2s-protocol | Per-hop workload attestation | https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/ |

---

**Bar to beat:** The best non-ZK stack (RFC 8693 + VC/BBS+ + WIMSE) can prove a delegation chain *exists* and was *AS-enforced at issuance*, but cannot prove monotonic scope narrowing to an auditor without disclosing intermediate scopes or participants — any auditor assurance beyond AS trust requires seeing what Bolyra's circuit hides.
