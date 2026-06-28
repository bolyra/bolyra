# Baseline: Strongest Non-ZK Alternative for Delegation Audit Without Exposure

## Candidate Restated

C3 asks whether an auditor can verify that a delegation chain narrowed monotonically at every hop — no hop exceeded its mandate — without reconstructing intermediate scopes or the identities of intermediate participants. The scope extends from enterprise compliance to AI agent pipelines (tool calls as hops) and whistleblower-safe intermediary chains.

---

## Best Non-ZK Alternative

The strongest plausible baseline combines three specifications:

1. **RFC 8693 OAuth 2.0 Token Exchange** as the delegation mechanics layer
2. **W3C VC Data Model 2.0 + BBS+ Selective Disclosure** (draft-irtf-cfrg-bbs-signatures / VC-DI BBS+ 2023) as the credential presentation layer
3. **WIMSE draft-ietf-wimse-s2s-protocol** as the workload-to-workload transport binding

Used together, this stack represents the maximum expressible delegation audit capability without zero-knowledge circuits.

---

## What the Baseline CAN Do

### 1. Delegation chain with scope narrowing (RFC 8693)

RFC 8693 Token Exchange ([https://datatracker.ietf.org/doc/html/rfc8693](https://datatracker.ietf.org/doc/html/rfc8693)) defines `subject_token` + `actor_token` + `requested_scope` → issued token. Each hop exchanges a credential at the Authorization Server (AS), which enforces that the issued scope is a subset of the subject token's scope. The AS can reject any exchange where `requested_scope ⊄ subject_scope`.

**What this gives auditors:** a chain of AS-issued tokens where each token's `scope` claim is a subset of its predecessor. An auditor with access to the token chain (not just the final token) can verify monotonic narrowing by comparing scope strings hop-by-hop.

### 2. Selective disclosure of chain segments (VC + BBS+)

BBS+ ([https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)) allows a holder to derive a Verifiable Presentation from a multi-message credential, revealing only a chosen subset of claims while proving the issuer's signature is valid. Applied to delegation, each hop can receive a VC encoding `{predecessor_scope, current_scope, participant_id, nonce}` and later present a derived proof that reveals only `{predecessor_scope, current_scope}`, withholding `participant_id`.

**What this gives auditors:** scope-to-scope narrowing proofs at each hop without revealing participant identity — provided each hop's VC is constructed with `participant_id` as a hidden message and the auditor is satisfied with per-hop BBS+ derived proofs rather than a single aggregated chain proof.

### 3. Workload-bound transport (WIMSE)

draft-ietf-wimse-s2s-protocol ([https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/)) extends SPIFFE SVIDs to service-to-service calls, binding a workload identity token to the HTTP request via a `Workload-Identity-Token` header and a request-binding proof. In an AI agent pipeline, each tool call hop can carry a WIMSE-bound credential, giving the auditor a chain of workload attestations.

**What this gives auditors:** cryptographic assurance that each hop was executed by an attested workload with a specific SPIFFE ID, without requiring human-in-the-loop token exchange.

---

## What the Baseline FUNDAMENTALLY CANNOT Do

### 1. Hide intermediate scopes from the auditor

BBS+ selective disclosure can hide `participant_id` but it cannot hide the scope values themselves while still allowing the auditor to verify narrowing. Narrowing verification requires the auditor to see (or compute over) predecessor scope and successor scope at each hop. To prove `scope_n ⊆ scope_{n-1}` without revealing either scope, the auditor must receive a predicate proof — BBS+ does not natively produce subset-predicate proofs over hidden string-valued claims. Range proofs apply to integers; scope bitmask containment requires Boolean circuit evaluation.

**Absence explicitly named:** BBS+ cannot prove `(current_bitmask & predecessor_bitmask) == current_bitmask` over hidden bitmask values.

### 2. Hide intermediate participants from the auditor while maintaining chain integrity

BBS+ can hide `participant_id` in an individual derived proof. But the chain is only as strong as the binding between hops: the auditor must verify that `hop_n`'s predecessor credential was issued to the same entity that presented it at `hop_{n+1}`. Without revealing the participant identity, this binding collapses. A participant could swap in a different valid BBS+ credential at hop N+1 and the auditor cannot detect it without seeing the linking information. This is the linkability-vs-auditability wall: selective disclosure breaks chain-of-custody verification when the linking attribute is the hidden one.

**Absence explicitly named:** BBS+ provides multi-presentation unlinkability within a single credential, not cross-credential chain integrity with participant hiding.

### 3. Prove monotonic narrowing across the full chain in a single verifiable artifact

RFC 8693 produces per-hop tokens. BBS+ produces per-hop derived proofs. Neither produces an aggregated proof that the entire chain from root to leaf narrowed monotonically. An auditor must process O(n) artifacts for an n-hop chain. There is no single digest that commits to chain structure and narrowing without exposing chain contents. Aggregated proof structures over delegation chains are not defined in any current RFC or W3C specification.

**Absence explicitly named:** no RFC or W3C spec defines a single verifiable artifact that proves ∀i: scope_i ⊆ scope_{i-1} across n hops without enumerating intermediate scopes.

### 4. Conceal chain length or graph structure

When the auditor receives per-hop proofs or tokens, the number of hops is visible from the artifact count. The branching structure of a multi-path delegation tree (e.g., one principal delegates to three independent tools) is visible from the token graph. No RFC 8693 or BBS+ mechanism hides chain length or graph topology.

**Absence explicitly named:** circuit-private chain length is undefined in the non-ZK baseline.

### 5. Guarantee AS-blind auditing

RFC 8693 requires the AS to mediate every hop exchange. The AS sees every `(subject_token, actor_token, requested_scope, issued_scope)` tuple for every hop. An auditor that relies on AS-signed records is relying on AS honesty. A malicious or subpoenaed AS can reconstruct the full delegation chain — participants, scopes, timing — for any exchange it mediated. This is not a configuration option; it is structural.

**Absence explicitly named:** AS-blind delegation is impossible under RFC 8693 because the AS is the narrowing enforcer.

### 6. Whistleblower-safe intermediary concealment

In the journalist/source scenario, intermediate nodes must be hidden not just from the final verifier but from the auditor and from each other in the paper trail. WIMSE binds workload identity to each hop; that identity is visible to the WIMSE verifier. BBS+ hides `participant_id` from a given verifier but the issuer of the BBS+ VC at each hop knows the participant it issued to. No combination of these standards provides a mechanism for a neutral auditor to verify chain integrity while every node is cryptographically hidden from everyone who did not participate directly at that hop.

**Absence explicitly named:** intermediary anonymity with chain integrity verification is not expressible in RFC 8693, BBS+, or WIMSE, individually or combined.

---

## Relevant Specifications

- RFC 8693 Token Exchange: [https://datatracker.ietf.org/doc/html/rfc8693](https://datatracker.ietf.org/doc/html/rfc8693)
- RFC 7662 Token Introspection: [https://datatracker.ietf.org/doc/html/rfc7662](https://datatracker.ietf.org/doc/html/rfc7662)
- RFC 9449 DPoP: [https://datatracker.ietf.org/doc/html/rfc9449](https://datatracker.ietf.org/doc/html/rfc9449)
- BBS+ Signatures: [https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- VC-DI BBS+ 2023: [https://www.w3.org/TR/vc-di-bbs/](https://www.w3.org/TR/vc-di-bbs/)
- W3C VC Data Model 2.0: [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
- WIMSE Architecture: [https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)
- WIMSE S2S Protocol: [https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/)
- SPIFFE: [https://spiffe.io/](https://spiffe.io/)

---

**Bar to beat:** produce a single, aggregated, auditor-verifiable proof that ∀i: scope_i ⊆ scope_{i-1} across an n-hop delegation chain, where neither the intermediate scope values, the intermediate participant identities, nor the chain length are revealed to the auditor.
