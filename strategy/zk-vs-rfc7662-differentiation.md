# ZK vs RFC 7662 — Does Bolyra Actually Beat Plain OAuth Introspection?

**Date:** 2026-04-21 (original) / 2026-04-22 (revised with autoresearch results)
**Purpose:** Resolve the load-bearing question raised by codex Round 2 pushback. If ZK does not deliver a measurable privacy/audit/compliance gain over ordinary RFC 7662 opaque-token introspection, the Bolyra-as-AS wedge collapses.

---

## 2026-04-22 revision — autoresearch verdict

Ran the `differentiation-autoresearch` loop: 7 candidates × up to 7 iterations, 5-persona Tier 3 adversarial scrutiny (rfc7662_advocate, auth0_pm, spiffe_engineer, cryptographer, cu_ciso), 5-dim × 2-pt rubric. See `differentiation-autoresearch/history/convergence_report.md` for full data.

**Empirical peaks under adversarial scrutiny:**

| Candidate                                        | Prior claim | Empirical peak | Winner? |
|--------------------------------------------------|-------------|----------------|---------|
| C1 Selective scope proof                         | 4/10        | 6/10           | no      |
| C2 Cross-scope unlinkability                     | 9/10        | **8/10**       | **yes (secondary)** |
| C3 Delegation audit without exposure             | 7/10        | 6/10           | no      |
| C4 Issuer-blind attribute predicates             | 9/10        | 5/10           | no      |
| C5 Bolyra as MCP auth, generally                 | ruled out   | 5/10           | no      |
| **C7 Cryptographic model-instance binding** (new) | —           | **9/10**       | **yes (primary)** |
| C9 Forward-secure agent delegation (new)         | —           | 5/10           | no      |

**Two findings the original doc got wrong:**

1. **C4 did NOT hold up at 9/10.** Under persona scrutiny, issuer-blind predicates overlap too heavily with W3C VC + BBS+ selective disclosure to clear `baseline_dominance`. Peak: 5/10.
2. **The strongest Bolyra wedge was missing from the original doc: C7 (cryptographic model-instance binding).** This is the agent-economy-native property that RFC 7662 + RFC 8693 + DPoP + WIMSE + BBS+ cannot match. 9/10 confirmed.

**Ceiling note:** 10/10 is unreachable under pure-ZK. C7's last point on `adversarial_survival` requires TEE integration (runtime execution binding, not just authorization binding). See `differentiation-autoresearch/history/convergence_report.md` §"Why 9/10 is the ceiling."

---

## Baseline: what RFC 7662 actually gives you

RFC 7662 (OAuth 2.0 Token Introspection) is a simple primitive:

1. Agent presents opaque bearer token to Resource Server (RS)
2. RS POSTs the token to the Authorization Server's (AS) `/introspect` endpoint
3. AS returns JSON metadata: `{active, scope, client_id, sub, aud, exp, iat, ...}`
4. RS makes auth decision from the response

Variants and extensions worth naming before arguing ZK is better:
- **draft-ietf-oauth-jwt-introspection-response**: AS can return a signed JWT instead of JSON, enabling offline cacheable introspection
- **Scope-limited responses**: AS is free to return a minimal subset of token metadata per RS (policy choice at the AS)
- **Per-RS audience binding (RFC 8707)**: tokens can be bound to a specific audience so cross-RS replay fails
- **Token exchange (RFC 8693)**: supports delegation with narrowed scope; each hop produces a fresh token
- **Sender-constrained tokens (DPoP, mTLS)**: tokens bound to a key to prevent replay

This baseline is the bar Bolyra must clear.

---

## The four candidate differentiators

### Candidate 1 — Selective scope proof

**Claim:** "Agent proves it has scope X without revealing full permission set to RS."

**Honest evaluation:**
- RFC 7662 already lets the AS return a minimal scope set per RS. The AS is a trusted party that decides what to disclose. Practically, if the AS policy says "when RS_A introspects a token, only tell it whether `read:foo` is present," that works.
- BUT: this requires the AS to know about every RS and make a policy decision. With ZK, the agent proves `(permissionBitmask & requiredMask) == requiredMask` to the RS directly. **No AS in the hot path.**
- JWT introspection response (offline verification) also removes AS from the hot path, but the JWT contains the full scope claim set that's been selected at issuance time — it can't adapt to the RS's specific ask.

**Verdict:** ZK wins **architecturally** (no AS roundtrip, agent-chosen disclosure at presentation time), but a well-configured AS with per-RS scope policies gets close. **Not a killer differentiator on its own.** Strength: 4/10.

### Candidate 2 — Cross-scope unlinkability

**Claim:** "Same agent accessing different RS instances produces unlinkable introspection responses."

**Honest evaluation:**
- RFC 7662 baseline: if the agent uses the same opaque token at multiple RSes, the AS sees every introspection call — the AS can trivially correlate which agent is talking to which RSes and when. This is AS-side surveillance by default.
- Even with per-RS audience-bound tokens (RFC 8707), the AS is the issuer of all of them and still sees the full topology.
- Pairwise subject identifiers (OIDC PPID) help against RS-vs-RS collusion but NOT against the AS.
- With Bolyra: per-scope nullifier construction — `nullifier = Poseidon(scope_id, secret)` — means the same agent produces a different public output per RS. Nullifier set does not reveal cross-RS linkage. And because verification can happen on-chain or locally against a Merkle root, **the AS doesn't see which RS the agent is talking to.**

**Verdict:** **Genuine ZK advantage that RFC 7662 cannot deliver.** The centralized AS in vanilla OAuth is a surveillance point by construction. ZK breaks that. Strength: 9/10.

### Candidate 3 — Delegation chain auditability without exposure

**Claim:** "Auditor can verify delegation narrowing happened without reconstructing the chain."

**Honest evaluation:**
- RFC 7662 + RFC 8693 (token exchange) supports delegation. Each hop mints a fresh token with narrower scope. Audit trail lives at the AS and contains the full chain: who delegated to whom with what scope at each hop.
- For most deployments this is fine — auditors want the full chain. But for some regulated scenarios (healthcare chain-of-custody, financial delegation with carrier-of-record rules, cross-jurisdiction agent delegation), revealing intermediate scopes or intermediaries to the final verifier is a compliance leak.
- Bolyra delegation: each hop produces a PLONK proof linking `scopeCommitment_i` to `scopeCommitment_{i+1}` with `(delegator & delegatee) == delegatee` enforced in-circuit. The public record shows that a valid narrowing happened; the intermediate bitmasks are not revealed.

**Verdict:** **Genuine ZK advantage for a narrow set of regulated scenarios.** Most deployments won't care. But when it matters (HIPAA-adjacent, cross-border financial delegation, whistleblower-safe delegation audits), nothing in vanilla OAuth can do this. Strength: 7/10.

### Candidate 4 — Regulated attribute predicates

**Claim:** "Agent proves 'belongs to an NCUA-chartered credit union' without revealing which CU."

**Honest evaluation:**
- RFC 7662 baseline: AS returns attribute like `cu_chartered: true`. But the AS IS the CU — every introspection call to that AS reveals which CU's AS is being hit. Cross-CU verifiers now know which CU the member belongs to, even though that wasn't the question asked.
- OIDC claims + pairwise subjects don't fix this at the issuer-identity level; the issuer's identity is visible in the token/introspection response by construction.
- Verifiable credentials (W3C VC) with BBS+ / ZK selective disclosure handle this cleanly, and that's the neighborhood Bolyra lives in. An agent holds a credential issued by a CU, then proves a predicate (`chartered_by_NCUA == true`) to a verifier without the verifier — or the original issuer — learning which CU signed.
- Bolyra maps this to: credential commitment as Merkle leaf, membership proof against a cross-CU registry Merkle root, predicate satisfied in-circuit, only the predicate result and nullifier leak.

**Verdict:** **Genuine advantage, strongest in regulated multi-issuer ecosystems.** Credit unions, healthcare networks, agent-on-behalf-of-corp scenarios. RFC 7662 cannot do this because the AS identity is definitionally exposed. Strength: 9/10.

---

## Summary table

| Candidate | Strength | Can RFC 7662 do it? | Key differentiator |
|---|---|---|---|
| 1. Selective scope proof | 4/10 | Partially (AS policy + JWT response) | No AS in hot path; runtime-adaptive disclosure |
| 2. Cross-scope unlinkability | 9/10 | **No** | Breaks AS-side surveillance, per-scope nullifier |
| 3. Delegation audit without exposure | 7/10 | **No** (for regulated cases) | Intermediate bitmasks hidden; narrowing proven |
| 4. Regulated attribute predicates | 9/10 | **No** | Multi-issuer, issuer-blind verification |

---

## What this means for strategy

The honest answer to codex's load-bearing question: **Yes, ZK beats RFC 7662 — but not on #1 (selective scope), which was the weakest framing.** The real advantages are:

1. **Unlinkability against the AS itself** (#2). The AS in vanilla OAuth is a surveillance point by construction. This is not fixable inside RFC 7662.
2. **Multi-issuer / issuer-blind predicates** (#4). Verifiable-credential-shaped scenarios where the verifier shouldn't learn the issuer's identity.
3. **Niche but real: regulated delegation audit** (#3).

**#1 should be dropped from the pitch.** It invites the "just tweak your AS policy" rebuttal and muddies the real argument.

## Refined wedge

> **Bolyra = the OAuth 2.1 Authorization Server for deployments where the AS itself must not see the verifier-agent traffic graph, and where issuer-blind attribute proofs are a regulatory requirement.**

That is a narrow, defensible wedge. It rules out Big Tech internal-only agent auth (where the AS is already trusted and centralized). It rules IN:
- Cross-credit-union agent identity (NCUA-chartered predicate, no CU learns member's merchant graph)
- Healthcare agent delegation (HIPAA-adjacent, chain narrowing without exposure)
- Cross-firm financial agents (regulated attribute proofs without counterparty disclosure)
- Any multi-issuer ecosystem where the issuer is a regulated entity and the ecosystem needs unlinkability

## What this rules out

- "Bolyra as MCP auth, generally." Too broad. Auth0/WorkOS/Stytch win on the general case because operators don't need the privacy properties and DO need the ecosystem integrations.
- "Bolyra because selective scope is better." Weakest argument. Drop it.
- "Bolyra as Anthropic-side infrastructure." Anthropic runs centralized services. The AS-surveillance concern doesn't apply inside Anthropic's own boundary.

## What this rules in

- **Credit union first deployment** (GeniusComply channel). This is the scenario where all three genuine advantages (#2, #3, #4) converge. One CU deploying Bolyra as their member-facing agent AS gives the reference architecture.
- **ext-auth contribution scoped to "unlinkable introspection"** (Mode B of the IETF 1-pager). This is the protocol-visible behavior that justifies ext-auth as the right venue.
- **KLRC §10.8 addendum framed as "issuer-blind agent identity,"** not "ZK everywhere."
- **AAIF privacy WG as the standards home.** Right venue for privacy-against-the-IdP arguments.

---

## Outstanding technical questions before outreach

1. **AS-side performance under nullifier verification.** If every RS call still hits some registry to check nullifier freshness and Merkle root currency, how is that better than a fast introspection cache? Answer must show the trust model difference, not just the latency.
2. **Revocation in the unlinkable model.** If the AS can't link agent → RS calls, how does revocation propagate? Nullifier set growth and gossip protocol needs a concrete story.
3. **On-chain vs off-chain registry.** Codex flagged chain-in-critical-path as a dealbreaker. Need an off-chain default with chain as optional audit anchor, not the other way around.
4. **Key custody for the human side.** Groth16 human proofs require a secret held by the human. For credit union members this must not be "another wallet" — needs to ride on existing CU authentication factors.

These are engineering questions, not strategy questions. They get answered in the reference implementation, not the pitch.

---

## Bottom line

The wedge survives, but narrower than originally framed. The strong arguments are **unlinkability against the AS** and **issuer-blind attribute proofs**. The weak argument (selective scope) should be dropped. Credit union deployment via GeniusComply is the cleanest way to prove all three advantages converge in one regulated scenario. Standards work (ext-auth, KLRC §10.8, AAIF) should cite the CU deployment as evidence, not lead with theory.
