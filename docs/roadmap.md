# Bolyra product roadmap

**Revised 2026-08-31 (supersedes the 2026-08-19 revision; Codex-reviewed). Operator's roadmap for a solo pre-revenue founder — sequenced motions to reach the first externally-owned usage, not a feature-build list.** Living doc; revise as gates resolve. Companion docs: `docs/customer-plan-14day.md` (the Now-horizon executable), `drafts/operator-call-targets-2026-08-27.md` (the ranked ask list), `strategy/product-strategy-2026-07.md` (the layered product thesis — unchanged).

## The frame (unchanged, now with receipts)

The product is ~shipped and the **standards leg is now proven**: EVC v1 stable with a live IETF -01; a published conformance suite (`@bolyra/evc-conformance@0.2.0`, provenance-attested); and — the existence proof the 8/19 revision was waiting for — **an independent maintainer implemented the host boundary from the spec text alone and passed 27/27 at a pinned public commit** (khandrew1/mcp-use-evc-example, listed in `spec/IMPLEMENTER.md` §9 with permission). The binding constraint is unchanged and is now the ONLY constraint: **zero buyer pull** — as of this revision (2026-08-31, per the engagement graph's revenue line — re-verify against the call log at the 9/03 gate): 0 pilot conversations, 0 signed pilots, $0 ARR. Every horizon below converts credibility → usage → paid; building ahead of demand stays frozen.

## North Star (unchanged)

**One named external party runs a Bolyra authorization primitive in an externally-owned agent/payment flow where an action is allowed or blocked based on a mandate before execution.**

Leading indicators: a named workflow + integration owner; an external PR/branch where Bolyra is on the execution path; 3+ real decision receipts from that flow.

## State of the gates (2026-08-31)

| Gate | State |
|---|---|
| Second independent EVC implementer (dated-check half 1) | **MET 2026-08-26** — khandrew1, 27/27 pinned at `17642a5`, maintainer permission on record |
| x402 home (dated-check half 2, deadline 2026-09-21) | **OPEN** — #3230 final review-cost note armed to fire 2026-08-31 10:00 ET (update this row with posted / skipped-for-engagement / routed once it resolves); the profile implementation + demo are shipped in-repo (`spec/x402-evc-profile-v0.md`, `integrations/payment-protocols/src/x402-evc.ts`, `examples/x402-evc-profile/`), and a standalone package shape is additionally staged on a local unpushed branch — any routing verdict is answerable same-day |
| Day-14 operator-call gate | **Thu 2026-09-03** — one real operator call booked/completed, else the market-access path is declared not working (see fork below) |
| Platform build | **FROZEN** (Codex 2026-08-27 re-ruling) — no hosted control plane / policy engine / audit portal until a signed pilot or named-workflow commitment; if one lands, the build is partner-specific only (one workflow, one enforcement point, receipts, observability; NO dashboard/self-serve/billing/tenant model) |
| Patent counsel | **Scheduled**: cash-capped triage ask to 2–3 attorneys AFTER 9/03 — what NP claims are supportable for 2027-04-20, what must stay RF; full drafting only on operator traction or a deadline risk |

## Now (through 2026-09-03) — the operator-call sprint

The 8/19 revision's "OPEN CONFLICT" (buyer-discovery channel vs retired cold outreach) was **resolved by the customer plan (2026-08-20)**: maintainer intros → revettr close-loop → Anthropic Startups routing → bounded 12-email cold re-test (≤120w, diagnostic ask, kill at <3 replies/<2 calls). The executable is `drafts/operator-call-targets-2026-08-27.md` — ten ranked targets with verbatim asks; khandrew1/Manufact is #1 (he is now simultaneously the warmest node AND an operator archetype). The demo is click-only linkable (transcript gist, captured 2026-08-29) and runnable (`npx -y @bolyra/mpp@latest demo`).

**Falsification scoreboard** (fill for every candidate operator; conceptual agreement does not count — a named operator-owned accept/reject workflow does):
- Named workflow?
- Current accept/reject owner?
- Existing pain, or concrete near-term risk?
- Current workaround?
- Would mandate evidence change a decision?
- Will they supply sample decisions?
- Will they run Bolyra in staging?
- Would they pay, or is this only ecosystem hygiene?

**Nothing else enters this horizon.** Explicitly parked this week: khandrew1 CI PR (his PR #2 unreviewed), all vendor partnerships (Redis ruling 2026-08-30: five revisit triggers, all downstream of pull), all M&A positioning (Bun lesson: dependencies get acquired, propositions get evaluated).

## The 9/03 fork (write the branch down BEFORE the gate)

- **Gate passes** (≥1 real operator call): the market-access path stays alive — but a problem call is NOT a named yes. Enter Next only when a call produces a named workflow, an accept/reject owner, and an integration path. The call itself is diagnosis, not pitch: their accept/reject owner, failure modes, current logging, what a mandate gate would change, what makes a 30-day pilot worth it. Score every candidate on the falsification scoreboard above.
- **Anti-escape guard:** no fork review starts before ALL required warm asks, the Anthropic routing ask, and the 12-email fallback are actually executed — or 2026-09-03 EOD arrives, whichever is first. The fork is a pre-commitment, not permission to quit the sprint early.
- **Gate fails** (all of the above executed, zero booked calls): **the wedge's market-access path is declared not working. Do not compensate with more protocol.** The pre-committed response is a wedge-downgrade review: keep the standards asset warm (it compounds unattended), and run a sharper-wedge search with Codex — candidate directions to test, not presume: consumer mandate surface via Malkolm design-partnership; seller-side receipts-as-data (revettr's gate-2 thesis); ZK-lane differentiation where classical verification legally cannot satisfy (the uncontested APS gap). A failed gate is evidence about the wedge, not about the technology.

## Next — produce usage evidence (gate: a named yes)

Unchanged in substance from 8/19; entry gate: a named person, workflow, repo/system, integration owner, success criteria ("nice project" does not count).

1. Handhold the first integration until it executes a real authorize/deny path.
2. Tighten ONLY what blocks the integration (docs, adapter, CLI, receipt example, fixture) — nothing speculative. This includes storage adapters (e.g., a Redis nonce-store) — one-day builds on pull, never ahead of it.
3. Package the outcome as evidence: decision receipts, before/after flow, integration notes — feeding the **buyer-proof evidence ledger** (acquirability thread, Codex 2026-08-30: every claim third-party-verifiable, the khandrew1 pattern generalized).
4. Conformance work only around what the integration exercises. If maintainers route #3230, the in-repo profile work (plus the locally staged package shape) ships in whatever form they picked — that is Next-horizon work with an external owner, not a standards campaign.

## Later — convert evidence to a paid pilot (gate: usage evidence exists)

1. Price the narrow thing they already use. The $25k/90-day design-partner shape exists (`docs/pilot/design-partner-brief.md`).
2. Build hosted ops ONLY if the pilot requires it — and then only the Codex-ruled minimal slice (2026-08-27): one workflow, one enforcement point, partner token, policy config, receipts, day-one observability, JSONL export. Explicitly out even then: dashboard, self-serve, billing, tenant model, policy-builder UI, SSO, SLA, hosted ZK.
3. Standards leg on autopilot: -02 revision when there is implementation news worth an RFC 7942 update; conformance-authority definition (what "EVC-conformant" means, compatibility-mark question) as a low-bandwidth acquirability-thread item.
4. Non-provisional patent decision per the counsel triage — before 2027-04-20, shaped around operating proof, without letting IP become product strategy.

## Do not build (and the trigger to unfreeze)

| Frozen lane | Why | Unfreeze trigger |
|---|---|---|
| Hosted control plane / policy engine / audit portal | Fake enterprise software without a buyer | Signed pilot explicitly needs hosted ops / non-dev users / policy mgmt / audit review — then minimal slice only |
| More package surfaces | Artifacts hide the real problem: no adoption | First partner integration blocked by a missing adapter (the staged x402-evc ships only on #3230 routing) |
| Vendor partner programs (Redis et al.) | Channel programs monetize partners WITH customers; logo-theater risk | The five 2026-08-30 triggers: customer asks for the integration; named technical owner + named account; deployed customer story; a governance/authz marketplace category; twice-independent adapter requests |
| M&A positioning as an active motion | Dependencies get acquired, propositions get evaluated (Bun, Dec 2025); premature buyer-talk poisons the Malkolm IP-carveout posture | Standing low-bandwidth hygiene only: evidence ledger, IP data room, conformance-authority definition |
| Chain / Base / default token work | Confuses the wedge | A paying workflow requires settlement-layer verification AND preserves the wedge |
| Listing / awesome / example PRs | Activity without conversion | A maintainer requests it inside an accepted integration |
| Public-reply / cold-DM motion | Retired (17 DMs → 1 reply) | Only the bounded 12-email diagnostic re-test in the customer plan, warm asks first |
| ZKProva / speculative ZK mainnet | The buyer problem is not ZK availability | A partner needs privacy properties classical verification cannot satisfy — note this is also the sharpest anti-APS lane if the wedge downgrades |

## Biggest risk and honest failure mode (unchanged, sharpened)

The wedge may be **admired by maintainers but not urgently bought**. This month proved the admiration half beyond doubt — a maintainer implemented the spec unprompted, a competitor peer-reviews our receipts design, the reference repos merge our fixes same-day. None of that moved the revenue line, which is exactly why the 9/03 gate and its pre-committed fork exist. The standards asset compounds while parked; the wedge hypothesis does not get more true by being polished. Warmth is never mistaken for a market — the scoreboard question stays: *named operator-owned accept/reject workflow, or it doesn't count.*
