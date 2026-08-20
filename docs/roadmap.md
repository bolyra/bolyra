# Bolyra product roadmap

**Built with Codex, 2026-08-19 (2 rounds). Operator's roadmap for a solo pre-revenue founder — sequenced motions to reach the first externally-owned usage, not a feature-build list.** Living doc; revise as the Now-horizon gates resolve.

## The frame

The product is ~shipped (EVC v1 stable; `@bolyra/mpp` mandate gate; `@bolyra/receipts`; `bolyra verify` reference verifier; `hosted-verify` preview; SDKs). The binding constraint is **not more features** — it is **zero external usage and zero pilots**. So this roadmap is motions to convert warmth → usage → paid, with product work kept narrow and gated on a specific partner needing it. Building ahead of demand stays frozen.

## North Star

**One named external party runs a Bolyra authorization primitive in a externally-owned agent/payment flow where an action is allowed or blocked based on a mandate before execution.** (Not a formal "design partner" label — externally-owned usage is the point.)

Leading indicators:
- 1 party commits to a named workflow, repo, and integration owner.
- 1 external PR/branch/example where Bolyra is on the **execution path**, not just documented.
- 3+ real decision receipts from that flow proving mandate-enforcement behavior.

## Buyer hypothesis

The buyer is the **seller-side agent-payment risk / acceptance operator** — whoever owns *"should this merchant/API accept this agent-originated action or payment?"* Revettr is the clearest live example; the archetype is broader.

Why the pain is urgent: domain reputation, wallet reputation, and protocol compliance do **not** prove a specific agent action was *authorized*. Their accept/reject decision becomes defensible if they can say: this agent had a valid credential, this action matched a mandate, and here is a signed receipt the seller can keep. That maps directly onto Bolyra's assets:
- **EVC verifier** → proves the actor/credential.
- **MPP mandate gate** → proves the action/payment was allowed *before* execution.
- **ES256K receipts** → portable evidence *after* execution.

So maintainers are the **channel**; seller-side acceptance operators are the **market**. The Now horizon is a test of this hypothesis.

## Now — convert warmth into a named workflow

Success: one credible external party agrees to run Bolyra in a specific flow they own or influence. Priority order, with falsifiable gates:

| # | Workstream | Time-box | Advance signal | Kill / deprioritize |
|---|---|---|---|---|
| 1 | **Buyer validation via the 2 warm maintainers** (x402-foundation `phdargen`, qntx/r402 `gitctrlx`) — a reference-integration/where-does-this-fit ask, not another bug-fix ask | 10 business days; first ask within 48h, max one follow-up each | A maintainer names a specific acceptance/risk owner, makes an intro, or says mandate/receipt evidence belongs in an x402/r402 accept-reject path. Strong: both independently point to seller-side risk as the pain center | Both stay at "interesting protocol idea" with no named operator / no transaction path / no willingness to run evidence → maintainers become standards+channel only, not market evidence |
| 2 | **Generic seller-side acceptance demo** — verify credential, check mandate, emit signed receipt/evidence JSON for an x402/r402-style action. **Generic, NOT a revettr build** | 3 focused dev days, max 5 calendar | Demo produces an artifact that revettr / a maintainer / a referred operator agrees to discuss against a real accept-reject decision (external engagement, not just existence). Do not extend past the fixed demo envelope without a named operator pull | Needs revettr-specific APIs/data, exceeds 5 days, or becomes a custom product for one silent lead → stop |
| 3 | **Revettr re-entry** — only after the demo exists; the demo is the trigger | after #2; one concise re-entry + at most one follow-up 7 days later | Accepts a working session, gives a sample decision path, or states what receipt/mandate evidence the domain index would need | No reply / vague / "send more docs" with no working session. **Do NOT send the design note on founder-clock timing** |
| 4 | **SIWX fix-on-ack** (held GHSA-2vm3 patch) | zero build before ack; on ack, 48h to a surgical PR | Maintainer acks, asks for a PR, or merges | No ack after one follow-up, or out-of-scope → credibility work, not the core roadmap |

## Demand test — the 14-day falsification scoreboard (added after Codex's cold judgment, 2026-08-19)

The Now horizon's real job is to **falsify or confirm the buyer hypothesis fast**, and not mistake channel validation (a maintainer likes it) for market validation (an operator will run it). For every candidate operator, fill this scoreboard. Conceptual agreement does not count; a **named operator-owned accept/reject workflow within 14 days** does.

- Named workflow?
- Current accept/reject owner?
- Existing pain, or concrete near-term risk?
- Current workaround?
- Would mandate evidence change a decision?
- Will they supply sample decisions?
- Will they run Bolyra in staging?
- Would they pay, or is this only ecosystem hygiene?

**Hard kill / pivot:** if no buyer-owned accept/reject workflow appears within 2 weeks, **downgrade this wedge** and go looking for a sharper one. A "fake buyer" ("interesting, belongs in the stack, send docs") counts as a miss, not progress.

**Honest odds (Codex, cold judgment):** ~25-35% as originally written / ~35-45% with the falsification-sprint changes, of producing one externally-owned usage within 60 days. Top reason it fails: **the ecosystem may be too early** — the people who understand the problem may not own urgent workflows, and the people who own workflows may not yet feel agent-payment authorization as a must-fix pain.

**OPEN CONFLICT for the founder to resolve:** Codex's judgment says "don't let maintainer warmth be the main evidence — add parallel direct buyer discovery (10-15 conversations with marketplaces / payment-acceptance / fraud-risk operators)." That is sound *in principle*, but it **collides with the settled decision** that cold DMs and public replies are retired (17 cold DMs → 1 reply; the whole reason the bug-fix-PR motion exists). Codex made that call in a pass where the retirement was not re-listed. So: buyer discovery beyond the 2 maintainers is needed, but the CHANNEL is undecided — maintainer intros, the demo attracting inbound, and existing warm threads are motion-consistent; cold operator outreach would be re-opening a killed motion and is a **founder decision**, not something to do by default.

## Next — produce usage evidence

Gate to enter: a named person said yes to one workflow (repo/system context + integration owner + success criteria; "nice project" does not count).

Success: Bolyra runs in someone else's dev/staging/prototype flow and emits usable evidence.
1. Handhold the first integration until it executes an authorize/deny path.
2. Tighten **only** the primitive that blocks the integration (docs, adapter, CLI verifier, receipt example, EVC fixture) — nothing speculative.
3. Package the result as evidence: decision receipts, before/after flow, mandate examples, integration notes.
4. EVC conformance **only** around what the integration exercised — not a standards campaign.

All Next work optimizes for **externally-owned usage evidence inside a seller-side accept/reject flow**, not generic agent auth, broad merchant tooling, or compliance positioning.

## Later — convert evidence to a paid pilot

Gate to enter: external usage evidence exists and the partner agrees the authorization evidence is useful.

Success: one signed pilot or written design-partner commitment naming the workflow and required product surface.
1. Price the narrow thing they already use (verified agent actions for payment/tool execution), not a platform.
2. Build the hosted control plane / policy / audit **only if the pilot requires** hosted ops, non-dev users, admin UX, or compliance review.
3. Turn EVC into a credible ecosystem spec **only after** there is externally-owned usage to point at.
4. Advance the non-provisional patent before **2027-04-20** without letting it become product strategy.

## Do not build (and the trigger to unfreeze)

| Frozen lane | Why | Unfreeze trigger |
|---|---|---|
| Hosted control plane / policy engine / audit portal | Fake enterprise software without a buyer or workflow | Signed pilot explicitly needs non-dev users, policy management, audit review, or hosted ops |
| More package surfaces | More artifacts hide the real problem: no adoption | First partner integration is blocked by a missing adapter or hard product gap |
| Chain / Base / default token work | Confuses the wedge, reopens the wrong narrative | A paying workflow requires settlement-layer verification AND still preserves "verified agent actions" as the product |
| Listing / awesome / example PRs | Activity without conversion | Only if a maintainer requests it as part of an accepted integration |
| Public-reply / cold-DM motion | Retired; weak signal, time sink | Only a specific thread with an integration owner who has an immediate mandate/auth problem |
| ZKProva / speculative ZK mainnet | The buyer problem is not ZK availability | A partner needs privacy properties classical verification cannot satisfy |

## Biggest risk and honest failure mode

The wedge — "verified agent actions" — may be **admired by technical maintainers but not urgently bought** by anyone owning a painful workflow. The failure mode: more warm conversations, more merged cleanup PRs, more respect, and still no one puts Bolyra on a live execution path. That would mean the wedge is intellectually coherent but not yet attached to a must-fix operational pain. The Now horizon exists to falsify or confirm the buyer hypothesis fast, and every workstream has a kill signal so warmth is never mistaken for a market.
