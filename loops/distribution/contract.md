# Distribution Loop Contract

**Loop:** Bolyra x402 Design Partner
**Start:** 2026-06-30
**Duration:** 7 days
**Goal:** Close one x402 design partner — defined as an external builder who runs Bolyra in a real paid-agent flow and publicly acknowledges it.

---

## ICP (Ideal Customer Profile)

A qualified design partner is someone who:

1. Has a **live or in-progress x402 endpoint** (paid API, inference, scraping, data)
2. Accepts payment from **any wallet-equipped agent** with no identity/authorization check
3. Is an **individual builder or small team** (not enterprise — they move too slow for 7 days)
4. Has **public artifacts** (repo, tweet, blog post, hackathon entry) proving they build

A qualified design partner is NOT:
- A VC or investor (they're a different pipeline)
- A standards body contact (IETF is a different loop)
- A competitor (Skyfire, World, Kite AI — study, don't partner)
- Someone who only talks about x402 but hasn't built anything

## Offer

> "Can I do a 20-minute live test against one of your x402 flows and see whether agent authorization catches anything useful? If it's not useful, I'll take the feedback and move on."

Not "use Bolyra." Not "adopt our protocol." A time-boxed test with clear exit.

## Success Criteria

A design partner is "closed" when ANY of:
- They merge a PR that includes Bolyra
- They add Bolyra to their README or docs
- They tweet/post about using Bolyra
- They commit to a pilot with a named timeline
- They give a usable quote about the problem Bolyra solves

---

## Roles

### 1. Planner (overnight, agent-driven)

- Reads `loop.json` + `pipeline.json`
- Picks 8 high-fit targets for today
- Each target gets a **hypothesis**: why THIS person, why TODAY, what specific pain
- Writes target list + hypotheses to `day-N.json`
- Rotates across categories to avoid clustering

### 2. Generator (overnight, agent-driven)

- For each target, drafts a personalized DM/message
- References something SPECIFIC they built or said (not generic hooks)
- Runs Codex review on each draft (per workflow rule: Codex reviews all outreach)
- 5 sentences max per message, one ask per message
- Writes drafts to `day-N.json`

### 3. Evaluator (in-session, founder present)

- Founder opens morning session
- Claude presents: yesterday's scorecard, new replies, today's 8 targets + drafts
- Founder scores each reply using the signal rubric (below)
- Founder approves/edits/kills today's drafts
- Founder names today's "top blocker learned"
- Claude updates `loop.json` scorecard

### 4. Operator (background + in-session)

- Logs sent messages to `pipeline.json` (status transitions)
- Fires follow-up reminder for prospects at day+2 with no reply
- Updates prospect notes with any new signal
- Mostly schema + checklist — minimal ceremony

---

## Signal Rubric (per reply)

| Score | Label | Definition | Example |
|-------|-------|------------|---------|
| 0 | No reply | No response after 48h | — |
| 1 | Polite decline | Replied but not interested | "Cool project, not for us right now" |
| 2 | Interested, no action | Positive signal but no commitment | "Interesting, let me look at it" |
| 3 | Qualified conversation | Agreed to walkthrough, asked technical questions, or started integration | "Can you show me how this works with our endpoint?" |

**"Positive reply" = score 2 or 3.**

---

## Scorecard (6 metrics)

| Metric | Daily | Day 7 Target |
|--------|-------|--------------|
| Qualified prospects contacted | ~8/day | 40 total |
| Positive replies (score 2+) | track | 5+ |
| Walkthroughs booked/completed (named tech owner) | track | 2+ |
| Integration started (repo invite, PR, SDK trial) | track | 1+ |
| Public proof point shipped | track | 1 |
| Top blocker learned | 1/day | 7 total |

**Hard conversion metric:** booked qualified call OR committed pilot.

---

## Kill Criteria

### Day 3 checkpoint
- **< 2 positive replies from first 16 contacts:** pivot the MESSAGE, CHANNEL, or ICP — not the whole loop. Diagnose which is broken:
  - No opens/reads → channel problem (try GitHub instead of X DM, or vice versa)
  - Opens but no reply → message problem (rewrite the hook)
  - Replies but score 1 → ICP problem (wrong people)

### Day 7 checkpoint
- **< 3 positive replies from 40 contacts:** kill this MESSAGE entirely. Try alternate wedge.
- **0 walkthroughs:** change the wedge (not just the message — the entire angle).
- **1+ walkthrough but no integration:** the product has a gap. Log it, fix it, re-run.

---

## Restart Protocol (Karpathy Principle V)

Any new session reads three files and knows the full state:
1. `loop.json` — where we are in the 7 days, cumulative scores
2. `pipeline.json` — every prospect's status and history
3. Latest `day-N.json` — today's targets, drafts, and results

No context window dependency. No "what happened yesterday?" questions.

---

## Daily Cadence

| Time | Role | Action |
|------|------|--------|
| Overnight | Planner + Generator | Pick targets, write hypotheses, draft DMs, Codex review |
| Morning | Evaluator (founder) | Score yesterday, approve today, name blocker |
| Daytime | Founder | Send approved DMs manually |
| Evening | Operator | Log replies, update pipeline, prep follow-ups |

---

## Files

| File | Purpose | Updated by |
|------|---------|------------|
| `contract.md` | This file. Loop rules. | Human only. |
| `loop.json` | Cumulative scorecard + state | Evaluator |
| `pipeline.json` | Per-prospect status + history | Operator |
| `day-N.json` | Daily targets, drafts, scores, blocker | Planner, Generator, Evaluator |
