# PR Outreach Loop Contract

**Loop:** Bolyra PR-based Distribution
**Start:** 2026-06-30
**Cadence:** Weekly (every Monday)
**Goal:** Get PRs merged on external repos as proof points. Each merged PR = public proof that Bolyra integrates with real infrastructure.

---

## Purpose

PRs are the highest-signal outreach channel. A merged PR means:
- The maintainer reviewed your code and accepted it
- Your project appears in their repo permanently
- Anyone reading their repo discovers Bolyra
- It's a credibility asset for all future conversations

PRs that stall are wasted work. This loop prevents that.

---

## Scope

1. **Manage existing open PRs** — respond to reviews, rebase, fix CI, follow up, close if dead
2. **Find new high-fit repos** — weekly scan for x402/MCP/agent repos where a Bolyra integration PR would be valuable
3. **Open 1-2 new PRs per week** — quality over quantity

---

## ICP (Ideal PR Target)

A good PR target repo:
- Has **active maintainers** (recent commits, issues responded to)
- Is in the **x402, MCP, or agent payment** ecosystem
- Has **no existing auth/identity solution** (the gap Bolyra fills)
- Accepts **external contributions** (CONTRIBUTING.md, open issues, merged external PRs)
- Has **enough stars/usage** to matter as a proof point (>50 stars or used by ICP prospects)

---

## Roles

### 1. Scanner (weekly, agent-driven)
- Check status of all open PRs (CI, reviews, comments)
- Identify repos from the DM outreach pipeline that could use a PR
- Search GitHub for new x402/MCP repos with no auth layer
- Write findings to `week-N.json`

### 2. Builder (in-session, on demand)
- Write the actual PR code (examples, integrations, docs)
- Codex-review before pushing (per workflow rule)
- Set correct git author (per workflow rule)

### 3. Monitor (weekly, agent-driven)
- Check each open PR for: new comments, CI status, stale warning
- Draft responses to review comments
- Flag PRs that need attention in `week-N.json`

---

## PR Status Lifecycle

`planned → opened → reviewing → changes_requested → approved → merged`

Also: `stale` (no activity 7+ days), `closed` (rejected or withdrawn)

---

## Scorecard (weekly)

| Metric | Target |
|--------|--------|
| Open PRs monitored | all |
| Review comments responded to | within 48h |
| PRs merged this week | 1+ |
| New PRs opened this week | 1-2 |
| Stale PRs followed up on | all |

---

## Rules

1. **Codex reviews all PR code before pushing.** No exceptions.
2. **Set correct git author on every commit.** GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com"
3. **Each PR must be self-contained.** Don't require the target repo to install Bolyra as a dependency — show the integration as an example or optional addon.
4. **Don't spam.** Max 2 new PRs per week. Quality > quantity.
5. **Close dead PRs.** If no response after 2 follow-ups (14 days), close with a polite note and move on.

---

## Kill Criteria

- **Week 4:** If 0 PRs merged out of 10+ open, the PR approach isn't working. Switch to a different code contribution strategy (e.g., standalone example repos, blog posts with code).

---

## Files

| File | Purpose | Updated by |
|------|---------|------------|
| `contract.md` | This file. Loop rules. | Human only. |
| `loop.json` | Cumulative state + scorecard | Monitor |
| `prs.json` | Per-PR status + history | Scanner, Monitor |
| `week-N.json` | Weekly scan results, actions, new targets | Scanner |
