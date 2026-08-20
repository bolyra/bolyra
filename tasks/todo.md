# GTM: next bug-fix PR cycle (Codex PICK A, 2026-08-04)

(previous task — Dependabot triage 2026-07-22 — complete: peak 74 → 10 via PRs #83/#86/#87/#88/#89; full log in tasks/dependabot-cleanup-plan.md + checkpoint_2026_07_22_contribution_day)

Context: primary 30-day motion (2026-07-27 ruling) had zero new PRs in 8 days.
Codex ruled today: start the next bug-fix PR cycle. Scout → pick → fix → test → PR.

## Tasks

- [x] 1. Refresh live status of watched threads (x402-rs #101, mcp #2216, cf/agents #1872, mcp-use #1835 — all quiet, nothing owed)
- [x] 2. Codex prioritization ruling (PICK A: new bug-fix PR cycle)
- [x] 3. Scout: 2 parallel research agents — DONE. NOTE: one scout fabricated intermediate findings + one gave a wrong Python vector claim; lesson recorded 2026-08-04.
- [x] 4. Compile candidate list; independently verify top picks AT HEAD myself (SIWX trust-boundary confirmed real; Python dotAll bug confirmed real but NARROWER than scout claimed — mid-segment %0A only)
- [x] 5. Codex ruled the target: PICK A (x402 SIWX) private-disclosure-first + PICK B (x402 Python dotAll) as the public PR today; sequence A private then B public in same repo; do NOT touch Go (core-contributor collision), do NOT public-file A or C
- [x] 6. Founder approved building both deliverables (2026-08-04)
- [x] 7. B: test-first fix (red: 3 LF cases failed pre-fix / 2 guards passed; green: 5/5 + full suite 1855 passed). One-line fix: re.DOTALL on the route regex. Verified in a real clone via `uv run pytest` (CI-exact), ruff check + format clean, towncrier fragment renders.
- [x] 8. B: Codex code review → APPROVE-WITH-NITS → applied (LF-specific wording, dropped #3036 from changelog) → clean APPROVE on re-pass. Claude+Codex AGREE.
- [x] 9. B: single commit off upstream HEAD, 3 deliverable files only, author+committer = Viswa, DCO signed-off, NO Claude trailer. Exported as git patch.
- [x] 10a. B: PR title + description drafted (maintainer-first: bug/risk/fix/test proof, parity with #3036). At `bolyra/drafts/x402-gtm-2026-08-04/B-PR-description.md`.
- [x] 10b. A: HackerOne disclosure drafted + Codex APPROVE-WITH-NITS → clean APPROVE on re-pass. At `bolyra/drafts/x402-gtm-2026-08-04/A-hackerone-siwx-disclosure.md`.
- [x] 11b. **B SHIPPED 2026-08-05 → PR #3055** — forked, pushed, opened, signed with the registered SSH key (`verified: true`), `check-verified-commits` + `labeler` PASS, integrity re-verified (1 commit `ae96cc4a` / 3 files). Vercel-fail benign. Python CI awaits maintainer workflow-approval.
- [ ] 11a. **A — FOUNDER SEND, still pending:** submit privately to hackerone.com/coinbase (draft `bolyra/drafts/x402-gtm-2026-08-04/A-hackerone-siwx-disclosure.md`, sendable body fenced BEGIN/END). Never a public PR/issue.
- [x] 12. Engagement graph node + MEMORY.md updated (x402-foundation/x402 now a live thread).

## Queued for later today (2026-08-05)

- [ ] Rotate the exposed + spent Anthropic API key; check what the $180.77 promo credit actually covers (it exhausted at ~$32)
- [ ] x402-rs #101 — nudge eligible since 8/5 (14d silence); one gentle nudge to ukstv, not yet drafted
- [ ] qm ADR — founder hand-writes ~250-350w informal, first-person (corrected house style in the engagement-graph node; Codex's 600-900w formal-proposal guidance is STALE and trips their anti-AI-expansion rule)
- [ ] Optional: NVIDIA Retail-Agentic-Commerce webhook idempotency finding (real, minor, unclaimed) — only survivor of the batch sweep

## Parallel / deferred (Codex ALSO rulings, 2026-08-04)

- [ ] x402-rs #101 ukstv nudge: HOLD until 14 full days silent → eligible 2026-08-05; one gentle nudge only
- [ ] Surface to founder (async, non-blocking): qm ADR hand-written draft, switchboard follow-up send confirmation (was due 7/25; 90-day clock → 2026-10-16), Jeet/Malkolm framing conversation

## Review / results

(to fill when the cycle completes)
