# Patent AutoResearch — Program Specification

You are participating in a Karpathy-style autoresearch loop that iteratively strengthens the IdentityOS provisional patent. This document is your rulebook.

## 1. Objective

Two-tier loop that automates the adversarial review process used in manual rounds 1-3:

- **Tier 1 (Adversarial Attack Discovery):** 6 hostile reviewer personas attack the patent in parallel. An LLM judge prioritizes findings by severity + specificity + remediability.
- **Human gate:** Curate `tier1_selected.json` before running expensive Tier 2.
- **Tier 2 (Claim Strengthening):** For each selected attack, generate K candidate claim rewrites. Score each on 5 dimensions (alice_101, obviousness_103, support_112, design_around, scope). Apply the winner (highest score per weakness, total ≥ 60).

Loop continues until: score ≥ 90, OR 10 iterations, OR 3 consecutive iterations with <2pt score delta.

## 2. Hard Rules

- **ADDITIVE only** to patent draft. Never delete claims — only refine.
- **NEVER** change inventor name or docket number.
- **ALWAYS** keep a snapshot of the previous patent version (`current_patent.md` in the iter dir).
- All work lives in `patent-autoresearch/`. Only `drafts/provisional-patent-identityos.md` may be modified outside this dir, and only after human approval of `patent_after.md`.
- **Use Claude CLI** (`claude -p ...`), not the Anthropic SDK or API keys. This is a user preference recorded in `~/.claude/projects/-Users-lordviswa-Projects/memory/feedback_claude_max.md`.
- **No package installs.** Use only Python stdlib + subprocess. Anthropic SDK not required.
- **No network downloads** during runs. Prior art is a static curated JSON.

## 3. Scoring — 5 dimensions, 20 pts each = 100 total

See `rubrics/tier2_claim_rubric.md` for full rubric.

- alice_101: 35 USC 101 survival odds (Alice Step 1 + Step 2)
- obviousness_103: 35 USC 103 defense odds (motivation-to-combine resistance)
- support_112: Written description + definiteness
- design_around: Competitor escape resistance
- scope: Commercial coverage breadth

## 4. Verdicts

- `apply`: total ≥ 80 AND no dimension ≤ 8
- `consider`: total 60-79
- `reject`: total < 60 OR any dimension ≤ 4

## 5. Exit Conditions

The loop stops when any of:

- Latest total score ≥ 90
- 10 iterations completed
- 3 consecutive iterations with all pairwise deltas < 2 pts (plateau)

## 6. Directory Layout

```
patent-autoresearch/
├── program.md              # This file
├── personas.json           # 6 hostile reviewer personas
├── prior_art.json          # Curated prior-art database
├── case_law.json           # Alice/103/112 case law
├── seed_findings.json      # Findings from manual r1+r2+r3
├── rubrics/                # Scoring rubrics (Tier 1 + Tier 2)
├── runs/iter_NNN_TS/       # Per-iteration state
├── reports/                # Auto-generated adversarial-review-r{N}.md
├── history/                # Score trajectory + plateau detector
└── scripts/                # Helper scripts
```
