# Bolyra Protocol AutoResearch — Program Specification

You are participating in a three-stage autoresearch loop that iteratively improves the Bolyra protocol. This document is your rulebook.

## 1. Objective

Three-stage loop optimizing the protocol across 4 dimensions: adoption, standards, completeness, correctness.

- **Tier 1 (Discovery):** 8 constructive explorer personas brainstorm and score improvement candidates from `seed_candidates.json`. An LLM judge ranks by combined score. Output: `tier1_ranked.json`.
- **Human gate:** Review `tier1_ranked.json`, curate `tier1_selected.json` before running Tier 2.
- **Tier 2 (Build):** For each selected candidate, generate a concrete experiment artifact (circuit, contract, SDK, spec). Run 24 automated checks. Score on 4 dimensions. Promote winners to `winners/`.
- **Tier 3 (Codex Adversarial Review):** Codex-harness adversarial review of promoted winners. 6 review axes. APPROVE/CONDITIONAL/REJECT verdict required before merging to production.

Loop continues until: all 4 dims ≥ 21 simultaneously (total ≥ 84), OR 10 iterations, OR 3-iteration plateau (deltas < 3 pts per dim).

## 2. Hard Rules

- **ADDITIVE ONLY.** All experiment work goes in `experiments/`. NEVER modify production code in `circuits/`, `contracts/`, `frontend/`, `backend/`.
- **Claude CLI only.** Use `claude -p ...` (no Anthropic SDK, no API keys). Per user preference in `feedback_claude_max.md`.
- **No pip/npm installs at runtime.** Use Python stdlib + subprocess only.
- **Human gate required** between Tier 1 and Tier 2. Do not auto-advance.
- **Correctness regression halts the loop.** Any experiment that degrades existing 104 unit + 7 integration tests is immediately dropped. Security must never regress.
- **Constraint budget:** circuits must remain ≤ 80k constraints. Exceeding this is a hard fail.
- **No network downloads** during runs. Dependencies must already be installed.

## 3. Scoring — 4 dimensions × 25 pts each = 100 total

See `rubrics/tier1_rubric.md` and `rubrics/tier2_check_rubric.md` for full rubrics.

- **CORRECTNESS (25):** circuits compile, proofs roundtrip, tests don't regress, formal properties
- **COMPLETENESS (25):** circuit/contract/spec artifacts present, CIP features implemented
- **ADOPTION (25):** SDK modules, framework integrations, DX quality, error messages, TTHW
- **STANDARDS (25):** RFC 2119 normative language, test vectors, interop evidence, spec completeness

## 4. Verdicts

- `promote`: total ≥ 75 AND all 4 dims ≥ 15
- `consider`: total 60–74
- `drop`: total < 60 OR any dim ≤ 8

## 5. Exit Conditions

The loop stops when any of:

- All 4 dimensions simultaneously ≥ 21 (total ≥ 84)
- 10 iterations completed
- 3 consecutive iterations where all pairwise dim deltas < 3 pts (plateau)

## 6. Directory Layout

```
protocol-autoresearch/
├── program.md                   # This file — master rulebook
├── seed_candidates.json         # 20 initial protocol improvement candidates
├── _shared.py -> ../patent-autoresearch/_shared.py
├── personas/
│   └── exploration_personas.json  # 8 constructive explorer personas
├── rubrics/
│   ├── tier1_rubric.md           # Candidate scoring rubric (Tier 1)
│   ├── tier2_check_rubric.md     # 24-check harness rubric (Tier 2)
│   └── tier3_adversarial_rubric.md  # Codex adversarial review (Tier 3)
├── templates/                   # Prompt templates for each tier
├── scripts/                     # Runner scripts (tier1.py, tier2.py, tier3.py)
├── experiments/                 # Per-candidate experiment artifacts
│   └── <candidate-id>/
│       ├── artifact.*           # Circuit / contract / SDK / spec
│       ├── checks.json          # 24-check results
│       └── score.json           # Dimension scores + verdict
├── winners/                     # Promoted experiments (verdict: promote)
├── history/
│   ├── __init__.py
│   └── iter_NNN.json            # Per-iteration score snapshot
└── reports/                     # Auto-generated loop reports
```
