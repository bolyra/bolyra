# Theseus Partnership Discovery Loop

## Objective

Discover features and integration opportunities that make Bolyra the ideal identity/authorization layer for Theseus L1 — a chain purpose-built for autonomous AI agents.

## Scoring

Each proposal is scored on 4 dimensions, each 0-25 (total 0-100):

| Dimension | What It Measures |
|---|---|
| **Agent Need** | How urgently do autonomous agents on Theseus need this capability? |
| **ZKP Edge** | Does ZKP-based identity provide a meaningful advantage over conventional crypto? |
| **Primitive Readiness** | Can Bolyra serve this with existing circuits/contracts/SDK, or is new R&D needed? |
| **Partnership Leverage** | Does this create mutual dependency — Theseus needs Bolyra, Bolyra needs Theseus? |

## Verdict Thresholds

| Verdict | Condition |
|---|---|
| **PROMOTE** | Total >= 70 AND every dimension >= 12 |
| **CONSIDER** | Total >= 50 AND no dimension <= 5 |
| **DROP** | Total < 50 OR any dimension <= 5 |

## Exit Conditions

- **Max iterations:** 8
- **Plateau:** exit after 3 consecutive low-yield iterations (fewer than 2 new PROMOTE/CONSIDER results)
- **Convergence:** exit when top 5 proposals are stable across 2 consecutive iterations

## Reference

Bolyra's existing primitives are catalogued in `primitives.json` (symlinked from discovery-autoresearch). Any proposal that maps to an existing primitive scores higher on Primitive Readiness.

## Loop Structure

1. **Tier 1 — Discovery:** Each persona generates raw proposals from its search queries and focus area.
2. **Tier 2 — Validation:** Proposals are cross-validated against evidence requirements (rubrics/tier2).
3. **Tier 3 — Adversarial Challenge:** Surviving proposals face 5 attack axes (rubrics/tier3).
4. **Scoring & Ranking:** Final scored board written to `output/integration_board.json`.
