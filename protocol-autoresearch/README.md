# protocol-autoresearch

A Karpathy-style autoresearch loop for iteratively improving the Bolyra
identity protocol. Three-stage loop optimizing across 4 dimensions:
correctness, completeness, adoption, standards.

## What this does

**Tier 1 (Discovery):** 8 constructive explorer personas (SDK designer,
framework integrator, standards architect, circuit optimizer, security auditor,
product visionary, cross-chain engineer, formal verifier) propose protocol
improvements in parallel via Claude CLI. An LLM judge scores candidates on
4 dimensions (adoption, standards, completeness, correctness). Top 8 winners
go to Tier 2.

**Tier 2 (Build):** For each winner, generates a structured implementation
outline, then builds experiment artifacts (circuits, contracts, SDK modules,
specs) into `experiments/`. Each experiment is scored by the 24-check harness
(file existence, LLM-judged quality, build checks). Winners with verdict
promote/consider advance to Tier 3.

**Tier 3 (Adversarial Review):** Codex-harness (or Claude fallback) adversarial
review on 6 axes (circuit correctness, security, API design, spec quality,
integration, performance). APPROVE -> `winners/`. CONDITIONAL -> attempt fix.
REJECT -> findings fed back to next Tier 1 iteration.

**Plateau detector:** Loop stops when (a) total score >= 84, (b) 10 iterations
done, or (c) 3 consecutive iterations with deltas < 3.0.

## Safety properties

- **Additive only.** All experiment work goes in `experiments/`. Production code
  in `circuits/`, `contracts/`, `frontend/`, `backend/` is never modified.
- **Correctness regression halts the loop.** Any drop > 1pt in correctness
  triggers immediate halt in auto-approve mode.
- **Claude CLI only.** No API keys, no SDK. Uses `claude -p ... --model opus|sonnet`.
- **No package installs.** Pure stdlib + subprocess.
- **Human gate** between Tier 1 and Tier 2 (unless `--auto-approve`).

## Prerequisites

- Python 3.13+
- `claude` CLI logged in via Claude MAX

Verify:

```bash
claude --version
python3 --version
```

## First-time baseline

```bash
cd ~/Projects/bolyra/protocol-autoresearch
python3 run_loop.py --baseline-only
```

Takes ~3-5 min (one opus call). Writes `history/score_trajectory.jsonl` with
iteration 0.

## Running the full loop (interactive)

```bash
python3 run_loop.py
```

Flow per iteration:
1. Tier 1: parallel fanout with 8 personas (~8-12 min)
2. **Human gate** - review `tier1_winners.json`, press Enter
3. Tier 2: outline + build + score experiments
4. Tier 3: adversarial review
5. Score protocol state
6. Regression check
7. Emit reports

## Running auto-approve (unattended)

```bash
python3 run_loop.py --auto-approve --max-iters 3
```

In auto-approve mode, any regression causes immediate exit with code 1.

## CLI flags

```bash
python3 run_loop.py [options]

  --max-iters N        Cap iterations (default 10)
  --target-score F     Stop when reached (default 84.0)
  --auto-approve       Skip human gates
  --baseline-only      Score current protocol and exit
```

## Output layout

```
protocol-autoresearch/
├── history/
│   ├── score_trajectory.jsonl    # one JSON per line, per iteration
│   └── plateau_detector.py
├── runs/
│   └── iter_NNN_TS/
│       ├── tier1_candidates.json     # raw persona output
│       ├── tier1_scored.json         # candidates + judge scores
│       ├── tier1_winners.json        # top 8 winners
│       ├── tier2_outlines.json       # implementation outlines
│       ├── tier2_experiments.json    # built experiments + scores
│       ├── tier2_scores.json         # 24-check harness scores
│       ├── tier2_winners.json        # experiments passing checks
│       ├── tier3_reviews.json        # adversarial verdicts
│       ├── tier3_promoted.json       # APPROVE/CONDITIONAL winners
│       ├── tier3_rejected.json       # REJECT findings for feedback
│       └── iteration_report.md
├── experiments/                      # per-candidate artifacts
│   └── tier2_NNN_<id>/
├── winners/                          # promoted experiments
├── reports/
│   └── protocol-iteration-rN.md
├── personas/
│   └── exploration_personas.json
├── rubrics/
│   ├── tier1_rubric.md
│   ├── tier2_check_rubric.md
│   └── tier3_adversarial_rubric.md
```

## Scoring — 4 dimensions x 25 pts each = 100 total

- **CORRECTNESS (25):** circuit compiles, proofs roundtrip, tests pass, no shared modified
- **COMPLETENESS (25):** circuit/contract/spec exist, test vectors, CIP feature, constraint budget
- **ADOPTION (25):** SDK module, types, tests, framework integration, TTHW, errors, docs
- **STANDARDS (25):** normative language, test vectors conformance, interop, spec completeness

24 individual checks. See `rubrics/tier2_check_rubric.md` for full details.

## Verdicts

- **promote:** total >= 75 AND all 4 dims >= 15
- **consider:** total 60-74
- **drop:** total < 60 OR any dim <= 8

## Running tests

```bash
cd protocol-autoresearch
python3 -m pytest -v -m "not integration"          # all fast tests
python3 -m pytest -v -m "integration"              # slow, hits Claude CLI
```

## Design notes

- **Dict-keyed merge, not positional.** LLMs reorder arrays silently.
- **Error stubs, not exceptions.** Per-persona/candidate failures become
  error-stub entries rather than raising.
- **Batched judge calls.** Max 6 candidates per Claude call to avoid truncation.
- **REJECT feedback loop.** Rejected findings from Tier 3 are injected into
  the next Tier 1 iteration as context.
