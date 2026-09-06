# standards-autoresearch

Karpathy-style autoresearch loop: compound Bolyra/EVC toward being THE
standard for agent authorization. Fills the Standards slot in the
`CLAUDE.md` loop registry. **Board-only v1**: every output is a reconciled
board, an append-only evidence ledger, or a staged artifact with an
`APPLY.md` — the loop never posts, publishes, or applies anything.

Rulebook: `program.md` (injected into every model call — read it first).
Doctrine: `~/Projects/.viswa/reference/karpathy-loops-md.md`.

## Model split (founder decision 2026-09-06)

- **Generate:** Fable 5.1 (`claude-fable-5-1`) via the Claude MAX CLI, every stage.
- **Judge:** Codex (`codex exec`), every gate: Tier-1 ranking, Tier-2
  acceptance, Tier-3 adversarial review, ecosystem-position scoring.
- Objective checks are scripts; no model judges what a test can decide.
- Neither model silently falls back — missing CLI = loud halt.

## Run

```bash
cd standards-autoresearch
python3 run_loop.py                     # human gate between Tier 1 and Tier 2
python3 run_loop.py --auto-approve      # unattended (outputs are boards + staged only)
python3 run_loop.py --baseline-only     # score current state, no iteration
python3 reconcile.py --dry-run          # check tracked entities, touch nothing
python3 scoring.py --no-judge           # objective dims only
pytest -m "not integration"             # stdlib test suite
```

Cadence: manual, roughly weekly (roadmap "autopilot"); a scheduler is a
v1.1 decision after 2–3 clean iterations.

## Iteration shape

reconcile (no LLM, ground truth first) → signal fetch (WebSearch) →
6-persona attack/scout fan-out → Codex judge → human gate → typed artifact
builds with objective checks (`checks/`) → Codex acceptance → Codex
adversarial review → `output/staged/<date>/<id>/` + `APPLY.md` → score +
report. REJECT findings feed the next iteration's Tier 1.

Exits: drought (3 iterations with no new cards and no staged artifacts),
`--max-iters`, regression halt (standard-ness drop > 2.0 — deliberate: a
drop means ground truth moved against us and the founder should read the
report, exit code 2).

## Outputs

- `output/threat_board.json` / `output/adoption_board.json` — append-only
  cards, reconciled every iteration; terminal is terminal.
- `output/evidence_ledger.jsonl` — third-party-reproducible facts only.
- `output/staged/<date>/<id>/` — founder-applyable artifact packages.
- `reports/standards-iteration-rN.md` + `history/score_trajectory.jsonl`.

## Safety invariants (see program.md §2 for the full list)

Writes only inside this directory · no outbound ever · engagement-graph
holds respected read-only · spec changes staged as pinned diffs, never
applied · published 28-vector set never modified · terminal states never
reopened · reconcile before everything, recompute never accumulate.
