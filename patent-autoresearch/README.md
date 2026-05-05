# patent-autoresearch

A Karpathy-style autoresearch loop for iteratively strengthening the IdentityOS
provisional patent. This is the automated version of the adversarial review
cycles already done manually in `drafts/adversarial-review{,-r2,-r3}.md` —
each loop iteration is one more round.

## What this does

**Tier 1 (adversarial review):** 6 hostile reviewer personas (USPTO examiner,
competitor attorney, 101 specialist, 103 specialist, 112 specialist,
code/spec auditor) attack the patent in parallel via Claude CLI. An LLM judge
ranks findings by severity + specificity + remediability. Top 8 high-priority
attacks go to Tier 2.

**Tier 2 (claim strengthening):** For each attack, 3 candidate claim rewrites
are generated (narrow, positive-structural, dependent, etc.). Each candidate
is scored on 5 dimensions (alice_101, obviousness_103, support_112,
design_around, scope). The highest-scoring candidate per attack (if total ≥ 60)
is applied to the patent via strict exact-string replacement.

**Plateau detector:** Loop stops when (a) total score ≥ 90, (b) 10 iterations
done, or (c) 3 consecutive iterations with deltas < 2.0.

**Adversarial-review reports:** Each iteration produces a drop-in successor at
`reports/adversarial-review-r{N}.md` where N = iteration + 3 (rounds 1-3 were
manual). Same structure as the manual reviews in `drafts/`.

## Safety properties

- **Additive only.** Mutations use exact-string replacement. A missing
  `original_language` raises ValueError — no silent wrong edits.
- **Source never modified** without human approval. Every iteration snapshots
  the current patent at `runs/iter_N_TS/current_patent.md` before anything
  else, writes mutations to `patent_after.md`, and only overwrites
  `drafts/provisional-patent-identityos.md` after a human Enter-key gate.
- **Regression detector.** If a mutation drops the score by more than 1.0 pt,
  the loop halts (or prompts in interactive mode). This is the guard against
  another M2-style self-inflicted wound.
- **Claude CLI only.** No API keys, no SDK. Uses `claude -p ... --model opus|sonnet`.
- **No package installs.** Pure stdlib + subprocess. Built-in pytest for tests.

## Prerequisites

- Python 3.13+
- `claude` CLI logged in (`claude /login` or via the desktop app). Your Claude
  MAX login is what's used — no API keys needed.

Verify:

```bash
claude --version
python3 --version
```

## First-time baseline

```bash
cd ~/Projects/bolyra/patent-autoresearch
python3 run_loop.py --baseline-only
```

Takes ~3-5 min (one opus call). Writes `history/score_trajectory.jsonl` with
iteration 0. Exit 0 = ready.

## Running the full loop (interactive)

```bash
python3 run_loop.py
```

Flow:
1. If no trajectory, runs baseline first.
2. Starts iteration 1:
   a. Tier 1: parallel fanout (~5-8 min with 6 personas).
   b. **Human gate** — script prints `Press Enter to proceed` and waits.
      Review `runs/iter_001_TS/tier1_selected.json` and edit if desired.
   c. Tier 2: candidate generation (~2-3 min per attack, 4 parallel).
   d. Scoring (~3 min per candidate, sequential to avoid opus rate limits).
   e. Mutations applied to `patent_after.md`.
   f. New score computed.
   g. **Regression check** — script halts/prompts if new < previous - 1.0.
   h. **Human gate** — review `patent_after.md` vs current. Press Enter to
      overwrite `drafts/provisional-patent-identityos.md`, or Ctrl-C to abort.
3. Emits `runs/iter_001_TS/iteration_report.md` and
   `reports/adversarial-review-r4.md`.
4. Updates `history/score_trajectory.jsonl`.
5. Checks plateau detector. If stopping, prints reason and exits. Otherwise
   proceeds to iteration 2.

## Running auto-approve (dangerous; post-validation only)

Once the loop is validated with at least one interactive pass, you can skip
human gates:

```bash
python3 run_loop.py --auto-approve --max-iters 5
```

In auto-approve mode, any regression (score drop > 1.0) causes **immediate
exit with code 1**. The live patent is not overwritten for that iteration.

## CLI flags

```bash
python3 run_loop.py [options]

  --max-iters N        Cap iterations (default 10)
  --target-score F     Stop when reached (default 90.0)
  --auto-approve       Skip human gates
  --baseline-only      Score current patent and exit
  --k N                Candidates per attack in Tier 2 (default 3)
```

## Output layout

```
patent-autoresearch/
├── history/
│   └── score_trajectory.jsonl    # one JSON per line, per iteration
├── runs/
│   └── iter_NNN_TS/
│       ├── current_patent.md         # snapshot at iteration start
│       ├── tier1_attacks.json        # raw persona output
│       ├── tier1_scored.json         # attacks + judge scores
│       ├── tier1_selected.json       # top 8 high-priority (editable)
│       ├── tier2_candidates.json     # K candidates per selected attack
│       ├── tier2_scored.json         # candidates + 5-dim scores
│       ├── tier2_winners.json        # highest-scoring per weakness, total ≥ 60
│       ├── patent_after.md           # patent with mutations applied
│       └── iteration_report.md
├── reports/
│   └── adversarial-review-rN.md  # drop-in successor to drafts/adversarial-review{,-r2,-r3}.md
```

## Summarizing a run

```bash
python3 scripts/summarize_run.py              # print to stdout
python3 scripts/summarize_run.py --write-file # also write FINAL_REPORT.md
```

Shows ASCII score trajectory chart, baseline/latest/delta, list of
adversarial-review reports produced.

## Adding new prior art

Edit `prior_art.json`. Each entry needs `id`, `name`, `url`, `year`,
`what_it_teaches`, `threatens_claims`. The next iteration's Tier 1 prompts
will include the new reference.

## Adding a new reviewer persona

Edit `personas.json`. Each entry needs `id`, `role`, `focus` (list of
keywords). The next iteration will dispatch the new persona in parallel
with the existing 6.

## Running tests

```bash
cd patent-autoresearch
python3 -m pytest -v -m "not integration"          # all fast tests
python3 -m pytest -v -m "integration"              # slow, hits Claude CLI ($$)
```

## Troubleshooting

- **"Claude CLI timed out"**: bump timeouts (defaults are 240-600s depending
  on the module). Tier 2 opus calls can be slow when the patent is large.
- **"JSON not found in response"**: the LLM returned prose instead of JSON.
  The affected attack/candidate becomes an error stub and the batch continues.
  If all personas hit this at once, check `claude` CLI health.
- **Mutation skipped (original_language not found)**: the candidate's
  `original_language` field didn't match patent text verbatim. The next
  iteration will likely generate a different candidate. Not a bug.
- **Regression in interactive mode**: press Ctrl-C to abort, inspect the
  diff, and consider which applied mutation caused the drop. Revert by
  deleting the last trajectory entry and the overwritten patent.

## Design notes

- **Positional vs dict-keyed merge**: always dict-keyed. LLMs reorder arrays
  silently; positional merge causes silent mispairing (see the r3 review on
  the M2 self-inflicted wound for the lesson).
- **Error stubs, not exceptions**: per-attack/per-candidate failures become
  error-stub entries in the output JSON rather than raising. This keeps
  parallel batches resilient and makes the failure visible downstream.
- **Sequential mutations, not transactional**: `apply_winners` applies each
  winner in order; each sees the state from prior applications. A failing
  mutation is recorded but does not halt the batch.
