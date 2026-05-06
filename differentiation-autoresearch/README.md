# differentiation-autoresearch

Karpathy-style adversarial hardening loop for Bolyra's five load-bearing differentiation claims. Drives each claim to Strength=10/10 under the 5-dim × 2-pt rubric, or escalates on plateau.

## Candidates (from codex Round 2)

| ID | Claim | Seed strength |
|---|---|---|
| C1 | Selective scope proof | 4 |
| C2 | Cross-scope unlinkability | 9 |
| C3 | Delegation audit without exposure | 7 |
| C4 | Issuer-blind attribute predicates | 9 |
| C5 | Bolyra as MCP auth, generally | 0 (ruled out by codex; H1-H5 hypotheses to validate) |

## Loop per candidate

```
Tier 1 — Survey       → baseline.md       (strongest non-ZK alternative)
Tier 2 — Construct    → construction.md   (ZK construction that strictly beats baseline)
Tier 3 — Adversarial  → attacks.md        (5 personas + codex challenge)
Judge                 → score.json        (0–10 with justification + gap list)
Mutator               → construction.md'  (surgical fixes to named gaps via Tier 2 refine)
Plateau               → stop or continue  (target=10, plateau=3 equal iters)
```

## Rubric (see `rubric.md`)

5 dims × 2 pts each. Any dim < 2 caps total at 9.
1. Baseline dominance
2. Formal security argument
3. Implementability in Bolyra
4. Adversarial survival
5. Scenario fit

## Running

```bash
cd identityos/differentiation-autoresearch

# Dry-run on C2 (closest to 10), no codex (faster)
python run_loop.py --candidate C2 --max-iters 3 --no-codex

# Full run with codex adversary
python run_loop.py --candidate C2 --max-iters 5

# Run all candidates
python run_loop.py --all --max-iters 5
```

## Outputs

- `runs/iter_NNN_TIMESTAMP/C{1..5}/{baseline,construction,attacks}.md` + `score.json`
- `history/score_trajectory.jsonl` — one entry per iteration per candidate
- `winners/C{1..5}/` — promoted when strength=10
- `history/convergence_report.md` — written by a separate script when all five at 10/10

## Models

Per workspace rule (feedback_claude_max): Claude CLI with MAX login only. No API keys, no SDK.

- Tier 1 (survey): `sonnet` — fast, factual distillation
- Tier 2 (construct): `opus` — reasoning-heavy construction
- Tier 3 (adversarial): `sonnet` for personas + `codex` CLI for second-model adversary
- Judge: `opus` — rubric-strict

## Reuses (do not rewrite)

- `protocol-autoresearch/_shared.py` — `call_claude_cli()` + JSON extraction
- `patent-autoresearch/history/plateau_detector.py` — plateau / target / max-iter stop logic
- `spec/draft-bolyra-mutual-zkp-auth-01.md` — Bolyra primitives source of truth
- `circuits/FORMAL-PROPERTIES.md` — circuit-level security properties
- `~/.claude/skills/codex/SKILL.md` — codex invocation pattern

## Status

See `history/score_trajectory.jsonl` for per-iteration scores. When all five candidates reach strength=10, `history/convergence_report.md` is generated and the strategy files are updated:
- `strategy/zk-vs-rfc7662-differentiation.md` — final scores
- `drafts/ietf-mapping-1pager.md` — strongest construction per candidate
- `strategy/codex-pushback-round2.md` — resolved load-bearing question
