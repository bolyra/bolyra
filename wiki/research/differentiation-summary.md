---
title: Differentiation Autoresearch Summary
visibility: internal
sources:
  - differentiation-autoresearch/README.md
  - differentiation-autoresearch/history/convergence_report.md
  - differentiation-autoresearch/history/score_trajectory.jsonl
  - differentiation-autoresearch/rubric.md
  - differentiation-autoresearch/winners/C7/construction.md
  - differentiation-autoresearch/winners/C2/construction.md
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [research, differentiation, zkp, competitive-moat]
---

The differentiation autoresearch loop is a Karpathy-style adversarial hardening program that drove Bolyra's differentiation claims to their empirical ceiling. Two candidates were promoted; five were dropped.

## Overview

The loop tested whether Bolyra's ZKP construction actually beats the best non-ZK alternatives (RFC 7662 + JWT introspection + RFC 8693 + DPoP + BBS+ + SPIFFE/WIMSE). Each candidate was iteratively refined through three tiers: Tier 1 (survey the strongest non-ZK baseline), Tier 2 (construct a ZK approach that strictly beats it), Tier 3 (5-persona adversarial attack + Codex challenge). A 5-dimension x 2-point rubric scored each candidate on baseline dominance, formal security, implementability, adversarial survival, and scenario fit.

## Key Findings

### Three Passes

**Pass 1:** Aborted due to a module-shadowing bug (`_imports.py` resolving the wrong `judge.py`).

**Pass 2:** 5 seed candidates (C1-C5) x 5 iterations each. All plateaued below target. The multi-gap mutator tried to close 6 gaps simultaneously per iteration, which bloated constructions and expanded attack surfaces. C2 regressed from 8 to 5 across iterations.

**Pass 3:** After Pass 2 plateau, two new candidates were seeded (C7: cryptographic model-instance binding, C9: forward-secure agent delegation). The mutator was rewritten to harden rather than expand: address ONE gap per iteration, preserve claim statements verbatim, prefer narrowing over adding machinery. C7 climbed 0 -> 4 -> 6 -> **9** -> 7 -> 6, peaking at iteration 3. C9 was flat at 5 across all iterations.

**Surgical refinements on C7 peak:** Two attempts to reach 10/10 both regressed. Narrowing the claim (9 -> 7) sacrificed baseline_dominance. Patching secondary gaps (9 -> 5) re-bloated the attack surface. The 9/10 peak is the empirical ceiling for pure-ZK.

### Winners

Two candidates promoted to `winners/`:

| ID | Claim | Peak | Key Property |
|---|---|---|---|
| **C7** | Cryptographic model-instance binding | **9/10** | Per-call binding of (modelHash, operator_pk, permBitmask, messageHash) with provider anonymity |
| **C2** | AS-blind cross-scope unlinkability | **8/10** | Agent-side proof generation keeps AS off the per-scope path |

### Score Trajectory (C7)

```
iter 1: 4  (drop)
iter 2: 6  (drop)
iter 3: 9  (consider) <-- PEAK, promoted to winners/
iter 4: 7  (consider)
iter 5: 6  (drop)
iter 6: 7  (surgical v1, narrowed claim -- regressed)
iter 7: 5  (surgical v2, patched gaps -- regressed further)
```

### Methodology Lessons

1. **Multi-gap mutation is self-defeating.** Closing many gaps at once bloats the construction and creates new attack surfaces. Single-gap-per-iteration hardening is more effective.
2. **The rubric correctly caps pure-ZK at 9/10.** The structural tension between bold claims (needed for baseline_dominance) and defensible claims (needed for adversarial_survival) is a feature, not a bug. The last point on C7 requires TEE/hardware attestation.
3. **Seed strength is unreliable.** C4 was seeded at 9/10 but dropped to 5/10 under adversarial scrutiny (BBS+ overlap). C7 was seeded at 0 and reached 9/10.

## Current Status

Loop completed April 2026. Recommendation accepted: ship C7 + C2 as the two wedges. Path to C2 improvement (IND-UNL-AS game reformulation) is available but not prioritized. TEE integration for C7 (10/10) is a separate research track, deferred until customer pull.

Later runs (June 2026) retested C3 and C4 with additional iterations. C3 peaked at 7/10 (iter 24). C4 peaked at 9/10 (iter 8) but regressed to 6/10, confirming instability.

## See Also

- `differentiation-autoresearch/history/convergence_report.md` -- full methodology and results
- `differentiation-autoresearch/winners/C7/` -- peak construction, baseline, attacks, score
- `differentiation-autoresearch/winners/C2/` -- peak construction, baseline, attacks, score
- `differentiation-autoresearch/rubric.md` -- 5-dimension scoring rubric
- `wiki/strategy/differentiation.md` -- strategic implications
