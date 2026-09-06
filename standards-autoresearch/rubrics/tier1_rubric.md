# Tier 1 Rubric — candidate scoring (Codex judges)

Score every candidate on four dimensions, 0–25 each. Be a CONSERVATIVE
scorer: when evidence is thin, score low. A candidate without a URL, repo,
datatracker entry, or runnable command cannot exceed 40 total (program.md
rule 2k).

## Dimensions by candidate type

**spec_finding / vector_gap** (attack candidates):
- `severity` (0–25): how badly does this gap hurt interop or safety if two
  implementers diverge / an attacker exploits it? 25 = fail-open or
  silent-divergence class; 5 = cosmetic.
- `evidence` (0–25): does the finding quote the exact spec text and
  demonstrate the divergent/exploitable behavior? 25 = quoted text + concrete
  counterexample; 0 = vibes.
- `fixability` (0–25): can Tier 2 produce a bounded artifact (diff or
  vector) that closes it without breaking the 28 published vectors? 25 =
  additive vector or one-paragraph clarification; 5 = requires a breaking
  wire change.
- `standard_impact` (0–25): does closing it move standard-ness (hardness,
  RFC 7942 readiness, registry closure)? 25 = removes a known -02 blocker.

**evidence_opportunity**:
- `verifiability` (0–25): third-party reproducible with pins + commands?
- `demand` (0–25): would a skeptical implementer/reviewer actually ask for this?
- `cost` (0–25): executable locally this iteration? 25 = minutes; 0 = needs outbound.
- `standard_impact` (0–25): RFC 7942 / evidence-ledger value.

**threat_update / adoption_target** (scout candidates):
- threat: `momentum` / `overlap` / `adoption_risk` / `counter_available` (0–25 each)
- adoption_target: `incentive_fit` / `technical_fit` / `channel_state` /
  `effort` (0–25 each). **channel_state is capped at 5 if the entity is under
  an engagement-graph hold** — the caller marks held entities in the input.

## Verdicts

- PROMOTE: total ≥ 70 AND every dimension ≥ 12
- CONSIDER: total ≥ 50 AND no dimension ≤ 5
- DROP: otherwise

## Output contract

Return ONE JSON object:
```json
{"scored": [{"id": "...", "dims": {"...": 0}, "total": 0,
             "verdict": "PROMOTE|CONSIDER|DROP", "reason": "one sentence"}]}
```
