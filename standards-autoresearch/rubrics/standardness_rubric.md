# Standard-ness Rubric — loop-level score (0–100)

Four of five dimensions are computed objectively by `scoring.py` from
reconciled truth. Only ECOSYSTEM POSITION is judged (by Codex) against the
anchors below.

## Objective dimensions (computed, not judged)

- **IMPLEMENTATIONS (25)** — 8 pts per independent implementation passing
  conformance at a pinned commit (external code, not ours), capped at 16;
  +5 if at least one is RFC 7942-listable (public, pinned, permissioned);
  +4 if a reference implementation in a second language exists (reference-host-rs).
- **SPEC HARDNESS (20)** — start at 20; −3 per open CONFIRMED spec_finding
  (Tier-3-approved, unapplied) against the current spec, floor 0; scale by
  MUST-coverage: multiply by (covered normative MUSTs / total normative
  MUSTs) as computed by the vector coverage map, floor 0.5 multiplier.
- **INTEROP EVIDENCE (20)** — 4 pts per ledger entry that is third-party
  reproducible (pinned_commit AND reproduce_cmd present), capped 16;
  +4 if ≥2 entries are rfc7942_ready.
- **REGISTRY CLOSURE (15)** — 5 if the published conformance package version
  matches the vendored spec snapshot (`sync:check` green); 5 if vector-set
  version aligns with spec version per the versioning note; 5 if -02
  material (implementation-status section draft) exists in staged/ or spec/.

## ECOSYSTEM POSITION (20) — Codex-judged anchors

- 0–5: EVC is one of several equivalent drafts; competitors set the terms.
- 6–10: EVC is cited by peers but competing specs hold equal or better
  adoption momentum; no competitor neutralized.
- 11–15: EVC is the reference point in shared threads; at least one
  competing spec positioned as an adapter/layer over EVC rather than a
  rival (the aeoess-concession pattern); datatracker standing current.
- 16–20: multiple competing specs interoperate through or defer to EVC
  boundaries; external parties initiate interop runs against EVC (the
  VATE-#57 pattern); no credible fork of the category.

Judge conservatively; when between anchors, take the lower band. Return ONE
JSON object: `{"points": 0, "band": "...", "reason": "two sentences max"}`.
