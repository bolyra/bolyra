# Tier 1 Attack Rubric

Three axes, 0-10 each. Sum → priority bucket.

## severity (0-10) — How much does this attack threaten the patent?

- 0-2:  Cosmetic (typo, stylistic)
- 3-5:  Minor claim scope adjustment
- 6-8:  Material weakness (one rejection path — e.g., a 101 or 103 ground)
- 9-10: Existential — invalidates an independent claim or blows up an entire strategy

## specificity (0-10) — How actionable is the finding?

- 0-2:  Vague ("claim is too broad")
- 3-5:  Identifies problem area without specifics
- 6-8:  Identifies exact claim element + recommended direction
- 9-10: Proposes concrete replacement language or concrete reference citation

## remediability (0-10) — How easily can it be fixed?

- 0-2:  Requires full restructure (rewrite every independent claim)
- 3-5:  Requires significant drafting (multi-section spec work)
- 6-8:  Local claim edit (one or two elements)
- 9-10: Trivial word-level fix

## Priority (derived from total severity + specificity + remediability)

- `high`:   total ≥ 22
- `medium`: total 15-21
- `low`:    total < 15

High-priority attacks are promoted to Tier 2 first (up to top 8 per iteration).
Low-priority attacks are logged but not fixed automatically — they accumulate as
a reference document for the attorney review stage.
