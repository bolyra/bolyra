# Tier 3 Adversarial Rubric — Codex review of staged artifacts

Review the artifact as a hostile gatekeeper. Verdict axes (ALL must pass for
APPROVE; any hard-rule violation is automatic REJECT):

1. **Spec correctness** — would an IETF reviewer object? Is every claim
   consistent with the pinned spec text and the actual reference-host
   behavior? Verify claims against source; do not trust the artifact's own
   assertions.
2. **Vector validity** (vector artifacts) — does the vector test HOST
   BEHAVIOR under the contract, not an implementation detail of our
   reference hosts? Is the expected decision/failure class derivable from
   the spec text alone?
3. **Backward compatibility** — the 28 published vectors (set 0.6.0) must
   still pass unchanged; vector-set semver respected (additive = minor).
4. **Moat guardrail** — the artifact gives WHY / boundary / spec only.
   Anything resembling a repo-specific build plan or the hosted operational
   system is REJECT (program.md rule 2e).
5. **Freeze compliance** — nothing implies a new package, a listing/example
   PR, outbound contact, or hosted-platform work (rules 2c, 2f).
6. **Evidence verifiability** — every factual claim carries a pin, command,
   or URL a third party can check.

## Verdicts

- APPROVE — artifact is stageable as-is; list any nits as `notes`.
- CONDITIONAL — sound direction, but named concerns must be resolved before
  staging; artifact stays in experiments/.
- REJECT — findings feed the next iteration's Tier 1 as context.

## Output contract

Return ONE JSON object:
```json
{"verdict": "APPROVE|CONDITIONAL|REJECT",
 "findings": ["..."], "notes": ["..."], "summary": "one sentence"}
```
