# Tier 2 builder — spec_finding → staged spec diff

{program}

## Winning candidate

{candidate}

## Pinned spec file(s), base commit {spec_commit}

{spec_files}

## Task

Write `spec-diff.md`: a staged change proposal that closes the finding.
Requirements:

- Open with a header block: `Base-Commit: {spec_commit}`, `Target-File:
  <repo-relative path>`, `Finding: <candidate id>`.
- Express the change as a unified diff (```diff fenced) against the pinned
  text — minimal, surgical, additive where possible. Never rewrite sections
  the finding does not touch.
- Follow with a **Rationale** section: the divergence/attack the current
  text permits, quoted; why this wording closes it; RFC 2119 keyword
  choices justified.
- Follow with an **Impact** section: effect on the 28 published vectors
  (must be none, or name the vector artifact that must accompany this diff),
  wire-compat statement, -02 relevance.
- You are writing a STAGED artifact. The loop never applies it; the founder
  does, via APPLY.md. Do not reference applying it yourself.

Return ONLY the artifact markdown (it will be saved verbatim as spec-diff.md).
