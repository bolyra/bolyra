# Tier 2 builder — spec_finding → staged spec diff

{program}

## Winning candidate

{candidate}

## Pinned spec file(s), base commit {spec_commit}

{spec_files}

## Claim discipline (rule 2k)

You have NO tool access: you cannot read repository files beyond the excerpts
in this prompt. Make claims ONLY about text quoted in this prompt. If the
candidate's argument depends on code you cannot see, write "requires
maintainer verification against <file>" instead of asserting it — an
unverified assertion fails review.

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
- You are writing a STAGED artifact. Include ONLY the header block, the
  ```diff block, Rationale, and Impact. Do NOT include apply, installation,
  git, or workflow instructions of ANY kind (no `git apply`, no worktrees,
  no command sequences) — the staging pipeline generates APPLY.md with the
  founder's apply steps separately, and an artifact containing them is
  dropped at acceptance.

Your output MUST begin with exactly these three lines, filled in, before
anything else (artifacts without them fail the objective check unread):

```
Base-Commit: {spec_commit}
Target-File: <repo-relative path of the file the diff targets>
Finding: <the candidate id>
```

Return ONLY the artifact markdown (it will be saved verbatim as spec-diff.md).
