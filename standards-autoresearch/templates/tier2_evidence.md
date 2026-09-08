# Tier 2 builder — evidence_opportunity → interop-evidence material

{program}

## Winning candidate

{candidate}

## Context: current evidence ledger tail + implementer facts

{ledger_tail}

## Claim discipline (rule 2k)

You have NO tool access: you cannot read repository files beyond the excerpts
in this prompt. Make claims ONLY about text quoted in this prompt. If the
candidate's argument depends on code you cannot see, write "requires
maintainer verification against <file>" instead of asserting it — an
unverified assertion fails review.

## Task

Write `evidence.md`: a self-contained, third-party-reproducible run record
or RFC 7942 implementation-status material (the candidate says which).
Requirements:

- Every command pinned: exact commits, exact invocations, expected outputs.
- Runs must be executable locally with zero outbound contact (rule 2c);
  if the candidate requires contacting anyone, output exactly the line
  `BLOCKED: requires outbound` and nothing else.
- The procedure MAY create and use ONE isolated scratch workspace (a fresh
  temp dir or a network-isolated container) for clones and re-runs of pinned
  code; say so explicitly. It must not touch `spec/` or any repo tree, and
  you are DESCRIBING the procedure — never state that you ran it.
- End with a fenced JSON ledger entry:
  `{"id": "...", "kind": "interop_run|implementation|citation|registry_event",
    "subject": "...", "pinned_commit": "...", "reproduce_cmd": "...",
    "urls": [], "rfc7942_ready": false}`
- The claim each record substantiates is stated in one sentence, literally,
  with no superlatives (honesty rule: standards context).

Return ONLY the artifact markdown.
