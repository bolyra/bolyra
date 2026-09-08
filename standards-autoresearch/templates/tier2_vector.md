# Tier 2 builder — vector_gap → host-conformance vector

{program}

## Winning candidate

{candidate}

## Existing vector entries (host_behavior, set {vector_set}) — schema by example

{vector_schema}

## Existing fixture example (a misbehaving-verifier script the host spawns)

{fixture_example}

## Claim discipline (rule 2k)

You have NO tool access: you cannot read repository files beyond the excerpts
in this prompt. Make claims ONLY about text quoted in this prompt. If the
candidate's argument depends on code you cannot see, write "requires
maintainer verification against <file>" instead of asserting it — an
unverified assertion fails review.

## Task

Produce ONE new host-conformance vector: an entry for `spec/test-vectors.json`
plus (usually) a new fixture script for `spec/fixtures/host-conformance/`.
Requirements:

- The vector must test HOST BEHAVIOR derivable from the spec text alone —
  never an implementation detail of the reference hosts. `description` cites
  the exact spec clause (§) it enforces and the divergence it catches.
- The entry matches the existing schema exactly: `id` (kebab, `host-` prefix),
  `description`, `type: "host_behavior"`, `inputs: {fixture, timeout_ms}`,
  `expected: {result: "PASS", host_decision | failure_class}` following the
  contract's precedence order.
- The fixture script follows the house pattern: `#!/usr/bin/env node`,
  a comment naming the misbehavior and spec clause, reads stdin, misbehaves
  deterministically. Include the `_pidfile.js` preamble ONLY if the vector
  asserts kill behavior.
- ADDITIVE: runs alongside the existing 28; none of them may change.

Return ONLY one JSON object (no fences, no prose):

```
{"vector": { ...test-vectors.json entry... },
 "fixture_js": "<full fixture source, or null if reusing an existing fixture>",
 "fixture_name": "<filename.js or null>"}
```
