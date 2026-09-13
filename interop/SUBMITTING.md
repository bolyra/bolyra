# Submitting a conformance claim

> **Status: not yet accepting submissions.** The isolated dispatch workflow
> this document describes (spec §3.5) has not landed. Until it does, a pull
> request of this shape will pass its offline checks but will not be replayed
> or merged. The process is published now so it can be reviewed before it is
> live; this notice is removed in the pull request that enables it.

This is the maintainer-operated path (v1). Nothing on a pull request executes
third-party code; the maintainer replays your exact commit by hand before
merging. It relies on maintainer discipline, stated here so nobody mistakes it
for machine enforcement. The isolation your code runs under is described in
`docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md` §3.5.

## What you submit

Exactly one pull request that touches only:

- `interop/claims.json` — **one added entry**, nothing else changed;
- for `bolyra-suite` claims, **one new** file `interop/adapters/<name>.ts`
  (pure I/O, see README rules) with its sha256 in `adapter_sha256`;
- `landing/conformance.html` — regenerated (below).

Do not modify existing claims or adapters. Do not set `verification_run_url`.

`implementer.install` must be exactly one of:

    ["npm", "ci", "--ignore-scripts"]
    ["npm", "install", "--ignore-scripts"]

optionally followed by `"--no-audit"` and/or `"--no-fund"`, in that order.
`external-suite` claims need a digest-pinned `node:` image
(`node:<tag>@sha256:<64 hex>`), `"network": "none"`, and integer
`run.expect.pass`, `run`, and `scoped_out`. `implementer.repo` must be
`https://github.com/<owner>/<repo>`.

What is enforced mechanically, on every pull request, by CI:

- the field shapes above — `implementer.repo`, `implementer.install`, the
  `node:` image and `network`, integer counts, the adapter pathname — by
  `node interop/replay.js --check` (`validateClaim` in `interop/replay.js`);
- `verification_run_url` being absent, and the page matching the registry,
  by `node landing/gen-conformance.js --check`.

What is enforced only by maintainer review: that the pull request touches
only the files listed, adds exactly one entry, and changes no existing claim
or adapter. Nothing mechanical checks those yet.

## Steps

1. Fork and branch from current `main`. Clone with full history — the
   offline check reads historical suite pins with `git show`, which fails on
   a `--depth 1` clone.
2. Add your entry (schema: README.md; copy an existing entry of the same kind).
3. Run `node interop/replay.js --check` — must pass offline.
4. Run `node landing/gen-conformance.js` and commit the regenerated
   `landing/conformance.html` together with your entry (and adapter).
5. Open the PR. CI runs the offline checks. Nothing executes your code yet.
6. The maintainer reviews the adapter and the pins, notes your head SHA, and
   runs the `Interop replay` workflow by dispatch (Actions → Interop replay →
   Run workflow → branch `main`, `ref=<that SHA>`, `claim=<your id>`). The
   reviewed `claims.json` and your one new adapter are overlaid from that SHA
   (which is why "one added entry, nothing else changed" is reviewed by hand);
   only the selected claim replays; the harness runs from `main`. Before
   dispatching, the maintainer runs `git diff main...<SHA> -- interop/claims.json`
   and rejects the submission if any pre-existing entry changed. Any push
   after that review needs a fresh review and a fresh dispatch.
7. Green dispatch on the reviewed SHA + code-owner review → merge → your row
   appears on https://bolyra.ai/conformance at the next deploy. The dispatch
   run URL is recorded as a comment on your PR before merge. (Spec §3.3 says
   "in the merge commit"; this repo rebase-merges, which leaves no editable
   merge message, so a PR comment is the durable place. Deliberate.)

## Rules (from README)

- A red replay means investigate, never edit the claim.
- Claims stay pinned; re-verification at a newer suite is a **new** row.
- `external-suite` results are own-corpus reproductions, not Bolyra-suite
  conformance; the page says so on every such row regardless of your text.
