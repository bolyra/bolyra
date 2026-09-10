# Public Conformance Claims -- Design Document

**Date:** 2026-09-10
**Author:** Claude (Fable 5.1) + Codex (gpt-6-astra) brainstorm; founder-approved scope
**Status:** DRAFT (pending spec review)

## 1. Motivation

Every external interoperability claim Bolyra publishes is already mechanically
reproducible from pins alone: `interop/claims.json` holds the claims,
`interop/replay.js` replays them, and the `interop-replay` workflow has
reproduced 2/2 in a clean runner. None of that is visible outside the
repository, and there is no path for a new implementer to add a claim.

Two adopters (khandrew1, host-side; stillmarcus24, verifier-side) ran the
conformance suite voluntarily. A third party (arian-gogani, AAR) adopted three
EVC design distinctions without running anything. The strategic risk named in
the 2026-09-10 brainstorm is **substitution**: others satisfy users with EVC's
distinctions while bypassing EVC. The one signal pointing at *conversion*
rather than substitution is someone running the suite to prove they match.
This build makes that status public, replayable, and earnable.

Explicitly not the goal: buyer pull, pilots, or operator conversations. Codex
scoring: "supports the substitution-defense rationale; does not establish
operator conversion."

## 2. Scope

### In
- **`landing/conformance.html`**: one page rendering every claim in
  `interop/claims.json`: implementer, pinned implementation commit, suite
  commit, vector-set version, vectors sha256, covered classes, claim kind,
  `verified_on`, and a link to the public `interop-replay` workflow runs.
- **Explicit coverage boundaries** on every row. `external-suite` rows say
  "own-corpus reproduction, NOT Bolyra-suite conformance" in the row itself,
  carrying `claim_text` verbatim.
- **Generator + drift guard**: `landing/gen-conformance.js` renders the page
  from `claims.json`; `node landing/gen-conformance.js --check` fails CI when
  the committed HTML drifts from the registry.
- **Submission contract** (`interop/SUBMITTING.md`): a PR adds one
  `claims.json` entry and, for `bolyra-suite` kind, one adapter under
  `interop/adapters/`. `node interop/replay.js --check` must pass offline
  before a maintainer applies the `replay-approved` label.
- **Label-gated replay workflow**: a `pull_request` job that runs only when a
  maintainer applies `replay-approved`, executes with `contents: read`, no
  secrets, `persist-credentials: false`, and replays only the claims the PR
  adds or changes.
- **Landing copy fixes on the same surface**: advertised
  `@bolyra/evc-conformance` version 0.5.0 -> 0.6.0 and vector count 40 -> 41;
  remove "hosted verifier preview is live for design partners" and "Pilot
  against Bolyra's hosted verifier preview today" (contradicts the 2026-08-27
  ruling not to build the hosted platform); the CTA describes what exists.

### Out
New demos or examples, new vector classes, adapters written on an
implementer's behalf, hosted verification, accounts, dashboards, certification
badges or logos, x402 #3376 hardening, Dependabot remediation, any revival of
the killed AAR/Nobulex adapter or `checked_layers` schema expansion, and any
mechanism that writes replay results back into the repository from a job that
ran third-party code.

## 3. Architecture

```
interop/claims.json  --gen-conformance.js-->  landing/conformance.html  --deploy.sh-->  bolyra.ai/conformance
        ^                                                ^
        |  PR adds entry (+ adapter)                     |  --check in CI: committed HTML == generated
        |                                                |
  interop-replay-pr.yml (label: replay-approved) ----> replays ONLY the PR's claims, read-only, no secrets
```

### 3.1 Generator: `landing/gen-conformance.js`
- Zero dependencies (matches `replay.js`, `sync.js`).
- Reads `interop/claims.json`; validates it with the same shape checks
  `replay.js --check` applies (reuse by `require`-ing the validator if it is
  exported; otherwise duplicate the minimal checks and add a test that both
  agree).
- Emits deterministic HTML: stable ordering (by `verified_on` desc, then id),
  no timestamps of generation, so `--check` is a byte comparison.
- `--check`: regenerate to a temp string and compare with the committed file;
  exit 1 with a unified diff on drift. Wired into `ci.yml` next to the existing
  `sync:check` step.
- Escapes every registry string for HTML. Registry values are data written by
  PR authors; they are never interpolated as markup.

### 3.2 Page: `landing/conformance.html`
- Static, self-contained, same visual system as `index.html` (reuse its
  stylesheet block; no new JS).
- Per-claim row: implementer repo link, implementation commit (full SHA in a
  `<code>`, short form displayed), suite commit, vector-set version,
  `test_vectors_sha256`, `runner_args` rendered as "covered classes", kind
  badge text (`bolyra-suite` / `external-suite`), `claim_text` verbatim,
  `scope` verbatim when present, `verified_on`, and one link to
  `https://github.com/bolyra/bolyra/actions/workflows/interop-replay.yml`.
- A short "How to add yours" section linking `interop/SUBMITTING.md`.
- Added to `deploy.sh`'s explicit file list (the script errors on a missing
  file, so this is a required edit, not optional).

### 3.3 Submission contract: `interop/SUBMITTING.md`
1. Fork; add one entry to `interop/claims.json` following the schema in
   `interop/README.md`. For `bolyra-suite`, add `interop/adapters/<name>.ts`
   (pure I/O, per README rules) and set `adapter_sha256`.
2. Run `node interop/replay.js --check` locally; it must pass offline.
3. Open the PR. CI runs `--check` and the generator `--check` (both offline,
   no third-party code). Nothing else runs yet.
4. A maintainer reviews the adapter and the pins, then applies
   `replay-approved`. That triggers the replay of the PR's claims.
5. Green replay + CODEOWNERS review -> merge -> the row appears on the next
   landing deploy.
6. Rules restated from README: a red replay means investigate, never edit the
   claim; claims stay pinned; re-verification at a newer set is a new row.

### 3.4 Label-gated replay: `.github/workflows/interop-replay-pr.yml`
```yaml
on:
  pull_request:
    types: [labeled]
    paths: ['interop/claims.json', 'interop/adapters/**']
permissions:
  contents: read
jobs:
  replay-pr:
    if: github.event.label.name == 'replay-approved'
    runs-on: ubuntu-latest
    steps:
      - checkout PR head, fetch-depth: 0, persist-credentials: false
      - setup-node 20, no cache
      - node interop/replay.js --check
      - node interop/replay.js --changed-since origin/main   # only the PR's claims
```
- **Event choice is the security decision.** `pull_request` (not
  `pull_request_target`) runs in the PR's context with a read-only token and
  no repository secrets, which is the correct posture for executing untrusted
  adapters. The label is a maintainer approval gate on top, so no third-party
  code runs merely because a PR was opened.
- Label removal + re-apply re-runs. A push to the PR after labeling does NOT
  re-run automatically (the event is `labeled`, not `synchronize`), so a
  maintainer must re-label after reviewing new commits. This is deliberate:
  code that changed after approval is not approved.
- `replay.js --changed-since <ref>`: new flag; diffs `claims.json` against the
  ref and replays only added or modified claim ids. Full replay stays on the
  existing dispatch workflow.
- Create the `replay-approved` label (repo has no such label today).
- Enable "Require approval for all outside collaborators" in Actions settings
  as a second belt (documented in SUBMITTING.md; not enforceable from code).

### 3.5 Landing copy changes (`landing/index.html`)
- `@bolyra/evc-conformance@0.5.0` -> `@0.6.0`; "40 wire-contract vectors" ->
  "41". `verify.sh` resolves the advertised version from the page's own
  string, so the string must be exact.
- Delete both hosted-verifier-preview sentences. Replace the pilot CTA copy
  with what exists: the published suite, the reference implementations, and
  the self-hosted `bolyra verify` path. Keep the "Book a 20-min technical fit
  call" link; it is truthful.
- Link the new page from the existing conformance section.

## 4. Data flow

Registry (`claims.json`, PR-authored, CODEOWNERS-reviewed) -> generator
(deterministic, escaped) -> committed HTML (drift-guarded in CI) ->
`deploy.sh` -> S3/CloudFront -> `verify.sh` (string + runtime checks). Replay
results never flow into the repo from CI; the page links to the public run
history instead.

## 5. Error handling

- Malformed `claims.json`: generator exits 1 with the validator's message; CI
  red; nothing deploys.
- Drift between registry and committed HTML: `--check` red with a diff.
- Missing `conformance.html` at deploy: `deploy.sh` already errors.
- Replay failure on a PR: job red; maintainer does not merge; per README the
  claim is investigated, never edited to pass.
- Label applied by a non-maintainer: only users with triage+ can label, which
  on this repo is the owner; documented as an assumption to re-check if
  collaborators are added.

## 6. Testing

- `landing/gen-conformance.test.js` (node:test, zero deps): deterministic
  output for a fixture registry; `--check` passes on identical input and fails
  with a diff on a one-byte change; HTML escaping of `<script>` in a
  `claim_text`; `external-suite` rows carry the own-corpus qualifier;
  ordering is stable.
- `interop/replay.test.js`: add cases for `--changed-since` (new claim,
  modified claim, unchanged claim skipped, removed claim ignored).
- CI: generator `--check` on every push; the label job proven with a test PR
  that adds a deliberately failing claim, confirming red, then a passing one,
  confirming green. Both recorded in the PR description.
- Landing: `landing/verify.sh` green after deploy, including the new version
  string; live curl for the four changed strings and the absence of the two
  deleted sentences.

## 7. Completion criterion

Both existing claims are publicly accessible with provenance and a link to
replay history. A test submission PR triggers replay via the label without
manual dispatch; a passing submission can reach merge, and a hash mismatch or
failing replay cannot appear as passing. `SUBMITTING.md` suffices to reproduce
the path without asking. The misleading hosted-verifier copy is gone and the
advertised version is current.

## 8. Kill criterion (Codex)

If, within 30 days of the public records reaching both existing adopters,
neither references or uses its record and no new independent implementer
submits a claim: stop expanding this feature. Leave the accurate page
operational. Page views alone do not justify continuation.

## 9. Open questions for review

1. Should `verified_on` be re-stamped when the dispatch workflow replays
   green, or is the registry's original date the right invariant? (Design
   says: original date; replay history is the freshness signal.)
2. Is `--changed-since` worth the new code path versus replaying all claims
   on every labeled PR (currently two, so cheap)? Design keeps it minimal but
   proposes the flag because full replays will not stay cheap.
