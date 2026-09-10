# Public Conformance Claims -- Design Document

**Date:** 2026-09-10
**Author:** Claude (Fable 5.1) + Codex (gpt-6-astra) brainstorm; founder-approved scope
**Status:** DRAFT v2 (spec-reviewer + Codex round 1 applied; pending round 2)

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

Not the goal: buyer pull, pilots, or operator conversations. Codex scoring:
"supports the substitution-defense rationale; does not establish operator
conversion."

## 2. Scope

### In
- **`landing/conformance.html`**: one page rendering every claim in
  `interop/claims.json` (section 3.2).
- **Explicit coverage boundaries** on every row; `external-suite` rows carry
  the own-corpus qualifier inserted by the generator, independent of
  author-provided text.
- **Generator + drift guard**: `landing/gen-conformance.js` renders the page
  from `claims.json`; `--check` fails CI when the committed HTML drifts.
- **Submission contract** (`interop/SUBMITTING.md`): one PR adds exactly one
  claim (+ one new adapter for `bolyra-suite`) and the regenerated page.
- **Trusted, label-gated replay of submissions** (section 3.4): workflow and
  harness from base; only the submission's data and adapter come from the PR;
  read-only token; no secrets; maintainer approval bound to an exact SHA; a
  merge-blocking gate that fails until that SHA has replayed green.
- **CI additions**: `node interop/replay.js --check` and the generator
  `--check` on every push and PR.
- **Landing copy on the same surface**: current suite version and counts;
  removal of every hosted-verifier-preview sentence (the 2026-08-27 ruling was
  not to build the hosted platform); a CTA that describes what exists; and
  version preflight/guard coverage for `@bolyra/evc-conformance` in
  `deploy.sh`/`verify.sh`, which today check only sdk/payment-protocols/
  gateway/cli.

### Out
New demos or examples, new vector classes, adapters written on an
implementer's behalf, hosted verification, accounts, dashboards, certification
badges or logos, live replay status or results write-back from CI, x402
#3376 hardening, Dependabot remediation, edits to existing pinned claims or
adapters via the submission path, and any revival of the killed AAR/Nobulex
adapter or `checked_layers` schema expansion.

## 3. Architecture

```
interop/claims.json --gen-conformance.js--> landing/conformance.html --deploy.sh--> bolyra.ai/conformance
        ^                                            ^
        | PR: +1 claim, +1 adapter, regenerated page | CI --check: committed HTML == generated
        |
  interop-submission.yml (pull_request_target, base-controlled, contents:read, no secrets)
     claims-gate  : fails until the current head SHA has a green replay status; required check
     replay-claim : runs ONLY on `replay-approved` label by @saneGuy on a matching SHA;
                   base checkout + overlay of the PR's claims.json and new adapter; sets status
```

### 3.1 Generator: `landing/gen-conformance.js`
- Zero dependencies (matches `replay.js`, `sync.js`).
- Reads `interop/claims.json`; validates every entry with
  `require('../interop/replay.js').validateClaim` (already exported at
  `replay.js:393`). Rejects unknown `kind` values explicitly (`validateClaim`
  treats non-`external-suite` as `bolyra-suite`; the generator does not).
  Because `validateClaim` resolves `adapter` relative to `interop/` on disk,
  test fixtures for `bolyra-suite` claims must reference real adapter files
  under a temp `interop/` layout; `external-suite` fixtures need none.
- Deterministic output: ordered by `verified_on` desc then `id`; no generation
  timestamps; `--check` is a byte comparison that exits 1 with a unified diff.
- Every registry string is HTML-escaped. **Link destinations are validated,
  not merely escaped**: `implementer.repo` must match
  `^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`; commit links are
  constructed from that validated URL plus the 40-hex `commit`; an optional
  `verification_run_url` must match
  `^https://github\.com/bolyra/bolyra/actions/runs/\d+$`. Any other value
  fails generation (exit 1), never renders.
- The page carries its own copy of the stylesheet rules it needs (it does not
  extract from `index.html` at generation time, so `index.html` style edits
  cannot trip `--check`).

### 3.2 Page: `landing/conformance.html`
Static, self-contained, no JS. Per claim:
- Implementer repo (validated link), implementation commit (full SHA in
  `<code>`, linked), suite commit, vector-set version, `test_vectors_sha256`.
- **Kind** as plain text (`bolyra-suite` / `external-suite`); no badge or logo.
- **Covered classes**: for `bolyra-suite`, derived only from validated
  `runner_args` selectors of the form `--type <class>`; otherwise "Not
  specified". **Runner arguments**: the raw `runner_args` value, labeled as
  such. For `external-suite`, "Covered classes: not applicable (own corpus)".
- `claim_text` and `scope` verbatim; for `external-suite` the generator
  additionally inserts the fixed sentence "Own-corpus reproduction: the
  implementer's published numbers reproduce at the pin. This is NOT Bolyra-
  suite conformance."
- **Recorded verification date**: `verified_on`. Directly beneath, page-wide:
  "These are dated claims. This page does not report current replay status."
- Links, each labeled: "Full-registry replay history" ->
  `.../actions/workflows/interop-replay.yml`; "Submission replay history" ->
  `.../actions/workflows/interop-submission.yml`; and, when a claim carries
  `verification_run_url`, "Verification run for this claim" -> that URL.
- "How to add yours" -> absolute
  `https://github.com/bolyra/bolyra/blob/main/interop/SUBMITTING.md`.
- `deploy.sh`: add the variable, the pre-check loop entry, two `aws s3 cp`
  calls (`/conformance.html` and `/conformance`), and both paths in the
  CloudFront invalidation list.

### 3.3 Submission contract: `interop/SUBMITTING.md`
1. Fork; add **exactly one** entry to `interop/claims.json` per the schema in
   `interop/README.md`. For `bolyra-suite`, add **one new** file
   `interop/adapters/<name>.ts` (pure I/O, README rules) and set
   `adapter_sha256`. Do not modify any existing claim or adapter.
2. Run `node interop/replay.js --check` (offline pins/schema) and
   `node landing/gen-conformance.js`; commit the regenerated
   `landing/conformance.html` with the claim and adapter.
3. A submission PR may touch ONLY: `interop/claims.json`, the one new file
   under `interop/adapters/`, and `landing/conformance.html`. Any other path
   makes `claims-gate` fail. Workflow, harness, runner, and dependency changes
   are never accepted through this path; open a separate PR.
4. Open the PR. `claims-gate` runs and FAILS with "awaiting approved replay";
   the offline checks run in ordinary CI. No third-party code runs.
5. The maintainer reviews the adapter and pins, notes the exact head SHA, and
   applies `replay-approved`. `replay-claim` runs for that SHA and sets a
   commit status. `claims-gate` re-evaluates and passes only on success.
6. Any push after approval invalidates it: the status is bound to the old
   SHA, `claims-gate` fails again, and the maintainer must re-review and
   re-label. Removing the label does not cancel a running job; the maintainer
   cancels it manually when revoking approval.
7. Green gate + CODEOWNERS review -> merge -> the row appears on the next
   landing deploy. README rules restated: a red replay means investigate,
   never edit the claim; claims stay pinned; re-verification at a newer set is
   a new row.

### 3.4 Trusted submission workflow: `.github/workflows/interop-submission.yml`

**Why `pull_request_target`, and why it is safe here.** Round 1 established
that on the `pull_request` event the workflow file, `replay.js`, and the
runner all execute from the PR's ref, so a PR can rewrite any of them and
produce a green check; the `paths:` filter only affects triggering. A green
result on `pull_request` is therefore not evidence. `pull_request_target`
runs the workflow definition from the base branch, so the harness is trusted.
Its documented danger is checking out and executing PR code while holding a
privileged token or secrets. This workflow does neither: the token is
downgraded explicitly, no secrets are referenced, no caches are used,
credentials are not persisted, and the only PR-sourced bytes that execute are
the one adapter the maintainer reviewed and approved by SHA. That is the same
blast radius as the existing dispatch job (compute, egress, public reads).
This is the repo's only use of `pull_request_target`; this section is the
justification.

```yaml
name: Interop submission
on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled, unlabeled]
permissions:
  contents: read
  statuses: write        # only to record the replay result on the head SHA
concurrency:
  group: submission-${{ github.event.pull_request.number }}
  cancel-in-progress: false

jobs:
  claims-gate:           # required status check in branch protection
    runs-on: ubuntu-latest
    steps:
      - checkout BASE (ref: main), fetch-depth: 0, persist-credentials: false
      - fetch the PR head SHA as a detached object: git fetch origin <head.sha>
      - node interop/submission-check.js --base main --head <head.sha>
          # fails unless: changed paths ⊆ {interop/claims.json, one new
          # interop/adapters/*, landing/conformance.html}; base→head registry
          # diff is exactly ONE added claim and zero modified/removed; no
          # existing adapter modified; head claims.json passes validateClaim.
          # If the PR touches none of the claim paths: exit 0 (not a submission).
      - query commit status "interop/replay" on <head.sha>; pass only if
        state == success; else fail "awaiting approved replay of <head.sha>"

  replay-claim:
    needs: claims-gate     # never runs on an out-of-scope diff
    if: >
      github.event.action == 'labeled' &&
      github.event.label.name == 'replay-approved' &&
      github.event.sender.login == 'saneGuy'
    runs-on: ubuntu-latest
    steps:
      - checkout BASE (ref: main), fetch-depth: 0, persist-credentials: false
      - echo "replaying head ${{ github.event.pull_request.head.sha }}"
      - git fetch origin <head.sha>; git checkout <head.sha> --
          interop/claims.json interop/adapters/<the one new file>
          # overlay ONLY the submission's data and adapter; harness stays base
      - setup-node 20, package-manager-cache: false
      - node interop/replay.js --check
      - node interop/replay.js --claim <id from submission-check>
      - set commit status "interop/replay" = success|failure on <head.sha>
        (the only step that uses the token; adapters run in earlier steps
        with no token in their environment)
```

Properties, stated plainly:
- The gate and the replay both run base-controlled code. A submission cannot
  alter what checks it.
- Approval is bound to an exact SHA: the status is written on `head.sha`;
  any new commit has no status and fails the gate. Re-runs of a completed job
  replay the originally approved SHA.
- The approving actor is restricted to the maintainer login; a label applied
  by anyone else does not run adapters.
- "Skipped" cannot satisfy the gate: `claims-gate` itself is the required
  check, and it fails (not skips) while awaiting replay.
- What the mechanism does NOT do: it does not judge whether an adapter is
  honest. The label is a *reviewed submission gate*; the maintainer's review
  of the adapter is the only defense against a malicious adapter, and this
  is written into SUBMITTING.md and the workflow header.
- Fork PRs on `pull_request_target` do not wait for "Approve and run"; the
  label is the sole execution gate. The Actions setting "Require approval for
  all outside collaborators" is still enabled for the `pull_request`-based
  `ci.yml`.
- Create the `replay-approved` label (none exists today).
- Full-registry replay stays on the dispatch workflow, unchanged.

### 3.5 Landing copy changes (`landing/index.html`) and deploy/verify coverage
Exact edits (line numbers as of `f106b00`):
- 948: delete "A hosted verifier preview is live for design partners:
  `POST /v1/verify` ..." (the whole sentence).
- 953: delete "Pilot against Bolyra's hosted verifier preview today, ...".
- 1031: delete "Hosted `POST /v1/verify` preview for design partners, same
  External Verifier Contract".
- 955: "10 domain-agnostic wire-envelope vectors" -> "11 domain-agnostic
  wire-envelope vectors".
- Every advertised suite string: literally `@bolyra/evc-conformance@0.6.0`
  and `41 wire-contract vectors`, including executable examples.
- Replacement CTA copy (Codex text): "Run the published conformance suite,
  explore the reference implementations, or verify locally with `bolyra
  verify`." Keep the "Book a 20-min technical fit call" link. Keep historical
  claim pins (e.g. "27/27 set 0.5.0 @ 17642a5") untouched.
- Link the conformance section to `/conformance`.
- `deploy.sh`: add `preflight_version "@bolyra/evc-conformance"
  "@bolyra/evc-conformance@"`. `verify.sh`: add the matching `guard_version`,
  and a check that the advertised count matches the installed package: run
  the resolved `@bolyra/evc-conformance@<advertised>` self-test from an empty
  dir and assert its "N test vectors loaded" equals the advertised total.

## 4. Data flow
Registry (PR-authored, gate-validated, CODEOWNERS-reviewed) -> generator
(deterministic, escaped, link-validated) -> committed HTML (drift-guarded) ->
`deploy.sh` -> S3/CloudFront -> `verify.sh`. Replay results flow only into a
commit status on the PR head SHA and into public run history; never into the
repository.

## 5. Error handling
- Malformed or unsafe registry entry: generator exits 1; CI red; no deploy.
- Drift: `--check` red with a diff.
- Out-of-scope submission diff, >1 claim, modified claim/adapter: gate red
  with the offending paths/ids named.
- Replay failure: status failure; gate red; per README the claim is
  investigated, never edited to pass.
- Label by non-maintainer or on a non-matching SHA: no replay; gate red.
- Missing `conformance.html` at deploy: `deploy.sh` errors.

## 6. Testing
- `landing/gen-conformance.test.js` (node:test): deterministic output;
  `--check` passes on identical input, fails with diff on a one-byte change;
  `<script>` in `claim_text` is escaped; `javascript:` and non-GitHub
  `implementer.repo` fail generation; unknown `kind` fails; external-suite
  rows carry the fixed qualifier regardless of `claim_text`; stable ordering;
  covered-classes derivation only from `--type` selectors.
- `interop/submission-check.test.js`: exactly-one-added passes; zero added,
  two added, modified existing, removed existing, extra path, modified
  existing adapter each fail with the right message; non-submission PR exits 0.
- `interop/replay.test.js`: all 18 existing parser tests retained, unchanged.
- Workflow proof on a test PR, recorded in the implementation PR: unrelated
  label -> no replay, gate red; push after approval -> gate red again;
  hash-mismatched claim -> replay failure, gate red; passing claim -> green;
  relabel after fresh push -> green.
- CI: `node interop/replay.js --check` added to the `evc-conformance` job in
  `ci.yml` (which today runs only `node --test interop/replay.test.js`); that
  job's checkout gets `fetch-depth: 0` because `checkSuitePin` uses
  `git show <suite.commit>:spec/test-vectors.json`. Generator `--check` in
  the same job.
- Landing after deploy: `verify.sh` green including the new evc-conformance
  guard; live curl asserts the four changed strings present, the three
  deleted sentences absent, and `/conformance` reachable with both claims.

## 7. Completion criterion
Both existing claims are publicly accessible with provenance, dated
verification, and labeled links to replay history. A test submission PR is
blocked by `claims-gate` until a maintainer labels a reviewed SHA, then
replays via base-controlled code and passes; a hash mismatch or failing
replay leaves the gate red; a skipped or foreign-label run cannot satisfy it.
`SUBMITTING.md` suffices to reproduce the path without asking. All
hosted-verifier copy is gone and the advertised suite version and counts are
current and machine-checked at deploy.

## 8. Kill criterion (Codex)
If, within 30 days of the public records reaching both existing adopters,
neither references or uses its record and no new independent implementer
submits a claim: stop expanding this feature. Leave the accurate page
operational. Page views alone do not justify continuation.

## 9. Decided questions
1. `verified_on` is the recorded date and is never re-stamped; the page says
   so explicitly. Per-claim `verification_run_url` is optional and manual.
2. No generic `--changed-since`. Submissions are exactly one new claim;
   `submission-check.js` derives the id and the existing `--claim <id>`
   selector replays it. Full replay stays on dispatch.
