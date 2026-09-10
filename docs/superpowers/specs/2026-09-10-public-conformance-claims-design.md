# Public Conformance Claims -- Design Document

**Date:** 2026-09-10
**Author:** Claude (Fable 5.1) + Codex (gpt-6-astra) brainstorm; founder-approved scope
**Status:** DRAFT v4 (rounds 1-3 applied from both reviewers; pending round 4)

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
- **Trusted, label-gated replay of submissions** (section 3.4): one
  base-controlled workflow, registered as a **required workflow in a
  repository ruleset** so the check's identity is pinned to that file at
  `main`; read-only token; no secrets, no caches, no status writes;
  third-party code confined to a container without the runner environment;
  execution only when a maintainer label is present AND the maintainer's
  approving review is bound to the exact head SHA; only the submission's
  data and one adapter come from the PR.
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
  interop-submission.yml  (REQUIRED WORKFLOW via ruleset => identity pinned to main; base-controlled;
                           contents:read + pull-requests:read only; no secrets/caches/status writes)
     submission-check : classifies the diff as DATA; outputs is_submission, claim id, adapter, kind
     replay-claim     : THE required check. non-submission -> pass. submission without
                        (label present AND maintainer APPROVED review at commit_id == head.sha
                         AND live head == captured head) -> FAIL. else overlay the validated
                        files and replay `--claim <id>` INSIDE A CONTAINER (no runner env).
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
3. A submission PR may touch ONLY: `interop/claims.json`, one new regular
   file under `interop/adapters/` (for `bolyra-suite`; none for
   `external-suite`), and `landing/conformance.html`. Anything else fails
   `submission-check`. Workflow, harness, runner, and dependency changes are
   never accepted through this path; open a separate PR. Submission branches
   must contain the current base of `main` (rebase before asking for review;
   any commit to `main` between review and merge changes the head SHA on
   rebase and requires a fresh approving review, accepted cost at current
   volume).
4. Open the PR. `submission-check` validates the diff; `replay-claim` (the
   required check) FAILS with "awaiting maintainer review + replay-approved on
   <head.sha>". Offline checks run in ordinary CI. No third-party code runs.
5. The maintainer reviews the adapter and pins and submits an **approving PR
   review** (GitHub records the reviewed `commit_id`), then applies
   `replay-approved`. `replay-claim` re-runs, confirms the approving review's
   `commit_id` equals the current head SHA, replays, and its own conclusion
   is the check.
6. Any push after approval changes the head SHA; the approving review no
   longer matches; `replay-claim` fails again until the maintainer submits a
   new approving review on the new SHA. A submitted or dismissed review
   re-triggers the workflow (`pull_request_review` is a trigger), so
   re-approval restarts the check without a manual rerun. The label may
   stay; it is necessary, not sufficient. A run whose captured head no longer
   equals the live PR head fails "head moved" before touching any PR bytes.
7. Green `replay-claim` + CODEOWNERS review -> merge -> the row appears on
   the next landing deploy. README rules restated: a red replay means
   investigate, never edit the claim; claims stay pinned; re-verification at
   a newer set is a new row.

### 3.4 Trusted submission workflow: `.github/workflows/interop-submission.yml`

**Threat model, stated honestly.** Three kinds of PR-sourced code execute
after approval: the reviewed adapter; the implementer repository at its
pinned commit (`npm ci` + `tsx` for `bolyra-suite`; the kit's own test
command inside a network-less container for `external-suite`); and the
`install`/`run` argv fields of the claim. A maintainer can review the adapter
and the *shape* of the pins and argv; a maintainer cannot review a whole
third-party repository. Therefore: review is the control for the adapter and
the argv fields (allowlisted below); **isolation** is the control for the
implementer's code; and the mechanism guarantees only that GitHub records the
outcome of executing maintainer-approved code from a base-controlled
harness. Malicious approved code can invalidate its own PR's outcome; it
cannot reach any other PR's check, any token that writes, or any cache that
base-branch workflows restore.

**Why `pull_request_target`.** On the `pull_request` event the workflow
file, `replay.js`, and the runner execute from the PR's ref. A green result
there is not evidence. `pull_request_target` runs the definition from the
base. Its documented danger is executing PR code while holding a privileged
token or secrets; this workflow holds neither.

**Why a ruleset-required workflow.** Branch-protection required status
checks match by *name*. A PR that edits `ci.yml` to add a green job named
`replay-claim` would produce a same-name check on the same SHA. A repository
ruleset "Require workflows to pass" pins the required check to
`.github/workflows/interop-submission.yml` at `main`, so a same-name job from
any other workflow cannot satisfy it. **Prerequisite (plan task 1):** confirm
rulesets with required workflows are available on `bolyra/bolyra` (public,
org-owned) and which events they honor; if `pull_request_target` is not
accepted by the ruleset, the trigger becomes `pull_request` and safety is
preserved because the ruleset itself pins the definition to `main` and every
checkout below is pinned to `TRUSTED_SHA`. The proof test in section 6
("same-name green job from a modified PR workflow does not unblock merge") is
mandatory either way.

**Why the replay job is the check.** v2 used commit statuses; that required a
write token, a finalizer, a refresh path, and status-source validation. v3+
removes the write entirely.

**Why a container.** `permissions:` scopes only `GITHUB_TOKEN`. Every job
also carries `ACTIONS_RUNTIME_TOKEN`, readable by any process on the VM and
sufficient to *write* cache entries even with `cache-mode: none`. On
`pull_request_target` those entries are restorable by base-branch workflows
(`ci.yml` Rust reference-host cache; `docker-gateway.yml` layer cache). So
both `replay.js` invocations run inside `docker run` with the workspace
bind-mounted and **no runner environment passed through**; `bolyra-suite`
replays need outbound network (clone + `npm ci`); `external-suite` replays
already run `--network none`.

```yaml
name: Interop submission
on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled, unlabeled]
    branches: [main]
  pull_request_review:                # re-approval / dismissal restarts the check
    types: [submitted, dismissed]
permissions:
  contents: read
  pull-requests: read
# NO concurrency block: cancellation can leave the newest SHA without a run.
# Stale runs are harmless: they fail the live-head check below.

env:                                  # captured once; never a moving ref
  TRUSTED_SHA: ${{ github.workflow_sha }}
  BASE_SHA:    ${{ github.event.pull_request.base.sha }}
  HEAD_SHA:    ${{ github.event.pull_request.head.sha }}
  PR_NUMBER:   ${{ github.event.pull_request.number }}
  MAINTAINER_ID: <numeric GitHub user id of saneGuy>   # ids, not logins

jobs:
  submission-check:
    permissions: { contents: read }
    steps:
      - checkout ref: ${{ env.TRUSTED_SHA }}, fetch-depth: 0, persist-credentials: false
      - git fetch origin "$HEAD_SHA"
      - node interop/submission-check.js        # inspects git OBJECTS only; outputs below
          # 1. classify: changed paths (merge-base BASE_SHA...HEAD_SHA).
          #    none of {interop/claims.json, interop/adapters/**} touched -> is_submission=false, exit 0
          #    (generator/HTML-only maintenance therefore flows through ordinary CI + CODEOWNERS).
          #    maintainer metadata route: author id == MAINTAINER_ID AND the ONLY registry diff is
          #    adding `verification_run_url` to existing entries -> is_submission=false, exit 0.
          # 2. for submissions, ALL of:
          #    changed paths ⊆ {interop/claims.json, one ADDED interop/adapters/<name>.ts, landing/conformance.html}
          #    git merge-base --is-ancestor BASE_SHA HEAD_SHA   (ancestry enforced only here)
          #    registry diff == exactly ONE added entry; every pre-existing entry DEEP-EQUAL (parsed JSON)
          #    added entry has NO verification_run_url; kind ∈ {bolyra-suite, external-suite}
          #    bolyra-suite: exactly one ADDED regular file (mode 100644, not symlink), claim.adapter ==
          #      "adapters/<name>.ts", adapter_sha256 matches the blob;
          #      implementer.install ∈ { ["npm","ci",...], ["npm","install",...] } AND contains "--ignore-scripts"
          #    external-suite: zero adapter changes; run.image matches ^node:[^@]+@sha256:[0-9a-f]{64}$;
          #      run.command[0] ∈ {"npm","node"}; run.network == "none"
          #    claim_id ~ ^[A-Za-z0-9@._/-]+$ ; adapter name ~ ^[A-Za-z0-9._-]+\.ts$
          #    validateClaim passes on head claims.json with the head adapter materialized into a temp interop/
          #    base generator on head claims.json == head landing/conformance.html (byte-equal)

  replay-claim:                       # THE ruleset-required check
    needs: submission-check
    if: ${{ !cancelled() }}           # fail-not-skip on dependency failure; skip only on cancellation
    permissions: { contents: read, pull-requests: read }
    steps:
      - if needs.submission-check.result != 'success': fail
      - if outputs.is_submission != 'true': echo "not a submission"; exit 0
      - authorization (REST with the job token; metadata GitHub owns; paginate):
          live PR head == $HEAD_SHA                         else fail "head moved"
          label 'replay-approved' present on the PR         else fail "awaiting label"
          most recent review BY user id MAINTAINER_ID has state APPROVED and commit_id == $HEAD_SHA
                                                            else fail "awaiting approving review on $HEAD_SHA"
      - checkout ref: ${{ env.TRUSTED_SHA }}, fetch-depth: 0, persist-credentials: false
      - git fetch origin "$HEAD_SHA"; git checkout "$HEAD_SHA" -- interop/claims.json
      - if kind == bolyra-suite: git checkout "$HEAD_SHA" -- "interop/adapters/$ADAPTER_NAME"
      - docker run --rm -v "$PWD:/work" -w /work node:20@<digest> \
            node interop/replay.js --check
      - docker run --rm -v "$PWD:/work" -w /work -e CLAIM_ID node:20@<digest> \
            sh -c 'node interop/replay.js --claim "$CLAIM_ID"'   # env var, quoted; no runner env passed
```

Properties, stated plainly:
- Harness, gate script, and runner come from `github.workflow_sha` (echoed
  on every run; confirmed on the first live run). Reruns replay the same SHAs.
- Check identity is pinned by the ruleset; a same-name job from another
  workflow cannot satisfy it (proven in section 6).
- No job holds a token that writes; third-party code runs in a container
  that cannot see `ACTIONS_RUNTIME_TOKEN` or `GITHUB_TOKEN`. The residual for
  code that escapes the container is the read-only `GITHUB_TOKEN` on the VM:
  public reads and quota consumption, no writes. Accepted.
- Approval is bound to an exact SHA by GitHub's review record; the label
  alone never authorizes; the live-head check defeats stale reruns.
- `replay-claim` fails, never skips, for an unapproved submission, and passes
  trivially for non-submissions; the workflow has no `paths:` filter.
- Fork PRs on `pull_request_target` need no "Approve and run"; the
  review-SHA binding plus label is the sole execution gate. "Require approval
  for all outside collaborators" stays enabled for `ci.yml`.
- Create the `replay-approved` label. Only `saneGuy` has triage+; re-check
  if collaborators are added.
- Full-registry replay stays on the dispatch workflow, unchanged.
- `verification_run_url` is maintainer-only: rejected on submitted entries;
  added afterwards through the maintainer metadata route above. Documented in
  `interop/README.md`'s schema.

### 3.5 Landing copy changes (`landing/index.html`) and deploy/verify coverage
Exact edits (line numbers as of `f106b00`):
- 948: delete "A hosted verifier preview is live for design partners:
  `POST /v1/verify` ..." (the whole sentence).
- 953: delete "Pilot against Bolyra's hosted verifier preview today, ...".
- 1031: delete "Hosted `POST /v1/verify` preview for design partners, same
  External Verifier Contract".
- 953 tail: delete "... and managed verifier path" (the platform the ruling
  said not to build).
- 954: delete "Managed operations when you need them."
- 955: "10 domain-agnostic wire-envelope vectors" -> "11 domain-agnostic
  wire-envelope vectors".
- Verified at `f106b00`: no other landing page mentions the hosted preview;
  the design-partner section (1153-1180) is pilot copy, not hosted-verifier
  copy, and stays.
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
  dir and assert its "N test vectors loaded" (stdout, non-JSON mode) equals
  the advertised total (41 today: 30 host_behavior + 11 verifier_envelope).

## 4. Data flow
Registry (PR-authored, gate-validated, CODEOWNERS-reviewed) -> generator
(deterministic, escaped, link-validated) -> committed HTML (drift-guarded) ->
`deploy.sh` -> S3/CloudFront -> `verify.sh`. Replay results exist only as the
`replay-claim` job conclusion and public run history; nothing is written to
the repository or to commit statuses.

## 5. Error handling
- Malformed or unsafe registry entry: generator exits 1; CI red; no deploy.
- Drift: `--check` red with a diff.
- Out-of-scope diff, >1 claim, modified claim/adapter, symlink, bad charset,
  stale branch, generator mismatch: `submission-check` red with the reason;
  `replay-claim` red because its dependency failed.
- Submission without label, or label present but no APPROVED maintainer review
  at the current head SHA, or live head != captured head: `replay-claim` red
  with the reason and SHA named.
- Disallowed `install`/`run.image`/`run.command`, or `verification_run_url`
  on a submitted entry: `submission-check` red naming the field.
- Replay failure: `replay-claim` red; per README the claim is investigated,
  never edited to pass.
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
- `interop/submission-check.test.js` additionally: symlink adapter rejected;
  bad claim-id charset rejected; adapter name with shell metacharacters
  rejected; external-suite with an adapter change rejected; head not
  containing base rejected; generator mismatch rejected.
- `interop/submission-check.test.js` additionally: `install` without
  `--ignore-scripts` rejected; `["bash","-c",...]` rejected; non-`node:`
  or undigested `run.image` rejected; `verification_run_url` on a submitted
  entry rejected; deep-equality catches an `adapter_sha256` edit to an
  existing entry; maintainer metadata route accepted only for the maintainer
  id and only for that field; generator-only PR classified non-submission.
- Ruleset proof (mandatory, recorded with a screenshot): a test PR that edits
  `ci.yml` to add a green job named `replay-claim` remains blocked from merge.
- Workflow proof on a test PR, recorded in the implementation PR: unrelated
  label -> `replay-claim` red "awaiting"; label without approving review ->
  red; approving review on H1 then push H2 then label -> red naming H2;
  approving review on H2 + label -> replay runs; hash-mismatched claim ->
  red; passing claim -> green; unrelated PR -> green without replay;
  external-suite submission -> green with no adapter; re-approval alone
  (no label change) re-triggers via `pull_request_review`; stale rerun on H1
  after H2 exists -> red "head moved"; ruleset actually blocks merge on red
  (screenshot in the PR); `workflow_sha` echoed and equal to `main` at run
  time; a probe adapter that prints its environment shows no
  `ACTIONS_RUNTIME_TOKEN` / `GITHUB_TOKEN` inside the container.
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
blocked by the required `replay-claim` check until a maintainer's approving
review is bound to the head SHA and the label is present, then replays via
base-controlled code pinned to `workflow_sha` and passes; a hash mismatch or
failing replay leaves it red; a skipped or foreign-label run cannot satisfy
it; a same-name job from a modified PR workflow does not unblock merge; no
job in the workflow holds a write token; third-party code cannot see the
runner's tokens.
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
3. No commit statuses. The replay job's own conclusion is the required check
   (v3), eliminating every write token from the workflow.
5. Check identity is pinned by a ruleset-required workflow (v4); its
   availability is plan task 1 and a hard prerequisite.
6. Third-party code runs in a container without the runner environment (v4).
4. Out of scope, noted for a follow-up: `integrations/evc-conformance/bin.js`
   line 12 says "112-vector suite" (set is 125).
