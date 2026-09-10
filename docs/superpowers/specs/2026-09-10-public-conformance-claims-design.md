# Public Conformance Claims -- Design Document

**Date:** 2026-09-10
**Author:** Claude (Fable 5.1) + Codex (gpt-6-astra) brainstorm; founder-approved scope
**Status:** DRAFT v3 (rounds 1-2 applied from both reviewers; pending round 3)

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
  base-controlled job that is itself the required check; read-only token
  everywhere; no secrets, no caches, no status writes; execution only when a
  maintainer label is present AND the maintainer's approving review is bound
  to the exact head SHA; only the submission's data and one adapter come from
  the PR.
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
  interop-submission.yml (pull_request_target; workflow + harness pinned to github.workflow_sha;
                          contents:read + pull-requests:read only; no secrets/caches/status writes)
     submission-check : validates the diff as DATA; outputs is_submission, claim id, adapter name
     replay-claim     : REQUIRED CHECK. non-submission -> pass. submission without
                        (label present AND saneGuy APPROVED review at commit_id == head.sha) -> FAIL.
                        else overlay the validated files at head.sha and replay `--claim <id>`.
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
   never accepted through this path; open a separate PR. The branch must
   contain the current base of `main` (rebase before asking for review).
4. Open the PR. `submission-check` validates the diff; `replay-claim` (the
   required check) FAILS with "awaiting maintainer review + replay-approved on
   <head.sha>". Offline checks run in ordinary CI. No third-party code runs.
5. The maintainer reviews the adapter and pins and submits an **approving PR
   review** (GitHub records the reviewed `commit_id`), then applies
   `replay-approved`. `replay-claim` re-runs, confirms the approving review's
   `commit_id` equals the current head SHA, replays, and its own conclusion
   is the check.
6. Any push after approval changes the head SHA; the approving review no
   longer matches; `replay-claim` fails again until the maintainer re-reviews
   (new approving review on the new SHA). The label may stay; it is
   necessary, not sufficient. In-progress runs on a superseded SHA are
   cancelled by the newer event.
7. Green `replay-claim` + CODEOWNERS review -> merge -> the row appears on
   the next landing deploy. README rules restated: a red replay means
   investigate, never edit the claim; claims stay pinned; re-verification at
   a newer set is a new row.

### 3.4 Trusted submission workflow: `.github/workflows/interop-submission.yml`

**Why `pull_request_target`.** On the `pull_request` event the workflow file,
`replay.js`, and the runner execute from the PR's ref; a PR can rewrite any
of them and go green, and `paths:` only affects triggering. A green result on
`pull_request` is not evidence. `pull_request_target` runs the workflow
definition from the base, so the harness is trusted. Its documented danger is
executing PR code while holding a privileged token or secrets. This workflow
holds neither: every job is `contents: read` (plus `pull-requests: read` for
the review lookup), no secrets are referenced, `cache-mode: none`, no
credentials persist, **no job writes anything to GitHub**, and the only
PR-sourced bytes that execute are the one adapter a maintainer approved by
SHA. This is the repo's only `pull_request_target` use; this section is the
justification.

**Why the replay job is the check.** v2 used commit statuses as the gate.
That required `statuses: write` in the workflow, a finalizer job, a refresh
mechanism, source validation of the status, and queue handling. Same-runner
steps are not a security boundary, so any write token in the adapter's job is
reachable by the adapter. v3 removes the write entirely: GitHub Actions
reports the job's conclusion itself, which no adapter can forge.

```yaml
name: Interop submission
on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled, unlabeled]
    branches: [main]             # submissions target main only
permissions:
  contents: read
  pull-requests: read
concurrency:
  group: submission-${{ github.event.pull_request.number }}
  cancel-in-progress: true       # a newer event supersedes; last run on the current SHA is the check

env:                             # captured once; every step uses these, never a moving ref
  TRUSTED_SHA: ${{ github.workflow_sha }}
  BASE_SHA:    ${{ github.event.pull_request.base.sha }}
  HEAD_SHA:    ${{ github.event.pull_request.head.sha }}
  PR_NUMBER:   ${{ github.event.pull_request.number }}

jobs:
  submission-check:
    permissions: { contents: read }
    steps:
      - checkout ref: ${{ env.TRUSTED_SHA }}, fetch-depth: 0, persist-credentials: false
      - git fetch origin "$HEAD_SHA"; git merge-base --is-ancestor "$BASE_SHA" "$HEAD_SHA" || fail "rebase onto main"
      - node interop/submission-check.js            # reads env, inspects git OBJECTS only
          # outputs: is_submission (true/false), claim_id, adapter_name, kind
          # rules when is_submission: changed paths (BASE_SHA...HEAD_SHA) ⊆ allowlist;
          #   registry diff == exactly ONE added claim, zero modified/removed;
          #   kind ∈ {bolyra-suite, external-suite}; bolyra-suite ⇒ exactly one ADDED
          #   regular file interop/adapters/<name>.ts (mode 100644, no symlink) and the
          #   claim's `adapter` == "adapters/<name>.ts" with matching adapter_sha256;
          #   external-suite ⇒ zero adapter changes;
          #   claim_id matches ^[A-Za-z0-9@._/-]+$, adapter_name matches ^[A-Za-z0-9._-]+\.ts$;
          #   head claims.json passes validateClaim after materializing the head
          #   adapter into a temp interop/ layout (writing a .ts file is not executing it);
          #   base generator on head claims.json == head landing/conformance.html (byte-equal).
          # when not a submission (no allowlisted path touched): is_submission=false, exit 0.

  replay-claim:                  # THE required status check in branch protection
    needs: submission-check
    if: always()                 # must produce a conclusion on every PR event
    permissions: { contents: read, pull-requests: read }
    steps:
      - if needs.submission-check.result != 'success': fail
      - if outputs.is_submission != 'true': echo "not a submission"; exit 0
      - authorization (trusted, metadata only, via REST with the job token):
          label 'replay-approved' present on PR $PR_NUMBER; AND the most recent
          review by 'saneGuy' has state APPROVED and commit_id == $HEAD_SHA.
          Otherwise: fail "awaiting maintainer review + replay-approved on $HEAD_SHA"
      - checkout ref: ${{ env.TRUSTED_SHA }}, fetch-depth: 0, persist-credentials: false
      - git fetch origin "$HEAD_SHA"
      - git checkout "$HEAD_SHA" -- interop/claims.json            # data
      - if kind == bolyra-suite: git checkout "$HEAD_SHA" -- "interop/adapters/$ADAPTER_NAME"
      - setup-node 20, cache-mode: none
      - node interop/replay.js --check
      - node interop/replay.js --claim "$CLAIM_ID"                 # env var, quoted; never ${{ }} in run:
```

Properties, stated plainly:
- Harness, gate script, and runner come from `github.workflow_sha`, an
  immutable commit of the base branch; reruns replay the same SHAs.
- A submission cannot alter what checks it, and no job holds a token that can
  write anything. An adapter that compromises its runner gains: compute,
  egress, and public reads. Nothing else exists on that VM.
- Approval is bound to an exact SHA by GitHub's own review record: the
  maintainer's APPROVED review must carry `commit_id == HEAD_SHA`. A push
  after review breaks the binding; the label alone never authorizes.
- A skipped or foreign-label run cannot satisfy the check: `replay-claim`
  runs on every PR event and fails, not skips, for an unapproved submission.
- Non-submission PRs pass the check trivially, so it can be required without
  blocking unrelated work; the workflow has no `paths:` filter for this reason.
- What the mechanism does NOT do: it does not judge whether an approved
  adapter is honest. The maintainer's adapter review is the only defense
  against a malicious adapter (stated in SUBMITTING.md and the workflow header).
- Fork PRs on `pull_request_target` do not wait for "Approve and run"; the
  review-SHA binding plus label is the sole execution gate. "Require approval
  for all outside collaborators" stays enabled for the `pull_request`-based
  `ci.yml`.
- Create the `replay-approved` label (none exists today). Only `saneGuy` has
  triage+; re-check this assumption if collaborators are added.
- Full-registry replay stays on the dispatch workflow, unchanged.
- `verification_run_url` is maintainer-only, added in a follow-up commit
  after merge (a maintainer push to the PR would change the SHA and restart
  the review cycle). Documented in `interop/README.md`'s schema.

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
  at the current head SHA: `replay-claim` red with the awaited SHA named.
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
- Workflow proof on a test PR, recorded in the implementation PR: unrelated
  label -> `replay-claim` red "awaiting"; label without approving review ->
  red; approving review on H1 then push H2 then label -> red naming H2;
  approving review on H2 + label -> replay runs; hash-mismatched claim ->
  red; passing claim -> green; unrelated PR -> green without replay;
  external-suite submission -> green with no adapter; branch protection
  actually blocks merge on red (screenshot in the PR).
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
it; no job in the workflow holds a write token.
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
4. Out of scope, noted for a follow-up: `integrations/evc-conformance/bin.js`
   line 12 says "112-vector suite" (set is 125).
