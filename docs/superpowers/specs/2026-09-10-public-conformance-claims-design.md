# Public Conformance Claims -- Design Document

**Date:** 2026-09-10
**Author:** Claude (Fable 5.1) + Codex (gpt-6-astra) brainstorm; founder-approved scope
**Status:** APPROVED for v1 scope (founder decision 2026-09-10 after five review rounds). The automatic submission gate is DEFERRED to Appendix A, which is fully reviewed and ready to activate.

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

### In (v1)
- **`landing/conformance.html`**: one page rendering every claim in
  `interop/claims.json` (section 3.2).
- **Explicit coverage boundaries** on every row; `external-suite` rows carry
  the own-corpus qualifier inserted by the generator, independent of
  author-provided text.
- **Generator + drift guard**: `landing/gen-conformance.js` renders the page
  from `claims.json`; `--check` fails CI when the committed HTML drifts.
- **Maintainer-operated submission contract** (`interop/SUBMITTING.md`,
  section 3.3): one PR adds exactly one claim (+ one new adapter for
  `bolyra-suite`) and the regenerated page; offline checks run in CI; the
  maintainer reviews, then replays the exact PR head via the existing
  `workflow_dispatch` job before merging. No third-party code runs on any PR
  event.
- **CI additions**: `node interop/replay.js --check` and the generator
  `--check` on every push and PR.
- **Landing copy on the same surface**: current suite version and counts;
  removal of every hosted-verifier/managed-platform sentence (the 2026-08-27
  ruling was not to build the hosted platform); a CTA that describes what
  exists; and version preflight/guard coverage for `@bolyra/evc-conformance`
  in `deploy.sh`/`verify.sh`.

### Out
The automatic, label-gated submission replay and its ruleset dependency
(deferred; the reviewed design is Appendix A and activates when a second real
external submission arrives). The maintainer-only `verification_run_url`
route (deferred with it). New demos or examples, new vector classes, adapters written on an
implementer's behalf, hosted verification, accounts, dashboards, certification
badges or logos, live replay status or results write-back from CI, x402
#3376 hardening, Dependabot remediation, edits to existing pinned claims or
adapters via the submission path, and any revival of the killed AAR/Nobulex
adapter or `checked_layers` schema expansion. `verification_run_url` is not
rendered in v1 (no route to set it).

## 3. Architecture

```
interop/claims.json --gen-conformance.js--> landing/conformance.html --deploy.sh--> bolyra.ai/conformance
        ^                                            ^
        | PR: +1 claim, +1 adapter, regenerated page | CI --check: committed HTML == generated
        |                                              (+ node interop/replay.js --check, offline)
  maintainer: review adapter + pins -> `Interop replay` workflow_dispatch on the PR head SHA
              (existing job, unchanged) -> green -> merge.  No PR event executes third-party code.
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
  constructed from that validated URL plus the 40-hex `commit`. Any other
  value fails generation (exit 1), never renders. (v1 renders no
  `verification_run_url`; the field is reserved for Appendix A.)
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
- One labeled link: "Replay history" ->
  `https://github.com/bolyra/bolyra/actions/workflows/interop-replay.yml`.
- "How to add yours" -> absolute
  `https://github.com/bolyra/bolyra/blob/main/interop/SUBMITTING.md`.
- `deploy.sh`: add the variable, the pre-check loop entry, two `aws s3 cp`
  calls (`/conformance.html` and `/conformance`), and both paths in the
  CloudFront invalidation list.

### 3.3 Submission contract (maintainer-operated): `interop/SUBMITTING.md`
1. Fork; add **exactly one** entry to `interop/claims.json` per the schema in
   `interop/README.md`. For `bolyra-suite`, add **one new** file
   `interop/adapters/<name>.ts` (pure I/O, README rules) and set
   `adapter_sha256`. Do not modify any existing claim or adapter. Do not set
   `verification_run_url`. `implementer.install` must be
   `["npm","ci","--ignore-scripts"]` or `["npm","install","--ignore-scripts"]`,
   optionally followed by `--no-audit` and/or `--no-fund`; `external-suite`
   claims need a digest-pinned `node:` image and `run.network: "none"`.
2. Run `node interop/replay.js --check` and `node landing/gen-conformance.js`;
   commit the regenerated `landing/conformance.html` with the claim (and
   adapter). A submission PR touches only those files.
3. Open the PR. Ordinary CI runs the offline checks (`replay.js --check`,
   generator `--check`, existing tests). **Nothing on the PR executes
   third-party code.**
4. The maintainer reviews the adapter and the pins, notes the exact head SHA,
   and runs the existing `Interop replay` workflow by `workflow_dispatch`
   against that SHA (the dispatch job gains an optional `ref` input and a
   `--claim <id>` input; it is otherwise unchanged and keeps its
   `contents: read` / `persist-credentials: false` posture). Any push after
   that review requires a fresh review and a fresh dispatch.
5. Green dispatch run on the reviewed SHA + CODEOWNERS review -> merge -> the
   row appears on the next landing deploy. The dispatch run URL is recorded
   in the merge commit message. README rules restated: a red replay means
   investigate, never edit the claim; claims stay pinned; re-verification at
   a newer set is a new row.
6. Stated plainly in the document: this path relies on maintainer discipline
   (review before dispatch; dispatch the reviewed SHA; do not merge red). It
   is not machine-enforced. Machine enforcement is the deferred Appendix A.

### 3.4 Landing copy changes (`landing/index.html`) and deploy/verify coverage
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
`deploy.sh` -> S3/CloudFront -> `verify.sh`. Replay results exist only as
dispatch-run conclusions and public run history; nothing is written to the
repository or to commit statuses.

## 5. Error handling
- Malformed or unsafe registry entry: generator exits 1; CI red; no deploy.
- Drift: `--check` red with a diff.
- Out-of-scope submission diff, >1 claim, modified claim/adapter, bad
  `install`/`image`/`command`, `verification_run_url` set: caught by the
  maintainer's review checklist in SUBMITTING.md (v1) and by `replay.js
  --check` where it validates shape; machine enforcement is Appendix A.
- Replay failure on dispatch: red run; per README the claim is investigated,
  never edited to pass; the PR is not merged.
- Missing `conformance.html` at deploy: `deploy.sh` errors.

## 6. Testing
- `landing/gen-conformance.test.js` (node:test): deterministic output;
  `--check` passes on identical input, fails with diff on a one-byte change;
  `<script>` in `claim_text` is escaped; `javascript:` and non-GitHub
  `implementer.repo` fail generation; unknown `kind` fails; external-suite
  rows carry the fixed qualifier regardless of `claim_text`; stable ordering;
  covered-classes derivation only from `--type` selectors.
- Dispatch inputs: `interop-replay.yml` gains optional `ref` (default
  `main`) and `claim` (default all) inputs; a test proves `--claim <id>` on a
  non-`main` ref replays exactly that claim, and a hash-mismatched test claim
  goes red.
- `interop/replay.test.js`: all 18 existing parser tests retained, unchanged.
- End-to-end proof on a test submission PR, recorded in the implementation
  PR: offline checks green on the PR with no third-party execution (verified
  from the run logs); maintainer dispatch on the PR head SHA green; the same
  flow with a deliberately wrong `adapter_sha256` -> dispatch red.
- CI: `node interop/replay.js --check` added to the `evc-conformance` job in
  `ci.yml` (which today runs only `node --test interop/replay.test.js`); that
  job's checkout gets `fetch-depth: 0` because `checkSuitePin` uses
  `git show <suite.commit>:spec/test-vectors.json`. Generator `--check` in
  the same job.
- Landing after deploy: `verify.sh` green including the new evc-conformance
  guard; live curl asserts the four changed strings present, all FIVE deleted
  phrases absent (948, 953, 1031, the 953 tail "managed verifier path", 954
  "Managed operations when you need them."), and `/conformance` reachable
  with both claims.

## 7. Completion criterion (v1)
Both existing claims are publicly accessible with provenance, dated
verification, explicit coverage boundaries, and a labeled link to replay
history. `SUBMITTING.md` suffices for an outside implementer to open a
correct submission PR without asking, and for the maintainer to replay the
exact PR head by dispatch; a test submission has been taken through that
path end to end, including a failing case. All hosted-verifier/managed-
platform copy is gone and the advertised suite version and counts are
current and machine-checked at deploy.

What Appendix A would buy over this v1 (Codex wording): compared with
dispatch alone, it makes successful trusted replay of the
submitted SHA a merge prerequisite and automatically validates submission
data. For a solo maintainer, merge enforcement primarily prevents mistakes,
including mistakes induced by attacker-controlled or stale check evidence.
It does not establish that malicious approved code reports honest results.

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
4. Check identity is pinned by a ruleset-required workflow (v4); its
   availability is plan task 1 and a hard prerequisite.
5. Isolation is per kind (v5): `bolyra-suite` inside a container; `external-suite` on the VM because `replay.js` must drive the host `docker` CLI, and its implementer code already runs only in the `--network none` child container.
6. No automatic restart (v5): ruleset workflows ignore label/review events; the maintainer re-runs the required workflow after approving and labeling.
7. **Scope cut to v1 (founder, 2026-09-10).** After five review rounds the
   automatic gate's "automatic" property collapsed (ruleset-required
   workflows ignore label/review events, so the restart is a manual rerun
   anyway); what remained was merge enforcement, which for a solo maintainer
   prevents mistakes rather than attackers. Codex recommended deferring it;
   Claude agreed; the founder chose v1. Appendix A is retained verbatim as
   the reviewed activation design.
8. Out of scope, noted for a follow-up: `integrations/evc-conformance/bin.js`
   line 12 says "112-vector suite" (set is 125).

## Appendix A (DEFERRED): automatic, label-gated submission replay

**Status:** fully reviewed (five rounds, spec reviewer + Codex, 2026-09-10)
and approved as a design; **not part of v1** by founder decision. Activate
when a second real external submission arrives. Plan task 1 of that
activation is verifying ruleset-required-workflow availability on
`bolyra/bolyra`. Nothing below is implemented in v1.

### A.1 Trusted submission workflow: `.github/workflows/interop-submission.yml`

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
any other workflow cannot satisfy it. Per GitHub's documentation, ruleset
workflows support `pull_request_target`, ignore activity filters, and run
only for opened/synchronize/reopened; label and review events therefore
never start the required run, which is why the restart path is a manual
rerun. The same ruleset MUST also enable **"Require branches to be up to date
before merging"**: the ancestry check inside the workflow sees only the
captured `BASE_SHA` of its own run, so without this setting a previously
green submission silently goes stale when `main` advances; with it, GitHub
blocks the merge until the branch is updated, which changes the head SHA and
requires fresh approval and replay. **Prerequisite (plan task 1):** confirm
on `bolyra/bolyra` that the ruleset executes this file from `main` even when
a PR edits it (test with a PR that modifies the workflow), that
`pull_request_target` is accepted, and that the up-to-date rule is available
alongside it.
If either fails, the design blocks here; there is no `pull_request`
fallback, because on that event `github.workflow_sha` is the PR merge ref
and pins nothing. The proof in section 6 is mandatory.

**Why the replay job is the check.** v2 used commit statuses; that required a
write token, a finalizer, a refresh path, and status-source validation. v3+
removes the write entirely.

**Why a container, and for which kind.** `permissions:` scopes only
`GITHUB_TOKEN`; every job also carries `ACTIONS_RUNTIME_TOKEN`, readable by
any process on the VM. (Since GitHub's 2026-06-26 change, untrusted triggers
in default-branch scope get read-only cache access, so cache poisoning from
this trigger is no longer the concern it was; `workflow_dispatch` retains
write access, so moving execution to dispatch would not be safer. The
credential boundary is still the reason to isolate.) Isolation is split on
the `kind` that `submission-check` emits:
- `bolyra-suite`: every third-party execution (`npm ci`, the implementer's
  `tsx`, the adapter) happens inside `replay.js`'s own process tree, so
  containing `replay.js` contains it. It runs inside `docker run` on the
  **full Debian `node:20` digest** (slim/alpine lack `git`, which
  `replay.js` needs for the implementer fetch and `git archive` of the
  suite), with the workspace bind-mounted, outbound network, `-e CLAIM_ID`
  only, `--user "$(id -u):$(id -g)" -e HOME=/tmp` (bind-mounted `.git`
  ownership), and no runner environment passed through. This is the last
  step of the job, so post-run workspace tampering has no consumer.
- `external-suite`: `replay.js` must call the host `docker` CLI
  (`replay.js:162-187`), so it cannot itself be containerized without
  exposing the daemon, which would be worse. Verified against the code: on
  the host it runs only base code: `docker version`, a fresh `git init` +
  `fetch --depth 1 <sha>` + `checkout FETCH_HEAD` of the implementer (a fresh
  init has only `.sample` hooks, so nothing executes on fetch or checkout),
  and, only when the claim sets `requires_zero_dependencies`, a `JSON.parse`
  of its `package.json`; **the
  only execution of implementer code is the kit's test command inside the
  existing child `docker run --network none` with no `-e` pass-through**,
  which therefore already sees no runner environment. That child container
  is the boundary. `replay.js` runs on the VM under `env -i` with an
  explicit allowlist (`PATH`, `HOME`, `CLAIM_ID`) as defense in depth, not as
  the boundary.
- `replay.js --check` runs no third-party code and stays on the VM.
Stated residual, both kinds: a container escape or a host compromise exposes
the runner's available credentials and privileges (GitHub-hosted runners
have passwordless sudo); the read-only `GITHUB_TOKEN` does not describe that
entire exposure. The label + review gate is the control for the adapter;
isolation is the control for the implementer's code.

```yaml
name: Interop submission
on:
  pull_request_target:
    types: [opened, synchronize, reopened]     # the ruleset ignores other activity anyway
    branches: [main]
# No label/review triggers: the ruleset ignores them. Restart = manual rerun.
permissions:                          # load-bearing: pull_request_target is a privileged-family event
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
          #    adding `verification_run_url` to existing entries (landing/conformance.html must be
          #    regenerated in the same PR; ci.yml's generator --check enforces it) -> is_submission=false, exit 0.
          # 2. for submissions, ALL of:
          #    changed paths ⊆ {interop/claims.json, one ADDED interop/adapters/<name>.ts, landing/conformance.html}
          #    git merge-base --is-ancestor BASE_SHA HEAD_SHA   (ancestry enforced only here)
          #    registry diff == exactly ONE added entry; every pre-existing entry DEEP-EQUAL (parsed JSON)
          #    added entry has NO verification_run_url; kind ∈ {bolyra-suite, external-suite}
          #    bolyra-suite: exactly one ADDED regular file (mode 100644, not symlink), claim.adapter ==
          #      "adapters/<name>.ts", adapter_sha256 matches the blob;
          #      implementer.install is ["npm","ci"|"install","--ignore-scripts"] optionally followed by
          #      "--no-audit" and/or "--no-fund" in that order, nothing else (matches the existing pinned claim;
          #      both exact forms are printed in SUBMITTING.md)
          #    external-suite: zero adapter changes; run.image matches ^node:[^@]+@sha256:[0-9a-f]{64}$;
          #      run.command[0] ∈ {"npm","node"}; run.network == "none"
          #    implementer.repo ~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ (explicit here, not only
          #      via the generator; this URL is what `git remote add` + `fetch` consume on the VM)
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
      - node interop/replay.js --check                            # base code only; on the VM
      - if kind == bolyra-suite (LAST step of the job):
          docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CLAIM_ID \
            -v "$PWD:/work" -w /work node:20@<full-debian-digest> \
            sh -c 'node interop/replay.js --claim "$CLAIM_ID"'   # no runner env passed
      - if kind == external-suite:
          env -i PATH="$PATH" HOME="$HOME" CLAIM_ID="$CLAIM_ID" \
            node interop/replay.js --claim "$CLAIM_ID"           # implementer code runs only in replay.js's own --network none child
```

Properties, stated plainly:
- Harness, gate script, and runner come from `github.workflow_sha` (echoed
  on every run; confirmed on the first live run). Reruns replay the same SHAs.
- Check identity is pinned by the ruleset; a same-name job from another
  workflow cannot satisfy it (proven in section 6).
- No job holds a token that writes; third-party code cannot see
  `ACTIONS_RUNTIME_TOKEN` or `GITHUB_TOKEN` (per-kind isolation above). The
  escape/host-compromise residual is stated in "Stated residual" above and is
  full host exposure, not merely the read-only token.
- Approval is bound to an exact SHA by GitHub's review record; the label
  alone never authorizes; the live-head check defeats stale reruns. The
  documented restart after approval and labeling is a manual rerun;
  automatic events (`synchronize`, `reopened`) also re-evaluate
  authorization and will replay if it already holds.
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

