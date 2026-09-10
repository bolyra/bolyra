# Public Conformance Claims (v1) — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish `interop/claims.json` as a public, drift-guarded page at `bolyra.ai/conformance`, document maintainer-operated claim submissions, isolate third-party code in the existing dispatch replay job, and fix the stale/false copy on the landing page.

**Architecture:** A zero-dependency generator (`landing/gen-conformance.js`) renders the registry to a committed static page, with a `--check` drift guard wired into CI. The existing `interop-replay.yml` dispatch job gains `ref`/`claim` inputs and per-kind isolation (bolyra-suite inside a read-only-mounted container; external-suite on the VM under `env -i`, its implementer code already confined to `replay.js`'s own `--network none` child). `SUBMITTING.md` describes the maintainer-operated path. No automatic gating (deferred; spec Appendix A).

**Tech Stack:** Node 20 (no runtime deps), `node:test`, GitHub Actions, Docker (on the runner), bash (`deploy.sh`/`verify.sh`), static HTML.

**Spec:** `docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md` (read §2, §3.1–3.5, §6, §7 before starting).

**Conventions (read first):**
- Work in the worktree at the path the orchestrator gives you, on branch `public-conformance-claims`. Never touch `main` directly.
- Every commit: `git commit -s` (DCO trailer required; CI checks it). Author/committer must be `Viswanadha Pratap Kondoju <kondojuviswanadha@gmail.com>` / `<saneGuy@users.noreply.github.com>` — set via env on each commit as shown in Task 1 Step 5 and reuse verbatim.
- Tests use `node:test` + `node:assert`, run with `node --test <file>`. No test framework installs.
- `interop/replay.js` is load-bearing and has 18 false-green regression tests. You will add ONE flag to it (`--list`). Do not touch its replay logic.
- Commands below are run from the worktree root unless a `cd` is shown.

---

## File Structure

```
interop/
  replay.js                     MODIFY: add --list (prints id, kind, adapter per claim; no execution)
  replay.test.js                MODIFY: add 3 tests for --list output
  SUBMITTING.md                 CREATE: maintainer-operated submission contract (spec §3.3)
  README.md                     MODIFY: pointer to SUBMITTING.md; install allowlist; verification_run_url reserved
.github/workflows/
  interop-replay.yml            MODIFY: ref/claim inputs; per-kind isolation; integrity check (spec §3.5)
  ci.yml                        MODIFY: evc-conformance job: fetch-depth 0; replay --check; generator --check + tests
landing/
  gen-conformance.js            CREATE: validateRegistry(), renderRegistry(), checkFile(); CLI with --check
  gen-conformance.test.js       CREATE: generator tests (escaping, URL/kind/field rejection, qualifier, ordering, --check)
  conformance.html              CREATE (generated): the public page — never hand-edit
  index.html                    MODIFY: five copy deletions, version/count fixes, /conformance links (spec §3.4)
  deploy.sh                     MODIFY: conformance page upload + invalidation; evc-conformance preflight
  verify.sh                     MODIFY: evc-conformance guard; installed-count assertion; deleted-phrase + /conformance checks
```

---

## Chunk 1: Registry listing + dispatch-job isolation

### Task 1: `replay.js --list`

The workflow needs each claim's `id`, `kind`, and `adapter` path without executing anything. Add a `--list` flag that prints one tab-separated line per claim.

**Files:**
- Modify: `interop/replay.js` (main(), after the `--check` block; and the header comment)
- Test: `interop/replay.test.js`

- [ ] **Step 1: Write the failing tests**

Append to `interop/replay.test.js`:

```js
// --list: the dispatch workflow reads id/kind/adapter per claim without executing anything.
const { spawnSync } = require('node:child_process');
const path = require('node:path');

function runList(extra = []) {
  return spawnSync(process.execPath, [path.join(__dirname, 'replay.js'), '--list', ...extra], { encoding: 'utf8' });
}

test('--list prints one tab-separated line per claim: id, kind, adapter', () => {
  const r = runList();
  assert.strictEqual(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split('\n');
  const claims = require('./claims.json').claims;
  assert.strictEqual(lines.length, claims.length);
  for (const [i, c] of claims.entries()) {
    const [id, kind, adapter] = lines[i].split('\t');
    assert.strictEqual(id, c.id);
    assert.strictEqual(kind, c.kind || 'bolyra-suite');
    assert.strictEqual(adapter, c.adapter || '');
  }
});

test('--list --claim <id> prints only that claim', () => {
  const first = require('./claims.json').claims[0];
  const r = runList(['--claim', first.id]);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stdout.trim().split('\n').length, 1);
  assert.ok(r.stdout.startsWith(first.id + '\t'));
});

test('--list --claim <unknown> exits 1 and prints nothing to stdout', () => {
  const r = runList(['--claim', 'does-not-exist']);
  assert.strictEqual(r.status, 1);
  assert.strictEqual(r.stdout, '');
  assert.match(r.stderr, /no claim with id does-not-exist/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test interop/replay.test.js`
Expected: the 18 existing tests pass; the 3 new `--list` tests FAIL (the first with `lines.length` 0 or a "claims reproduced" line, because `--list` is currently ignored and a full replay is attempted — it will fail fast on network/docker; that is fine).

- [ ] **Step 3: Implement `--list`**

In `interop/replay.js`, inside `main()`, insert immediately AFTER the `if (!allValid) return;` line and BEFORE `if (flag('--check')) {`:

```js
  // --list: id<TAB>kind<TAB>adapter per claim, no execution. The dispatch
  // workflow uses this to pick the per-kind isolation branch (spec §3.5).
  if (flag('--list')) {
    for (const c of claims) {
      process.stdout.write(`${c.id}\t${c.kind || 'bolyra-suite'}\t${c.adapter || ''}\n`);
    }
    return;
  }
```

Also add to the usage comment block near the top (after the `--keep` line):

```js
 *   node interop/replay.js --list       # offline: id<TAB>kind<TAB>adapter per claim
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test interop/replay.test.js`
Expected: 21 tests pass, 0 fail.

- [ ] **Step 5: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add interop/replay.js interop/replay.test.js
git commit -s -m "interop: replay.js --list (id, kind, adapter per claim; no execution)"
```

### Task 2: Pin the container image digest

The bolyra-suite replay runs inside the **full Debian** `node:20` image (slim/alpine lack `git`). Pin it by digest.

**Files:**
- (no file yet; the digest is used in Task 3)

- [ ] **Step 1: Resolve the digest**

Run:
```bash
docker pull node:20 >/dev/null && docker image inspect node:20 --format '{{index .RepoDigests 0}}'
```
Expected: one line like `node@sha256:<64 hex>`. Record the 64-hex digest; you will write it as `node:20@sha256:<digest>` in Task 3.

- [ ] **Step 2: Confirm it is the full image (has git)**

Run:
```bash
docker run --rm node:20@sha256:<digest> sh -c 'git --version && node --version'
```
Expected: `git version 2.x` and `v20.x`. If `git` is missing, you pulled a slim variant — re-run Step 1 with the plain `node:20` tag.

### Task 3: Dispatch job — inputs, per-kind isolation, integrity check

Rewrite `.github/workflows/interop-replay.yml` per spec §3.3 step 4 and §3.5. This also closes a pre-existing exposure (third-party code with runner tokens readable and cache-write access).

**Files:**
- Modify: `.github/workflows/interop-replay.yml` (whole file)

- [ ] **Step 1: Replace the workflow file**

Write `.github/workflows/interop-replay.yml` with exactly this content, substituting `<digest>` from Task 2:

```yaml
name: Interop replay

# Mechanically re-verify published external interop claims at their pins
# (interop/claims.json). Manual dispatch only: this executes third-party
# code (pinned, --ignore-scripts) and needs network access to external repos.
#
# Isolation (spec docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md §3.5):
#   bolyra-suite  -> all third-party execution is inside replay.js's process
#                    tree, so replay.js runs INSIDE a container: workspace
#                    mounted READ-ONLY, scratch on a tmpfs, no runner env.
#   external-suite-> replay.js must drive the host docker CLI, so it runs on
#                    the VM under env -i; the implementer's code runs only in
#                    replay.js's own `docker run --network none` child.
# Runner tokens (GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN) are never visible to
# third-party code. workflow_dispatch retains cache WRITE access, which is
# why this matters even with cache-mode none.
#
# Inputs:
#   ref   : commit SHA to take interop/claims.json (+ one new adapter) FROM.
#           The workflow file and the harness always run from the checked-out
#           default branch; only those files are overlaid (never a wholesale
#           checkout). Empty = replay the registry as committed on main.
#   claim : claim id to replay. Empty = all claims.
on:
  workflow_dispatch:
    inputs:
      ref:
        description: 'Commit SHA to overlay interop/claims.json (+ new adapter) from (empty = main as checked out)'
        required: false
        default: ''
      claim:
        description: 'Claim id to replay (empty = all)'
        required: false
        default: ''

# Third-party code executes in this job; give it nothing to steal.
permissions:
  contents: read

env:
  # Full Debian node:20 (NOT slim/alpine: git is required for the implementer
  # fetch and `git archive` of the suite). Re-pin deliberately, never by tag.
  REPLAY_IMAGE: node:20@sha256:<digest>

jobs:
  replay:
    name: Replay published interop claims
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          # git archive at historical suite pins needs full history
          fetch-depth: 0
          # do not leave the checkout token on disk where implementer
          # lifecycle code could read it
          persist-credentials: false

      - uses: actions/setup-node@v7
        with:
          node-version: 20
          package-manager-cache: false

      - name: Overlay submission files from ref (data only; harness stays on main)
        if: inputs.ref != ''
        env:
          REF: ${{ inputs.ref }}
          CLAIM: ${{ inputs.claim }}
        run: |
          set -euo pipefail
          [[ "$REF" =~ ^[0-9a-f]{40}$ ]] || { echo "ref must be a full 40-hex commit SHA"; exit 1; }
          git fetch -q origin "$REF"
          git checkout -q "$REF" -- interop/claims.json
          if [ -n "$CLAIM" ]; then
            # Only the one adapter the reviewed claim names, and only if it is
            # a bolyra-suite claim. Anything else stays at main.
            line=$(node interop/replay.js --list --claim "$CLAIM")
            kind=$(printf '%s' "$line" | cut -f2)
            adapter=$(printf '%s' "$line" | cut -f3)
            if [ "$kind" = "bolyra-suite" ]; then
              [[ "$adapter" =~ ^adapters/[A-Za-z0-9._-]+\.ts$ ]] || { echo "adapter path '$adapter' not allowed"; exit 1; }
              git checkout -q "$REF" -- "interop/$adapter"
            fi
          fi
          echo "overlaid from $REF:"; git status --porcelain -- interop

      - name: Offline registry + pin check (base code only)
        run: node interop/replay.js --check

      - name: Replay claims under per-kind isolation
        env:
          CLAIM_FILTER: ${{ inputs.claim }}
        run: |
          set -euo pipefail
          integrity() {
            if ! git diff --quiet HEAD -- interop spec landing .github \
               || [ -n "$(git status --porcelain -- interop spec landing .github | grep -v '^ M interop/claims.json$' | grep -v '^A  interop/adapters/' | grep -v '^?? interop/adapters/' || true)" ]; then
              echo "harness modified after claim $1 — refusing to continue"; git status --porcelain; exit 1
            fi
          }
          failed=0; total=0
          while IFS=$'\t' read -r id kind adapter; do
            [ -n "$CLAIM_FILTER" ] && [ "$id" != "$CLAIM_FILTER" ] && continue
            total=$((total+1))
            echo "::group::replay $id ($kind)"
            if [ "$kind" = "bolyra-suite" ]; then
              docker run --rm \
                --user "$(id -u):$(id -g)" -e HOME=/tmp -e CLAIM_ID="$id" \
                -v "$PWD:/work:ro" --tmpfs /tmp:rw,exec -w /work \
                "$REPLAY_IMAGE" sh -c 'node interop/replay.js --claim "$CLAIM_ID"' || failed=$((failed+1))
            else
              env -i PATH="$PATH" HOME="$HOME" CLAIM_ID="$id" \
                node interop/replay.js --claim "$id" || failed=$((failed+1))
            fi
            echo "::endgroup::"
            integrity "$id"
          done < <(node interop/replay.js --list)
          echo "$((total-failed))/$total claims reproduced"
          [ "$failed" -eq 0 ]
```

Notes for the implementer:
- The `integrity()` allowlist tolerates exactly the overlay's own changes (`claims.json` modified; a new adapter added) and nothing else. Do not widen it.
- `--tmpfs /tmp:rw,exec` — `exec` is required (tsx runs from `/tmp/.../node_modules/.bin`).
- The overlay step validates `ref` as a 40-hex SHA and the adapter path against the spec's charset; both come from a maintainer, but validating them costs nothing.

- [ ] **Step 2: Validate the YAML parses**

Run: `node -e "const y=require('fs').readFileSync('.github/workflows/interop-replay.yml','utf8'); console.log(y.split('\n').length, 'lines')"` then `npx -y yaml-lint .github/workflows/interop-replay.yml` (or `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/interop-replay.yml')); print('yaml ok')"`).
Expected: `yaml ok`.

- [ ] **Step 3: Local dry-run of the isolation branches (no third-party code)**

The two branches must at least start correctly on your machine before CI. Use a probe that prints its environment instead of a real claim:

```bash
# bolyra-suite branch shape: read-only mount + tmpfs + no runner env
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CLAIM_ID=probe \
  -v "$PWD:/work:ro" --tmpfs /tmp:rw,exec -w /work "node:20@sha256:<digest>" \
  sh -c 'env | sort; echo "--- write test ---"; (echo x > interop/replay.js && echo "WRITABLE (BAD)") || echo "read-only OK"; touch /tmp/ok && echo "tmpfs writable OK"; git -C /work rev-parse --short HEAD'
```
Expected: env shows only `HOME=/tmp`, `CLAIM_ID=probe`, `PATH`, `PWD`, `HOSTNAME`, `NODE_VERSION`, `YARN_VERSION` (no `GITHUB_*`, no `ACTIONS_*`); `read-only OK`; `tmpfs writable OK`; a short SHA (git accepts the mounted repo under `--user`).

```bash
# external-suite branch shape: scrubbed env
env -i PATH="$PATH" HOME="$HOME" CLAIM_ID=probe node -e 'console.log(Object.keys(process.env).sort().join(" "))'
```
Expected: `CLAIM_ID HOME PATH` only.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/interop-replay.yml
git commit -s -m "ci(interop-replay): ref/claim inputs; per-kind isolation; harness integrity check

bolyra-suite replays run inside a read-only-mounted node:20 container with
a tmpfs scratch and no runner environment; external-suite replays run on
the VM under env -i because replay.js must drive the host docker CLI (the
implementer's code already runs only in replay.js's --network none child).
Closes a pre-existing exposure: workflow_dispatch retains cache-write
access and runner tokens were readable by third-party code."
```

### Task 4: Prove the isolation in CI (recorded evidence)

**Files:** none committed; evidence goes in the eventual PR description.

- [ ] **Step 1: Push the branch and dispatch the workflow against main's registry**

```bash
git push -u origin public-conformance-claims
gh workflow run interop-replay.yml --repo bolyra/bolyra --ref public-conformance-claims
```
Then: `gh run list --repo bolyra/bolyra --workflow interop-replay.yml --limit 1` → note the run id → `gh run watch <id> --repo bolyra/bolyra --exit-status`.
Expected: success; log shows `2/2 claims reproduced`; the mcp-use claim ran inside `docker run` (group header `replay mcp-use-evc-example@17642a5/host_behavior@0.5.0 (bolyra-suite)`), the StillOS claim under `env -i`.

- [ ] **Step 2: Probe proof — bolyra-suite**

Temporarily (on a throwaway branch `probe/isolation`, never merged) add to `interop/adapters/` a copy of the existing adapter that prints `process.env` to stderr on startup, point a temporary duplicate claim at it, dispatch with `ref=<probe sha>` and `claim=<probe id>`, and confirm in the log: no `GITHUB_TOKEN`, no `ACTIONS_RUNTIME_TOKEN`, no `ACTIONS_*` at all. Also confirm the run fails at the adapter's attempt to write `interop/replay.js` if you add one (`EROFS`). Delete the probe branch. Save the run URL.

- [ ] **Step 3: Probe proof — external-suite**

Same pattern with a temporary external-suite claim whose `run.command` is `["sh","-c","env | sort"]` against a tiny public repo you control (or the StillOS pin with the command overridden). Confirm the child container's env has no runner tokens. Save the run URL. Delete the probe branch.

- [ ] **Step 4: Record**

Keep the three run URLs; they go into the implementation PR body under "Isolation proofs (spec §3.5)".

---

## Chunk 2: Generator, page, CI drift guard

### Task 5: `landing/gen-conformance.js` — validation

**Files:**
- Create: `landing/gen-conformance.js`
- Test: `landing/gen-conformance.test.js`

- [ ] **Step 1: Write the failing tests (validation only)**

Create `landing/gen-conformance.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateRegistry, renderRegistry, checkFile, coveredClasses } = require('./gen-conformance.js');

// external-suite fixtures need no adapter on disk (validateClaim resolves
// adapters relative to interop/, so bolyra-suite fixtures must be real).
function ext(overrides = {}) {
  return {
    id: 'kit@abc/own-corpus',
    kind: 'external-suite',
    claim_text: '39/39 of the kit\'s own pinned corpus (NOT Bolyra-suite conformance)',
    verified_on: '2026-09-09',
    implementer: { repo: 'https://github.com/example/kit', commit: 'a'.repeat(40) },
    run: {
      image: 'node:20@sha256:' + 'b'.repeat(64),
      command: ['npm', 'test', '--silent'],
      network: 'none',
      expect: { pass: 39, run: 39, scoped_out: 9 },
    },
    ...overrides,
  };
}

test('valid external-suite registry passes', () => {
  assert.deepStrictEqual(validateRegistry({ claims: [ext()] }), []);
});

test('unknown kind is rejected', () => {
  const errs = validateRegistry({ claims: [ext({ kind: 'mystery' })] });
  assert.ok(errs.some((e) => /unknown kind mystery/.test(e)), errs.join('\n'));
});

test('non-github implementer.repo is rejected', () => {
  for (const repo of ['javascript:alert(1)', 'https://evil.example/x/y', 'https://github.com/only-owner', 'http://github.com/a/b']) {
    const errs = validateRegistry({ claims: [ext({ implementer: { repo, commit: 'a'.repeat(40) } })] });
    assert.ok(errs.some((e) => /implementer\.repo/.test(e)), `should reject ${repo}`);
  }
});

test('verification_run_url is rejected in v1', () => {
  const errs = validateRegistry({ claims: [ext({ verification_run_url: 'https://github.com/bolyra/bolyra/actions/runs/1' })] });
  assert.ok(errs.some((e) => /verification_run_url/.test(e)));
});

test('verified_on must be YYYY-MM-DD and claim_text required', () => {
  assert.ok(validateRegistry({ claims: [ext({ verified_on: 'yesterday' })] }).some((e) => /verified_on/.test(e)));
  assert.ok(validateRegistry({ claims: [ext({ claim_text: '' })] }).some((e) => /claim_text/.test(e)));
});

test('registry-level shape errors', () => {
  assert.deepStrictEqual(validateRegistry(null), ['registry.claims must be an array']);
  assert.deepStrictEqual(validateRegistry({ claims: 'x' }), ['registry.claims must be an array']);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test landing/gen-conformance.test.js`
Expected: FAIL — `Cannot find module './gen-conformance.js'`.

- [ ] **Step 3: Implement validation**

Create `landing/gen-conformance.js`:

```js
#!/usr/bin/env node
'use strict';
// Renders interop/claims.json to landing/conformance.html. Zero dependencies.
//   node landing/gen-conformance.js          # (re)generate the page
//   node landing/gen-conformance.js --check  # exit 1 if the committed page drifts
// Never hand-edit conformance.html; CI runs --check.

const fs = require('fs');
const path = require('path');
const { validateClaim } = require('../interop/replay.js');

const ROOT = path.resolve(__dirname, '..');
const REGISTRY_PATH = path.join(ROOT, 'interop', 'claims.json');
const OUT_PATH = path.join(__dirname, 'conformance.html');

const KINDS = new Set(['bolyra-suite', 'external-suite']);
const REPO_RE = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function validateRegistry(reg) {
  if (!reg || !Array.isArray(reg.claims)) return ['registry.claims must be an array'];
  const errors = [];
  for (const c of reg.claims) {
    const id = c.id || '<no id>';
    const kind = c.kind || 'bolyra-suite';
    if (!KINDS.has(kind)) errors.push(`${id}: unknown kind ${kind}`);
    if (!c.implementer || !REPO_RE.test(c.implementer.repo || '')) {
      errors.push(`${id}: implementer.repo must match https://github.com/<owner>/<repo>`);
    }
    if ('verification_run_url' in c) errors.push(`${id}: verification_run_url is not rendered in v1; remove it`);
    if (!DATE_RE.test(c.verified_on || '')) errors.push(`${id}: verified_on must be YYYY-MM-DD`);
    if (!c.claim_text) errors.push(`${id}: claim_text is required`);
    if (KINDS.has(kind)) for (const e of validateClaim(c)) errors.push(`${id}: ${e}`);
  }
  return errors;
}

module.exports = { validateRegistry, esc };

if (require.main === module) {
  process.stderr.write('renderRegistry not implemented yet\n');
  process.exit(2);
}
```

- [ ] **Step 4: Run to verify the validation tests pass**

Run: `node --test landing/gen-conformance.test.js`
Expected: the 6 validation tests pass. (The `require` of `renderRegistry`, `checkFile`, `coveredClasses` yields `undefined` — no test calls them yet.)

- [ ] **Step 5: Commit**

```bash
git add landing/gen-conformance.js landing/gen-conformance.test.js
git commit -s -m "landing: conformance generator — registry validation"
```

### Task 6: `gen-conformance.js` — rendering

**Files:**
- Modify: `landing/gen-conformance.js`
- Test: `landing/gen-conformance.test.js`

- [ ] **Step 1: Write the failing rendering tests**

Append to `landing/gen-conformance.test.js`:

```js
test('coveredClasses: from --type selectors for bolyra-suite; not applicable for external-suite', () => {
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: { runner_args: ['--type', 'host_behavior'] } }), 'host_behavior');
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: { runner_args: ['--type', 'a', '--type', 'b'] } }), 'a, b');
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: { runner_args: [] } }), 'Not specified');
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: {} }), 'Not specified');
  assert.strictEqual(coveredClasses({ kind: 'external-suite' }), 'not applicable (own corpus)');
});

test('render escapes registry strings and never interpolates markup', () => {
  const html = renderRegistry({ claims: [ext({ claim_text: '<script>alert(1)</script> & "quotes"' })] });
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;'));
});

test('external-suite rows carry the fixed own-corpus qualifier regardless of claim_text', () => {
  const html = renderRegistry({ claims: [ext({ claim_text: 'totally conformant, trust me' })] });
  assert.ok(html.includes('Own-corpus reproduction: the implementer'));
  assert.ok(html.includes('This is NOT Bolyra-suite conformance.'));
});

test('render builds links only from validated repo + sha', () => {
  const html = renderRegistry({ claims: [ext()] });
  assert.ok(html.includes('href="https://github.com/example/kit"'));
  assert.ok(html.includes('href="https://github.com/example/kit/commit/' + 'a'.repeat(40) + '"'));
});

test('render is deterministic and ordered by verified_on desc then id', () => {
  const reg = { claims: [
    ext({ id: 'b', verified_on: '2026-01-01' }),
    ext({ id: 'a', verified_on: '2026-01-01' }),
    ext({ id: 'c', verified_on: '2026-02-01' }),
  ] };
  const html1 = renderRegistry(reg);
  const html2 = renderRegistry({ claims: [...reg.claims].reverse() });
  assert.strictEqual(html1, html2);
  const order = ['c', 'a', 'b'].map((id) => html1.indexOf(`<h2 class="claim-id">${id}</h2>`));
  assert.ok(order[0] < order[1] && order[1] < order[2], order.join(','));
  assert.ok(!/generated (at|on)/i.test(html1), 'no generation timestamp');
});

test('render throws on an invalid registry', () => {
  assert.throws(() => renderRegistry({ claims: [ext({ kind: 'mystery' })] }), /unknown kind/);
});

test('checkFile: identical passes, one-byte drift fails with the differing line', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gen-conf-'));
  const file = path.join(dir, 'conformance.html');
  const reg = { claims: [ext()] };
  fs.writeFileSync(file, renderRegistry(reg));
  assert.deepStrictEqual(checkFile(reg, file), { ok: true, diff: [] });
  fs.writeFileSync(file, renderRegistry(reg).replace('2026-09-09', '2026-09-08'));
  const r = checkFile(reg, file);
  assert.strictEqual(r.ok, false);
  assert.ok(r.diff.length >= 1 && r.diff[0].includes('2026-09-0'), r.diff.join('\n'));
  assert.strictEqual(checkFile(reg, path.join(dir, 'missing.html')).ok, false);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test landing/gen-conformance.test.js`
Expected: the 7 new tests FAIL (`coveredClasses is not a function`, etc.).

- [ ] **Step 3: Implement rendering, coveredClasses, checkFile, and the CLI**

Replace the `module.exports` line and the `require.main` block at the bottom of `landing/gen-conformance.js` with:

```js
function coveredClasses(c) {
  if ((c.kind || 'bolyra-suite') === 'external-suite') return 'not applicable (own corpus)';
  const args = (c.suite && Array.isArray(c.suite.runner_args)) ? c.suite.runner_args : [];
  const types = [];
  for (let i = 0; i + 1 < args.length; i++) if (args[i] === '--type') types.push(args[i + 1]);
  return types.length ? types.join(', ') : 'Not specified';
}

const EXTERNAL_QUALIFIER =
  'Own-corpus reproduction: the implementer\'s published numbers reproduce at the pin. This is NOT Bolyra-suite conformance.';

function sortClaims(claims) {
  return [...claims].sort((a, b) => (b.verified_on.localeCompare(a.verified_on)) || a.id.localeCompare(b.id));
}

function renderClaim(c) {
  const kind = c.kind || 'bolyra-suite';
  const repo = c.implementer.repo;                       // validated by REPO_RE
  const commit = c.implementer.commit;                   // validated 40-hex by validateClaim
  const rows = [];
  const row = (k, v) => rows.push(`<tr><th>${esc(k)}</th><td>${v}</td></tr>`);
  row('Implementer', `<a href="${esc(repo)}">${esc(repo.replace('https://github.com/', ''))}</a>`);
  row('Implementation commit', `<a href="${esc(repo)}/commit/${esc(commit)}"><code>${esc(commit)}</code></a>`);
  row('Kind', esc(kind));
  if (kind === 'bolyra-suite') {
    row('Suite commit', `<a href="https://github.com/bolyra/bolyra/commit/${esc(c.suite.commit)}"><code>${esc(c.suite.commit)}</code></a>`);
    row('Vector set', esc(c.suite.vector_set || 'Not specified'));
    row('test-vectors.json sha256', `<code>${esc(c.suite.test_vectors_sha256)}</code>`);
    row('Covered classes', esc(coveredClasses(c)));
    row('Runner arguments', `<code>${esc(JSON.stringify(c.suite.runner_args || []))}</code>`);
    row('Adapter', `<code>${esc(c.adapter)}</code> (sha256 <code>${esc(c.adapter_sha256)}</code>)`);
    row('Expected', esc(`${c.expected.pass} pass / ${c.expected.fail} fail / ${c.expected.skip} skip`));
  } else {
    row('Covered classes', esc(coveredClasses(c)));
    row('Run', `<code>${esc(JSON.stringify(c.run.command))}</code> in <code>${esc(c.run.image)}</code>, network <code>${esc(c.run.network)}</code>`);
    row('Expected', esc(`${c.run.expect.pass}/${c.run.expect.run} pass, ${c.run.expect.scoped_out ?? 0} scoped out`));
  }
  row('Claim', esc(c.claim_text));
  if (c.scope) row('Scope', esc(c.scope));
  row('Recorded verification date', esc(c.verified_on));
  const qualifier = kind === 'external-suite' ? `<p class="qualifier">${esc(EXTERNAL_QUALIFIER)}</p>` : '';
  return `<section class="claim">
<h2 class="claim-id">${esc(c.id)}</h2>
${qualifier}<table>${rows.join('')}</table>
</section>`;
}

function renderRegistry(reg) {
  const errors = validateRegistry(reg);
  if (errors.length) throw new Error(errors.join('\n'));
  const sections = sortClaims(reg.claims).map(renderClaim).join('\n');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Conformance Claims — Bolyra</title>
  <meta name="description" content="Every external interoperability claim Bolyra publishes, with the pins that make it mechanically reproducible.">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='12' fill='%230a0a0a'/%3E%3Ctext x='32' y='44' font-family='-apple-system,BlinkMacSystemFont,sans-serif' font-size='38' font-weight='700' text-anchor='middle' fill='%236366f1'%3EB%3C/text%3E%3C/svg%3E">
  <style>
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    :root { --bg: #0a0a0a; --bg-elevated: #111113; --bg-code: #1a1a2e; --text: #e0e0e0; --text-muted: #888; --accent: #6366f1; --accent-hover: #818cf8; --cyan: #22d3ee; --border: #222; --max-width: 1100px; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; }
    main { max-width: var(--max-width); margin: 0 auto; padding: 48px 24px 96px; }
    a { color: var(--accent); text-decoration: none; } a:hover { color: var(--accent-hover); }
    h1 { font-size: 2rem; margin-bottom: 8px; } .lede { color: var(--text-muted); margin-bottom: 8px; }
    .notice { color: var(--cyan); margin: 16px 0 32px; font-weight: 600; }
    .claim { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; overflow-x: auto; }
    .claim-id { font-size: 1.1rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-bottom: 12px; word-break: break-all; }
    .qualifier { color: var(--cyan); margin-bottom: 12px; }
    table { border-collapse: collapse; width: 100%; } th, td { text-align: left; vertical-align: top; padding: 6px 12px 6px 0; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); white-space: nowrap; width: 220px; font-weight: 500; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; word-break: break-all; }
    .links a { margin-right: 24px; } footer { color: var(--text-muted); margin-top: 48px; font-size: 0.9rem; }
  </style>
</head>
<body>
<main>
  <p><a href="/">&larr; bolyra.ai</a></p>
  <h1>Conformance claims</h1>
  <p class="lede">Every external interoperability claim Bolyra publishes, with the pins that make it mechanically reproducible from <code>interop/claims.json</code> using <code>interop/replay.js</code>.</p>
  <p class="notice">These are dated claims. This page does not report current replay status.</p>
  <p class="links"><a href="https://github.com/bolyra/bolyra/actions/workflows/interop-replay.yml">Replay history</a><a href="https://github.com/bolyra/bolyra/blob/main/interop/SUBMITTING.md">How to add yours</a><a href="https://github.com/bolyra/bolyra/blob/main/spec/IMPLEMENTER.md">IMPLEMENTER.md</a></p>
${sections}
  <footer>Source of truth: <a href="https://github.com/bolyra/bolyra/blob/main/interop/claims.json">interop/claims.json</a>. A red replay means investigate, never edit the claim.</footer>
</main>
</body>
</html>
`;
}

function checkFile(reg, filePath) {
  const expected = renderRegistry(reg);
  if (!fs.existsSync(filePath)) return { ok: false, diff: [`${filePath}: missing (run: node landing/gen-conformance.js)`] };
  const actual = fs.readFileSync(filePath, 'utf8');
  if (actual === expected) return { ok: true, diff: [] };
  const a = actual.split('\n'), e = expected.split('\n');
  const diff = [];
  for (let i = 0; i < Math.max(a.length, e.length) && diff.length < 20; i++) {
    if (a[i] !== e[i]) diff.push(`line ${i + 1}:\n  committed: ${a[i] ?? '<EOF>'}\n  expected:  ${e[i] ?? '<EOF>'}`);
  }
  return { ok: false, diff };
}

module.exports = { validateRegistry, renderRegistry, checkFile, coveredClasses, esc };

if (require.main === module) {
  const reg = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
  if (process.argv.includes('--check')) {
    const r = checkFile(reg, OUT_PATH);
    if (r.ok) { console.log('gen-conformance --check OK: landing/conformance.html matches interop/claims.json'); process.exit(0); }
    process.stderr.write(`gen-conformance --check FAILED: landing/conformance.html drifts from interop/claims.json\n${r.diff.join('\n')}\nRun: node landing/gen-conformance.js\n`);
    process.exit(1);
  }
  fs.writeFileSync(OUT_PATH, renderRegistry(reg));
  console.log(`wrote ${path.relative(ROOT, OUT_PATH)} (${reg.claims.length} claims)`);
}
```

- [ ] **Step 4: Run all generator tests**

Run: `node --test landing/gen-conformance.test.js`
Expected: 13 tests pass.

- [ ] **Step 5: Generate the real page and eyeball it**

Run: `node landing/gen-conformance.js && node landing/gen-conformance.js --check`
Expected: `wrote landing/conformance.html (2 claims)` then `... --check OK`.
Open `landing/conformance.html` in a browser: two sections; the StillOS one shows the cyan own-corpus qualifier; the mcp-use one shows "Covered classes: host_behavior".

- [ ] **Step 6: Commit (generator + generated page together)**

```bash
git add landing/gen-conformance.js landing/gen-conformance.test.js landing/conformance.html
git commit -s -m "landing: conformance page generator + first generated page (2 claims)"
```

### Task 7: CI drift guard and offline replay check

**Files:**
- Modify: `.github/workflows/ci.yml` (the `evc-conformance` job)

- [ ] **Step 1: Edit the job**

In `.github/workflows/ci.yml`, in the `evc-conformance` job:

(a) Replace its checkout step
```yaml
      - uses: actions/checkout@v7.0.1
```
with
```yaml
      - uses: actions/checkout@v7.0.1
        with:
          # replay.js --check does `git show <suite.commit>:spec/test-vectors.json`
          # at historical pins, which needs full history.
          fetch-depth: 0
```

(b) Replace the final step
```yaml
      - name: Interop replay harness — offline regression tests
        run: node --test interop/replay.test.js
```
with
```yaml
      - name: Interop replay harness — offline regression tests
        run: node --test interop/replay.test.js

      # Registry + suite-pin validation without executing anything (the live
      # replay is the separate interop-replay dispatch workflow).
      - name: Interop registry — offline pin check
        run: node interop/replay.js --check

      # landing/conformance.html is generated from interop/claims.json and
      # committed; any drift between them is a CI failure.
      - name: Conformance page — generator tests + drift check
        run: |
          node --test landing/gen-conformance.test.js
          node landing/gen-conformance.js --check
```

- [ ] **Step 2: Validate YAML and run the same commands locally**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"` then `node interop/replay.js --check && node --test landing/gen-conformance.test.js && node landing/gen-conformance.js --check`
Expected: `yaml ok`; two `registry + suite pin OK`/`registry OK` lines; 13 tests pass; `--check OK`.

- [ ] **Step 3: Negative control for the drift guard**

Run: `sed -i.bak 's/Recorded verification date/Recorded verification dat/' landing/conformance.html && node landing/gen-conformance.js --check; echo "exit=$?"; mv landing/conformance.html.bak landing/conformance.html`
Expected: `--check FAILED` with a `line N:` block, `exit=1`; then restored.

- [ ] **Step 4: Commit and push; watch CI**

```bash
git add .github/workflows/ci.yml
git commit -s -m "ci: offline interop pin check + conformance page drift guard"
git push
```
Then `gh pr checks` is not available until a PR exists — open the draft PR now so CI runs on every later push:
```bash
gh pr create --repo bolyra/bolyra --base main --head public-conformance-claims --draft \
  --title "Public conformance claims (v1): page, generator, dispatch isolation, landing copy" \
  --body "Implements docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md (v1 scope). Draft until Chunk 3 lands."
gh pr checks --repo bolyra/bolyra --watch
```
Expected: all checks green, including `EVC conformance — package sync & both reference hosts`.

---

## Chunk 3: Landing copy, deploy/verify, submission docs, end-to-end proof

### Task 8: `landing/index.html` copy changes (spec §3.4)

Line numbers are as of `f106b00`; confirm with `grep -n` before editing — the text is what matters.

**Files:**
- Modify: `landing/index.html`

- [ ] **Step 1: Line 947-948 — the "Hosted or self-hosted" card**

Replace
```html
          <h3>Hosted or self-hosted</h3>
          <p>Self-hosted gateway today — deploy inside your customer's VPC. A hosted verifier preview is live for design partners: <code>POST /v1/verify</code>, same External Verifier Contract, HTTP instead of local spawn — evaluate with a partner token before installing the gateway. Open-core protocol, Apache-2.0.</p>
```
with
```html
          <h3>Self-hosted</h3>
          <p>Self-hosted gateway — deploy inside your customer's VPC. Open-core protocol, Apache-2.0.</p>
```

- [ ] **Step 2: Line 953 — the boundary paragraph**

Replace the sentence pair
```
Pilot against Bolyra's hosted verifier preview today, then keep the same boundary if you self-host or swap verifier implementations later. Bolyra maintains the spec, conformance vectors, reference hosts, and managed verifier path.
```
with
```
Run the published conformance suite, explore the reference implementations, or verify locally with <code>bolyra verify</code>. Bolyra maintains the spec, conformance vectors, and reference hosts.
```

- [ ] **Step 3: Line 954 — delete the whole line**

Delete:
```html
        <p style="color: var(--cyan); margin: 14px 0 0; font-weight: 600;">Open contract. Managed operations when you need them.</p>
```

- [ ] **Step 4: Line 955 — count + link to the page**

Replace `and 10 domain-agnostic wire-envelope vectors` with `and 11 domain-agnostic wire-envelope vectors`.
Replace `It is also listed in &sect;9 with the author's explicit permission:` with `It is also listed in &sect;9 with the author's explicit permission. Every published claim, with its pins, is on <a href="/conformance">the conformance page</a>:`.

- [ ] **Step 5: Line 1031 — package row**

Replace `<code>@bolyra/evc-conformance@0.5.0</code>` with `<code>@bolyra/evc-conformance@0.6.0</code>`; replace `40 wire-contract vectors` with `41 wire-contract vectors`; delete ` Hosted <code>POST /v1/verify</code> preview for design partners, same External Verifier Contract.` (including the leading space).

- [ ] **Step 6: Navigation links**

After line 753 `<li><a href="/playground">Playground</a></li>` add `<li><a href="/conformance">Conformance</a></li>`; do the same in the footer list after line 1196's `<li><a href="/playground">Playground</a></li>`.

- [ ] **Step 7: Verify the edits by grep (all must hold)**

```bash
grep -c "hosted verifier preview" landing/index.html          # expect 0
grep -c "Hosted <code>POST /v1/verify</code> preview" landing/index.html   # expect 0
grep -c "managed verifier path" landing/index.html            # expect 0
grep -c "Managed operations when you need them" landing/index.html  # expect 0
grep -c "@bolyra/evc-conformance@0.6.0" landing/index.html    # expect 1
grep -c "41 wire-contract vectors" landing/index.html         # expect 1
grep -c "11 domain-agnostic wire-envelope vectors" landing/index.html  # expect 1
grep -c 'href="/conformance"' landing/index.html              # expect 3
```

- [ ] **Step 8: Commit**

```bash
git add landing/index.html
git commit -s -m "landing: drop hosted-verifier/managed-platform copy; evc-conformance 0.6.0 / 41 vectors; link /conformance"
```

### Task 9: `deploy.sh` and `verify.sh`

**Files:**
- Modify: `landing/deploy.sh`
- Modify: `landing/verify.sh`

- [ ] **Step 1: deploy.sh — page variable, pre-check, preflight**

After line 35 `PLAYGROUND="$SCRIPT_DIR/playground.html"` add:
```bash
CONFORMANCE="$SCRIPT_DIR/conformance.html"
```
In the `for f in ...` pre-check loop on line 37, append `"$CONFORMANCE"` to the list.
After line 59 `preflight_version "@bolyra/cli"     "@bolyra/cli@"` add:
```bash
preflight_version "@bolyra/evc-conformance" "@bolyra/evc-conformance@"
# The committed page must match the registry; deploying a stale page is a
# silent lie about which claims exist.
node "$SCRIPT_DIR/gen-conformance.js" --check || { echo "ERROR: landing/conformance.html drifts from interop/claims.json — run node landing/gen-conformance.js" >&2; exit 1; }
```

- [ ] **Step 2: deploy.sh — upload pair**

After the `agent-spend` upload pair (ends line 145) add:
```bash
echo "→ uploading conformance.html to s3://$BUCKET/"
aws s3 cp "$CONFORMANCE" "s3://$BUCKET/conformance.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$CONFORMANCE" "s3://$BUCKET/conformance" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
```

- [ ] **Step 3: deploy.sh — invalidation**

In the `--paths` list on line 252, add `"/conformance.html" "/conformance"` after `"/agent-spend"`.

- [ ] **Step 4: verify.sh — guard, count assertion, deleted phrases, /conformance**

After line 242 `guard_version "@bolyra/cli"     "@bolyra/cli@"` add:
```bash
guard_version "@bolyra/evc-conformance" "@bolyra/evc-conformance@"

# The advertised vector count must equal what the published package actually
# loads (pinned to the advertised version; unpinned npx can serve the cache).
EVC_PUBLISHED=$(npm view "@bolyra/evc-conformance" version 2>/dev/null | tr -d '[:space:]')
ADVERTISED_COUNT=$(grep -oE '[0-9]+ wire-contract vectors' <<< "$LIVE_HTML" | head -1 | grep -oE '^[0-9]+' || true)
[ -n "$ADVERTISED_COUNT" ] || fail "page does not advertise a wire-contract vector count"
EVC_TMP=$(mktemp -d)
LOADED_COUNT=$( (cd "$EVC_TMP" && npx -y "@bolyra/evc-conformance@${EVC_PUBLISHED}" 2>/dev/null | grep -oE '^[0-9]+ test vectors loaded' | head -1 | grep -oE '^[0-9]+') || true )
rm -rf "$EVC_TMP"
if [ "$ADVERTISED_COUNT" = "$LOADED_COUNT" ]; then
  pass "vector count: page advertises $ADVERTISED_COUNT, @bolyra/evc-conformance@$EVC_PUBLISHED loads $LOADED_COUNT"
else
  fail "vector count drift: page advertises '$ADVERTISED_COUNT' but @bolyra/evc-conformance@$EVC_PUBLISHED loads '$LOADED_COUNT'"
fi

# Copy that promises a hosted/managed platform was removed on 2026-09-10 and
# must not come back (settled 2026-08-27 ruling: no hosted platform).
for phrase in "hosted verifier preview" "Hosted <code>POST /v1/verify</code> preview" "managed verifier path" "Managed operations when you need them"; do
  if grep -qF "$phrase" <<< "$LIVE_HTML"; then fail "removed copy reappeared on the live page: '$phrase'"; fi
done
pass "no hosted-verifier / managed-platform copy on the live page"

# The conformance page is live and carries both published claims.
CONF_HTML=$(curl -fsS "https://bolyra.ai/conformance?vguard=$(date +%s)") || fail "GET /conformance failed"
grep -qF "17642a5" <<< "$CONF_HTML" || fail "/conformance lacks the mcp-use claim pin 17642a5"
grep -qF "35e209d" <<< "$CONF_HTML" || fail "/conformance lacks the StillOS claim pin 35e209d"
grep -qF "This is NOT Bolyra-suite conformance." <<< "$CONF_HTML" || fail "/conformance lacks the own-corpus qualifier"
pass "/conformance is live with both claims and the own-corpus qualifier"
```

- [ ] **Step 5: Shell-check both scripts**

Run: `bash -n landing/deploy.sh && bash -n landing/verify.sh && echo syntax ok`
Expected: `syntax ok`.

- [ ] **Step 6: Commit**

```bash
git add landing/deploy.sh landing/verify.sh
git commit -s -m "landing: deploy/verify the conformance page; evc-conformance version + vector-count guards; forbid hosted-platform copy"
```

### Task 10: `interop/SUBMITTING.md` and README pointer

**Files:**
- Create: `interop/SUBMITTING.md`
- Modify: `interop/README.md`

- [ ] **Step 1: Write SUBMITTING.md**

Create `interop/SUBMITTING.md`:

```markdown
# Submitting a conformance claim

This is the maintainer-operated path (v1). Nothing on a pull request executes
third-party code; the maintainer replays your exact commit by hand before
merging. It relies on maintainer discipline, stated here so nobody mistakes it
for machine enforcement.

## What you submit

Exactly one pull request that touches only:

- `interop/claims.json` — **one added entry**, nothing else changed;
- for `bolyra-suite` claims, **one new** file `interop/adapters/<name>.ts`
  (pure I/O, see README rules) with its sha256 in `adapter_sha256`;
- `landing/conformance.html` — regenerated (below).

Do not modify existing claims or adapters. Do not set `verification_run_url`.

`implementer.install` must be `["npm","ci","--ignore-scripts"]` or
`["npm","install","--ignore-scripts"]`, optionally followed by `"--no-audit"`
and/or `"--no-fund"` in that order. `external-suite` claims need a
digest-pinned `node:` image (`node:<tag>@sha256:<64 hex>`) and
`"network": "none"`.

## Steps

1. Fork and branch from current `main`.
2. Add your entry (schema: README.md; copy an existing entry of the same kind).
3. Run `node interop/replay.js --check` — must pass offline.
4. Run `node landing/gen-conformance.js` and commit the regenerated
   `landing/conformance.html` together with your entry (and adapter).
5. Open the PR. CI runs the offline checks. Nothing executes your code yet.
6. The maintainer reviews the adapter and the pins, notes the head SHA, and
   runs the `Interop replay` workflow by dispatch with `ref=<that SHA>` and
   `claim=<your id>`. Your implementation runs under the isolation in the
   design spec §3.5. Any push after that review needs a fresh review and a
   fresh dispatch.
7. Green dispatch on the reviewed SHA + code-owner review → merge → your row
   appears on https://bolyra.ai/conformance at the next deploy. The dispatch
   run URL is recorded in the merge commit.

## Rules (from README)

- A red replay means investigate, never edit the claim.
- Claims stay pinned; re-verification at a newer suite is a **new** row.
- `external-suite` results are own-corpus reproductions, not Bolyra-suite
  conformance; the page says so on every such row regardless of your text.
```

- [ ] **Step 2: README pointer**

In `interop/README.md`, at the end of the `## Rules` section, add:
```markdown
- **Submitting a claim**: see [SUBMITTING.md](SUBMITTING.md). `verification_run_url`
  is a reserved field (not rendered in v1; rejected on submissions).
```

- [ ] **Step 3: Commit**

```bash
git add interop/SUBMITTING.md interop/README.md
git commit -s -m "interop: SUBMITTING.md — maintainer-operated claim submissions"
```

### Task 11: End-to-end proof, deploy, and PR

**Files:** none new; evidence in the PR body.

- [ ] **Step 1: Dry-run submission on a throwaway branch**

On a throwaway branch `probe/submission` from `public-conformance-claims`: duplicate the StillOS entry with a new id `probe@35e209d/own-corpus`, regenerate the page, push, open a draft PR, confirm CI's offline checks are green and that no job executed third-party code (inspect the logs of the `evc-conformance` job: only `--check`, tests, generator). Then dispatch `interop-replay.yml` with `ref=<probe head sha>` and `claim=probe@35e209d/own-corpus` → expect green. Then change the probe entry's `run.expect.pass` to 38 → push → dispatch again → expect RED (`count mismatch`). Record both run URLs. Close the probe PR; delete the branch.

- [ ] **Step 2: Deploy the landing**

From the worktree: `BOLYRA_SKIP_VERIFY= ./landing/deploy.sh` (verify runs automatically after invalidation).
Expected: preflight lines including `OK: local page advertises @bolyra/evc-conformance@0.6.0`; upload lines including `conformance.html`; invalidation id; then verify.sh output ending with the new `OK:` lines (`vector count`, `no hosted-verifier`, `/conformance is live`).

- [ ] **Step 3: Live curl**

```bash
curl -fsS https://bolyra.ai/conformance | grep -c "claim-id"          # expect 2
curl -fsS https://bolyra.ai/ | grep -c "hosted verifier preview"       # expect 0
curl -fsS https://bolyra.ai/ | grep -c "@bolyra/evc-conformance@0.6.0" # expect 1
```

- [ ] **Step 4: Mark the PR ready with the evidence**

Update the PR body to list: the three isolation-proof run URLs (Task 4), the two submission-proof run URLs (Step 1), the deploy + verify output, and the live curls. Then `gh pr ready`. Codex reviews the diff before merge (workspace rule).

- [ ] **Step 5: After merge — record**

Append a line to `~/.claude/projects/-Users-lordviswa-Projects/memory/github_activity_bolyra.md` with the PR number, merge SHA, and the one-line summary; update `MEMORY.md`'s pointer line for this build to DONE.
