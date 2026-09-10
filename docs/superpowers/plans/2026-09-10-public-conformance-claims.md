# Public Conformance Claims (v1) — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish `interop/claims.json` as a public, drift-guarded page at `bolyra.ai/conformance`, document maintainer-operated claim submissions, isolate third-party code in the existing dispatch replay job, and fix the stale/false copy on the landing page.

**Architecture:** A zero-dependency generator (`landing/gen-conformance.js`) renders the registry to a committed static page with a `--check` drift guard in CI. The dispatch job's security-critical logic lives in three small tested scripts — `replay.js --list` (claim listing), `interop/submission-overlay.js` (data-only overlay of one submission from a ref, via git blobs, never a checkout), `interop/harness-integrity.js` (snapshot/verify of the protected tree between claims) — and the workflow only calls them. bolyra-suite replays run inside a read-only-mounted container; external-suite on the VM under `env -i` (its implementer code already confined to `replay.js`'s own `--network none` child). No automatic gating (deferred; spec Appendix A).

**Tech Stack:** Node 20 (no runtime deps), `node:test`, GitHub Actions, Docker on the runner, bash (`deploy.sh`/`verify.sh`), static HTML.

**Spec:** `docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md` — read §2, §3.1–3.5, §6, §7 first.

**Conventions (every task):**
- Work in the worktree the orchestrator names, on branch `public-conformance-claims`. Never touch `main` directly. This is a git **worktree**: its `.git` is a file pointing elsewhere — local Docker probes use a standalone clone (Task 5 Step 3).
- Every commit block below starts with this exact line; copy it verbatim each time (fresh shells do not inherit it):
  `export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"`
  and commits with `git commit -s` (DCO trailer; CI checks it).
- Tests: `node:test` + `node:assert`, run with `node --test <file>`. No test-framework installs.
- YAML syntax checks use `ruby -ryaml -e 'YAML.load_file("<file>"); puts "yaml ok"'` (ruby is present; python has no `yaml` module here).
- `interop/replay.js` has 18 false-green regression tests. Tasks 1 touches it minimally (listing + a test-only registry path override). Never touch its replay logic.
- `<digest>` in Chunk 2 is the one intentional placeholder; Task 4 resolves it before Task 5 uses it.
- "Expected:" lines are what you must see. If you see something else, stop and report; do not improvise.

---

## File Structure

```
interop/
  replay.js                   MODIFY: --list (id\tkind\tadapter; hardened); REPLAY_CLAIMS_PATH test override
  replay.test.js              MODIFY: 6 tests for --list
  submission-overlay.js       CREATE: overlay ONE submission's claims.json + adapter from a ref, as git blobs
  submission-overlay.test.js  CREATE: temp-git-repo tests (happy path, symlink, replacement, unknown, kinds, non-commit ref)
  harness-integrity.js        CREATE: snapshot/verify protected tree (status + content hashes), for between-claims checks
  harness-integrity.test.js   CREATE: temp-git-repo tests
  SUBMITTING.md               CREATE: maintainer-operated submission contract (spec §3.3)
  README.md                   MODIFY: pointer to SUBMITTING.md; verification_run_url reserved
.github/workflows/
  interop-replay.yml          MODIFY: ref/claim inputs; per-kind isolation; integrity check (spec §3.5)
  ci.yml                      MODIFY: evc-conformance job: fetch-depth 0; replay --check; new script tests; generator --check
landing/
  gen-conformance.js          CREATE: validateRegistry(), renderRegistry(), checkFile(), coveredClasses(); CLI --check
  gen-conformance.test.js     CREATE: generator tests
  conformance.html            CREATE (generated): never hand-edit
  index.html                  MODIFY: copy deletions, version/count fixes, /conformance links (spec §3.4)
  deploy.sh                   MODIFY: conformance page upload + invalidation; evc-conformance preflight; drift check
  verify.sh                   MODIFY: evc-conformance guard; installed-count assertion; forbidden phrases; /conformance checks
```

---

## Chunk 1: Tested building blocks for the dispatch job

### Task 1: `replay.js --list` (hardened) + test-only registry override

`--list` prints `id<TAB>kind<TAB>adapter` per selected claim and nothing else. It must run BEFORE registry validation (a new submission's adapter is not on disk yet when the workflow lists it) and must refuse to emit rows that could confuse a TSV consumer.

**Files:**
- Modify: `interop/replay.js` (registry load line; usage comment; `main()`)
- Test: `interop/replay.test.js`

- [ ] **Step 1: Write the failing tests**

Append to `interop/replay.test.js`:

```js
// ---- --list -------------------------------------------------------------
// The dispatch workflow reads id/kind/adapter per claim without executing
// anything. Tests pass --check too: on a harness that ignores --list, --check
// runs OFFLINE (no third-party code) and the output format mismatch fails the
// test; on the real harness --list returns before --check.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function runList(extra = [], env = {}) {
  return spawnSync(process.execPath, [path.join(__dirname, 'replay.js'), '--list', '--check', ...extra], {
    encoding: 'utf8', timeout: 20000, env: { ...process.env, ...env },
  });
}
function rows(stdout) {
  const lines = stdout.split('\n');
  assert.strictEqual(lines[lines.length - 1], '', 'stdout must end with exactly one newline');
  lines.pop();
  return lines.map((l) => l.split('\t'));
}
function withRegistry(claims) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'replay-list-'));
  const p = path.join(dir, 'claims.json');
  fs.writeFileSync(p, JSON.stringify({ version: '1.0', claims }));
  return { REPLAY_CLAIMS_PATH: p };
}

test('--list prints id<TAB>kind<TAB>adapter per claim, nothing else', () => {
  const r = runList();
  assert.strictEqual(r.status, 0, r.stderr);
  const claims = require('./claims.json').claims;
  const got = rows(r.stdout);
  assert.strictEqual(got.length, claims.length);
  claims.forEach((c, i) => assert.deepStrictEqual(got[i], [c.id, c.kind || 'bolyra-suite', c.adapter || '']));
});

test('--list keeps the empty adapter field on a final external-suite row (trailing tab survives)', () => {
  const env = withRegistry([
    { id: 'a', kind: 'external-suite', implementer: { repo: 'r', commit: 'a'.repeat(40) }, run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['npm', 'test'], network: 'none', expect: { pass: 1, run: 1 } } },
  ]);
  const r = runList([], env);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stdout, 'a\texternal-suite\t\n');
});

test('--list --claim <id> prints only that claim', () => {
  const first = require('./claims.json').claims[0];
  const r = runList(['--claim', first.id]);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.deepStrictEqual(rows(r.stdout), [[first.id, first.kind || 'bolyra-suite', first.adapter || '']]);
});

test('--list --claim <unknown> exits 1 with empty stdout', () => {
  const r = runList(['--claim', 'does-not-exist']);
  assert.strictEqual(r.status, 1);
  assert.strictEqual(r.stdout, '');
  assert.match(r.stderr, /no claim with id does-not-exist/);
});

test('--list runs before registry validation (a claim whose adapter is missing on disk still lists)', () => {
  const env = withRegistry([
    { id: 'new@1', implementer: { repo: 'r', commit: 'a'.repeat(40) }, suite: { commit: 'b'.repeat(40), test_vectors_sha256: 'c'.repeat(64) }, adapter: 'adapters/not-on-disk.ts', adapter_sha256: 'd'.repeat(64), expected: { pass: 1, fail: 0, skip: 0 } },
  ]);
  const r = runList([], env);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stdout, 'new@1\tbolyra-suite\tadapters/not-on-disk.ts\n');
});

test('--list refuses ids with tab/CR/LF, duplicate ids, and unknown kinds — with no stdout', () => {
  const base = { implementer: { repo: 'r', commit: 'a'.repeat(40) }, run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['x'], network: 'none', expect: { pass: 1, run: 1 } }, kind: 'external-suite' };
  for (const [label, claims, re] of [
    ['tab in id', [{ ...base, id: 'a\tb' }], /id contains a control character/],
    ['newline in id', [{ ...base, id: 'a\nb' }], /id contains a control character/],
    ['duplicate id', [{ ...base, id: 'dup' }, { ...base, id: 'dup' }], /duplicate id dup/],
    ['unknown kind', [{ ...base, id: 'k', kind: 'mystery' }], /unknown kind mystery/],
    ['empty id', [{ ...base, id: '' }], /missing id/],
  ]) {
    const r = runList([], withRegistry(claims));
    assert.strictEqual(r.status, 1, label);
    assert.strictEqual(r.stdout, '', label);
    assert.match(r.stderr, re, label);
  }
});
```

- [ ] **Step 2: Run to verify they fail — offline**

Run: `node --test interop/replay.test.js`
Expected: 18 existing tests pass; of the 6 new tests, 5 FAIL (the harness ignores `--list`, runs `--check` offline, and the stdout is `...registry + suite pin OK` lines, not TSV) and `--list --claim <unknown>` PASSES already (unknown id exits 1 today). No network activity; no `cloning …` lines in any output.

- [ ] **Step 3: Implement**

(a) In `interop/replay.js`, replace the registry load line
```js
const CLAIMS = JSON.parse(fs.readFileSync(path.join(__dirname, 'claims.json'), 'utf8'));
```
with
```js
// REPLAY_CLAIMS_PATH is for tests only (points --list at a fixture registry).
// The dispatch workflow runs with an explicit environment and never sets it.
const CLAIMS_PATH = process.env.REPLAY_CLAIMS_PATH || path.join(__dirname, 'claims.json');
const CLAIMS = JSON.parse(fs.readFileSync(CLAIMS_PATH, 'utf8'));
```

(b) In the usage comment near the top, after the `--keep` line, add:
```js
 *   node interop/replay.js --list       # offline: id<TAB>kind<TAB>adapter per claim (before validation)
```

(c) In `main()`, insert immediately AFTER the `if (!claims.length) { ... return; }` block and BEFORE `let allValid = true;`:
```js
  // --list: id<TAB>kind<TAB>adapter per selected claim, no execution and no
  // registry validation (a submission's adapter may not be on disk yet). The
  // dispatch workflow consumes this as TSV, so refuse anything that could be
  // misparsed: control characters in ids, duplicate ids, unknown kinds.
  if (flag('--list')) {
    const KINDS = new Set(['bolyra-suite', 'external-suite']);
    const seen = new Set();
    const out = [];
    for (const c of claims) {
      const id = c.id;
      if (typeof id !== 'string' || !id) return fail('--list: missing id');
      if (/[\t\r\n]/.test(id)) return fail(`--list: id contains a control character: ${JSON.stringify(id)}`);
      if (seen.has(id)) return fail(`--list: duplicate id ${id}`);
      seen.add(id);
      const kind = c.kind === undefined ? 'bolyra-suite' : c.kind;
      if (!KINDS.has(kind)) return fail(`--list: unknown kind ${kind} (claim ${id})`);
      const adapter = c.adapter === undefined ? '' : String(c.adapter);
      if (/[\t\r\n]/.test(adapter)) return fail(`--list: adapter contains a control character (claim ${id})`);
      out.push(`${id}\t${kind}\t${adapter}`);
    }
    process.stdout.write(out.join('\n') + '\n');
    return;
  }
```
(`fail()` sets `process.exitCode = 1` and returns undefined, so `return fail(...)` exits 1 with nothing on stdout.)

- [ ] **Step 4: Run to verify they pass**

Run: `node --test interop/replay.test.js`
Expected: 24 pass, 0 fail.

- [ ] **Step 5: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add interop/replay.js interop/replay.test.js
git commit -s -m "interop: replay.js --list (hardened TSV listing before validation) + REPLAY_CLAIMS_PATH test override"
```

### Task 2: `interop/submission-overlay.js`

Overlays exactly one submission's `interop/claims.json` and, for `bolyra-suite`, its one new adapter, from a commit — reading **git blobs**, never checking out (a checkout could install a symlink at the permitted path).

**Files:**
- Create: `interop/submission-overlay.js`
- Test: `interop/submission-overlay.test.js`

- [ ] **Step 1: Write the failing tests**

Create `interop/submission-overlay.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, 'submission-overlay.js');
const GIT_ENV = { GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };

function git(cwd, ...args) { return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', env: { ...process.env, ...GIT_ENV } }); }

const BASE_CLAIM = {
  id: 'base@1', implementer: { repo: 'https://github.com/x/y', commit: 'a'.repeat(40) },
  suite: { commit: 'b'.repeat(40), test_vectors_sha256: 'c'.repeat(64) },
  adapter: 'adapters/base.ts', adapter_sha256: 'd'.repeat(64), expected: { pass: 1, fail: 0, skip: 0 },
};
const EXT_CLAIM = {
  id: 'ext@1', kind: 'external-suite', implementer: { repo: 'https://github.com/x/z', commit: 'e'.repeat(40) },
  run: { image: 'node:20@sha256:' + 'f'.repeat(64), command: ['npm', 'test'], network: 'none', expect: { pass: 1, run: 1 } },
};

// A temp repo with a base commit (registry + one adapter), then a "submission"
// commit built by `mutate(repoDir)`. Returns {repo, baseSha, subSha}.
function makeRepo(mutate) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'overlay-'));
  git(repo, 'init', '-q');
  fs.mkdirSync(path.join(repo, 'interop', 'adapters'), { recursive: true });
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), JSON.stringify({ version: '1.0', claims: [BASE_CLAIM] }, null, 2));
  fs.writeFileSync(path.join(repo, 'interop', 'adapters', 'base.ts'), '// base adapter\n');
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'base');
  const baseSha = git(repo, 'rev-parse', 'HEAD').trim();
  git(repo, 'checkout', '-q', '-b', 'submission');
  mutate(repo);
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'submission');
  const subSha = git(repo, 'rev-parse', 'HEAD').trim();
  git(repo, 'checkout', '-q', 'master'); // back on base; working tree = base
  return { repo, baseSha, subSha };
}
function writeRegistry(repo, claims) {
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), JSON.stringify({ version: '1.0', claims }, null, 2));
}
function run(repo, args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: repo, encoding: 'utf8' });
}

test('happy path: new bolyra-suite claim + new adapter are materialized; prints id/kind/adapter', () => {
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/new.ts' };
  const { repo, subSha } = makeRepo((r) => {
    writeRegistry(r, [BASE_CLAIM, NEW]);
    fs.writeFileSync(path.join(r, 'interop', 'adapters', 'new.ts'), '// new adapter\n');
  });
  const r = run(repo, ['--ref', subSha, '--claim', 'new@2']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stdout, 'new@2\tbolyra-suite\tadapters/new.ts\n');
  assert.strictEqual(fs.readFileSync(path.join(repo, 'interop', 'adapters', 'new.ts'), 'utf8'), '// new adapter\n');
  assert.ok(fs.lstatSync(path.join(repo, 'interop', 'adapters', 'new.ts')).isFile());
  const reg = JSON.parse(fs.readFileSync(path.join(repo, 'interop', 'claims.json'), 'utf8'));
  assert.deepStrictEqual(reg.claims.map((c) => c.id), ['base@1', 'new@2']);
});

test('external-suite claim: registry overlaid, no adapter written', () => {
  const { repo, subSha } = makeRepo((r) => writeRegistry(r, [BASE_CLAIM, EXT_CLAIM]));
  const r = run(repo, ['--ref', subSha, '--claim', 'ext@1']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(r.stdout, 'ext@1\texternal-suite\t\n');
  assert.deepStrictEqual(fs.readdirSync(path.join(repo, 'interop', 'adapters')), ['base.ts']);
});

test('a symlink at the adapter path is rejected and nothing is written', () => {
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/new.ts' };
  const { repo, subSha } = makeRepo((r) => {
    writeRegistry(r, [BASE_CLAIM, NEW]);
    fs.symlinkSync('../../../../etc/passwd', path.join(r, 'interop', 'adapters', 'new.ts'));
  });
  const r = run(repo, ['--ref', subSha, '--claim', 'new@2']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /not a regular file \(mode 120000\)/);
  assert.ok(!fs.existsSync(path.join(repo, 'interop', 'adapters', 'new.ts')));
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(repo, 'interop', 'claims.json'), 'utf8')).claims.length, 1, 'registry untouched');
});

test('a symlink at interop/claims.json is rejected', () => {
  const { repo, subSha } = makeRepo((r) => {
    fs.unlinkSync(path.join(r, 'interop', 'claims.json'));
    fs.symlinkSync('/etc/hostname', path.join(r, 'interop', 'claims.json'));
  });
  const r = run(repo, ['--ref', subSha, '--claim', 'base@1']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /interop\/claims\.json.*not a regular file/);
});

test('replacing an EXISTING adapter is rejected', () => {
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/base.ts' };
  const { repo, subSha } = makeRepo((r) => {
    writeRegistry(r, [BASE_CLAIM, NEW]);
    fs.writeFileSync(path.join(r, 'interop', 'adapters', 'base.ts'), '// tampered\n');
  });
  const r = run(repo, ['--ref', subSha, '--claim', 'new@2']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /adapters\/base\.ts already exists/);
  assert.strictEqual(fs.readFileSync(path.join(repo, 'interop', 'adapters', 'base.ts'), 'utf8'), '// base adapter\n');
});

test('rejections: unknown claim, bad adapter pathname, unknown kind, non-commit ref, malformed JSON', () => {
  const { repo, subSha } = makeRepo((r) => writeRegistry(r, [BASE_CLAIM, { ...BASE_CLAIM, id: 'bad@3', adapter: 'adapters/../x.ts' }, { ...EXT_CLAIM, id: 'k@4', kind: 'mystery' }]));
  let r = run(repo, ['--ref', subSha, '--claim', 'nope']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /no claim with id nope/);
  r = run(repo, ['--ref', subSha, '--claim', 'bad@3']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /adapter pathname not allowed/);
  r = run(repo, ['--ref', subSha, '--claim', 'k@4']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /unknown kind mystery/);
  r = run(repo, ['--ref', 'f'.repeat(40), '--claim', 'base@1']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /not a commit/);
  r = run(repo, ['--ref', 'not-a-sha', '--claim', 'base@1']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /ref must be a full 40-hex/);
  const { repo: repo2, subSha: s2 } = makeRepo((r) => fs.writeFileSync(path.join(r, 'interop', 'claims.json'), '{not json'));
  r = run(repo2, ['--ref', s2, '--claim', 'base@1']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /claims\.json is not valid JSON/);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test interop/submission-overlay.test.js`
Expected: all 6 FAIL with `Cannot find module`/status `1` and `MODULE_NOT_FOUND` in stderr.

- [ ] **Step 3: Implement**

Create `interop/submission-overlay.js`:

```js
#!/usr/bin/env node
'use strict';
// Overlay ONE submission's registry + (for bolyra-suite) its ONE new adapter
// from a commit into the working tree, as git BLOBS — never a checkout, so a
// symlink or non-regular entry at either path is rejected rather than
// installed. Harness, runner, and every other adapter stay at the checked-out
// base. Used by .github/workflows/interop-replay.yml (spec §3.3 step 4, §3.5).
//   node interop/submission-overlay.js --ref <40-hex commit> --claim <id>
// Prints: id<TAB>kind<TAB>adapter on success (exit 0). Exit 1 on any refusal.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = process.cwd();
const REGISTRY = 'interop/claims.json';
const KINDS = new Set(['bolyra-suite', 'external-suite']);
const ADAPTER_RE = /^adapters\/[A-Za-z0-9._-]+\.ts$/;

function die(msg) { process.stderr.write(`submission-overlay: ${msg}\n`); process.exit(1); }
function git(...args) { return execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
function gitRaw(...args) { return execFileSync('git', ['-C', ROOT, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }); }

// `git ls-tree <ref> -- <path>` → { mode, type, sha } or null.
function treeEntry(ref, p) {
  const out = git('ls-tree', ref, '--', p).trim();
  if (!out) return null;
  const m = /^(\d{6}) (\w+) ([0-9a-f]{40})\t/.exec(out);
  return m ? { mode: m[1], type: m[2], sha: m[3] } : null;
}
function requireRegularBlob(ref, p) {
  const e = treeEntry(ref, p);
  if (!e) die(`${p} not present in ${ref}`);
  if (e.type !== 'blob' || e.mode !== '100644') die(`${p} in ${ref} is not a regular file (mode ${e.mode}, ${e.type})`);
  return e;
}

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const ref = opt('--ref');
const claimId = opt('--claim');
if (!ref || !/^[0-9a-f]{40}$/.test(ref)) die('ref must be a full 40-hex commit sha');
if (!claimId) die('--claim <id> is required');

let type;
try { type = git('cat-file', '-t', ref).trim(); } catch { type = ''; }
if (type !== 'commit') die(`${ref} is not a commit in this repository (fetch it first)`);

// 1. Registry blob (validated as a regular file), parsed as data.
requireRegularBlob(ref, REGISTRY);
const registryBytes = gitRaw('cat-file', '-p', `${ref}:${REGISTRY}`);
let reg;
try { reg = JSON.parse(registryBytes.toString('utf8')); } catch { die(`${REGISTRY} in ${ref}: claims.json is not valid JSON`); }
if (!reg || !Array.isArray(reg.claims)) die(`${REGISTRY} in ${ref}: registry.claims must be an array`);
const matches = reg.claims.filter((c) => c && c.id === claimId);
if (matches.length !== 1) die(matches.length ? `duplicate id ${claimId} in ${ref}` : `no claim with id ${claimId} in ${ref}`);
const c = matches[0];
const kind = c.kind === undefined ? 'bolyra-suite' : c.kind;
if (!KINDS.has(kind)) die(`unknown kind ${kind} (claim ${claimId})`);

// 2. Adapter (bolyra-suite only): pathname allowlist, regular blob, and never
//    a replacement of an adapter that already exists at the base.
let adapter = '';
let adapterBytes = null;
if (kind === 'bolyra-suite') {
  adapter = String(c.adapter || '');
  if (!ADAPTER_RE.test(adapter)) die(`adapter pathname not allowed: ${JSON.stringify(adapter)} (claim ${claimId})`);
  const rel = `interop/${adapter}`;
  if (fs.existsSync(path.join(ROOT, rel))) die(`${adapter} already exists at the base; submissions may only ADD an adapter`);
  requireRegularBlob(ref, rel);
  adapterBytes = gitRaw('cat-file', '-p', `${ref}:${rel}`);
}

// 3. Materialize as regular files (mode 0644), registry last.
if (adapterBytes) fs.writeFileSync(path.join(ROOT, 'interop', adapter), adapterBytes, { mode: 0o644 });
fs.writeFileSync(path.join(ROOT, REGISTRY), registryBytes, { mode: 0o644 });
process.stdout.write(`${claimId}\t${kind}\t${adapter}\n`);
```

- [ ] **Step 4: Run to verify they pass**

Run: `node --test interop/submission-overlay.test.js`
Expected: 6 pass, 0 fail. (If the `makeRepo` checkout of `master` fails because your git defaults to `main`, the test helper is wrong for your environment: change `'master'` to the branch name `git init` created, or set `git config --global init.defaultBranch master` for the test run. Report which you did.)

- [ ] **Step 5: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add interop/submission-overlay.js interop/submission-overlay.test.js
git commit -s -m "interop: submission-overlay.js — blob-based, symlink-safe overlay of one submission"
```

### Task 3: `interop/harness-integrity.js`

Snapshot the protected tree after the overlay; verify it is byte-identical after every claim (including failed ones). Detects a `bolyra-suite` run tampering with the harness before a later `external-suite` claim runs it on the VM.

**Files:**
- Create: `interop/harness-integrity.js`
- Test: `interop/harness-integrity.test.js`

- [ ] **Step 1: Write the failing tests**

Create `interop/harness-integrity.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, 'harness-integrity.js');
const GIT_ENV = { GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };
function git(cwd, ...a) { return execFileSync('git', ['-C', cwd, ...a], { encoding: 'utf8', env: { ...process.env, ...GIT_ENV } }); }

function makeRepo() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'integrity-'));
  git(repo, 'init', '-q');
  for (const d of ['interop/adapters', 'spec', 'landing', '.github/workflows', 'other']) fs.mkdirSync(path.join(repo, d), { recursive: true });
  fs.writeFileSync(path.join(repo, 'interop', 'replay.js'), '// harness\n');
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), '{"claims":[]}\n');
  fs.writeFileSync(path.join(repo, 'spec', 'runner.js'), '// runner\n');
  fs.writeFileSync(path.join(repo, 'landing', 'x.html'), '<x>\n');
  fs.writeFileSync(path.join(repo, '.github', 'workflows', 'w.yml'), 'on: x\n');
  fs.writeFileSync(path.join(repo, 'other', 'scratch.txt'), 'ok\n');
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'base');
  return repo;
}
function run(repo, ...args) { return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: repo, encoding: 'utf8' }); }
function snap(repo) { const f = path.join(os.tmpdir(), `snap-${process.pid}-${Math.random()}.json`); const r = run(repo, 'snapshot', f); assert.strictEqual(r.status, 0, r.stderr); return f; }

test('unchanged tree verifies', () => {
  const repo = makeRepo(); const f = snap(repo);
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 0, r.stderr);
});

test('overlaid (dirty) files are part of the baseline and verify as long as they stay identical', () => {
  const repo = makeRepo();
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), '{"claims":[1]}\n');      // like the overlay
  fs.writeFileSync(path.join(repo, 'interop', 'adapters', 'new.ts'), '// new\n');       // untracked, like a new adapter
  const f = snap(repo);
  assert.strictEqual(run(repo, 'verify', f).status, 0);
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), '{"claims":[2]}\n');      // tamper the overlaid file
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1); assert.match(r.stderr, /interop\/claims\.json/);
});

test('modifying a tracked harness file fails verify', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.writeFileSync(path.join(repo, 'interop', 'replay.js'), '// evil\n');
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1); assert.match(r.stderr, /interop\/replay\.js/);
});

test('adding an untracked file under a protected dir fails verify; outside protected dirs is ignored', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.writeFileSync(path.join(repo, 'other', 'more.txt'), 'x\n');
  assert.strictEqual(run(repo, 'verify', f).status, 0, 'outside protected dirs');
  fs.writeFileSync(path.join(repo, 'spec', 'sneaky.js'), 'x\n');
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1); assert.match(r.stderr, /spec\/sneaky\.js/);
});

test('replacing a file with a symlink fails verify', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.unlinkSync(path.join(repo, 'spec', 'runner.js'));
  fs.symlinkSync('/etc/hostname', path.join(repo, 'spec', 'runner.js'));
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1); assert.match(r.stderr, /spec\/runner\.js/);
});

test('deleting a tracked file fails verify', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.unlinkSync(path.join(repo, '.github', 'workflows', 'w.yml'));
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1); assert.match(r.stderr, /\.github\/workflows\/w\.yml/);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test interop/harness-integrity.test.js`
Expected: 6 FAIL (`MODULE_NOT_FOUND`).

- [ ] **Step 3: Implement**

Create `interop/harness-integrity.js`:

```js
#!/usr/bin/env node
'use strict';
// Snapshot/verify the protected tree so that a replay of one claim cannot
// alter what a later claim executes (spec §3.5). The baseline is taken AFTER
// the submission overlay, so overlaid files are part of it; anything that
// differs afterwards — content, mode/type, additions, deletions — fails.
//   node interop/harness-integrity.js snapshot <file.json>
//   node interop/harness-integrity.js verify   <file.json>
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = process.cwd();
const PROTECTED = ['interop', 'spec', 'landing', '.github'];

function die(msg) { process.stderr.write(`harness-integrity: ${msg}\n`); process.exit(1); }
function git(...a) { return execFileSync('git', ['-C', ROOT, ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }

// Every path git knows about under the protected dirs (tracked, modified,
// deleted, untracked) — status covers deviations, ls-files covers the rest.
function protectedPaths() {
  const set = new Set();
  for (const line of git('ls-files', '-z', '--', ...PROTECTED).split('\0')) if (line) set.add(line);
  for (const line of git('status', '--porcelain=v1', '-z', '--untracked-files=all', '--', ...PROTECTED).split('\0')) {
    if (line.length > 3) set.add(line.slice(3));
  }
  return [...set].sort();
}
function fingerprint(rel) {
  const abs = path.join(ROOT, rel);
  let st;
  try { st = fs.lstatSync(abs); } catch { return 'absent'; }
  if (st.isSymbolicLink()) return `symlink:${fs.readlinkSync(abs)}`;
  if (!st.isFile()) return `other:${st.mode.toString(8)}`;
  const h = crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
  return `file:${(st.mode & 0o111) ? 'x' : '-'}:${h}`;
}
function snapshot() { const out = {}; for (const p of protectedPaths()) out[p] = fingerprint(p); return out; }

const [cmd, file] = process.argv.slice(2);
if (!file || !['snapshot', 'verify'].includes(cmd)) die('usage: snapshot|verify <file.json>');
if (cmd === 'snapshot') {
  fs.writeFileSync(file, JSON.stringify(snapshot(), null, 1));
  console.log(`harness-integrity: snapshot of ${Object.keys(JSON.parse(fs.readFileSync(file, 'utf8'))).length} protected paths → ${file}`);
} else {
  const base = JSON.parse(fs.readFileSync(file, 'utf8'));
  const now = snapshot();
  const diffs = [];
  for (const p of new Set([...Object.keys(base), ...Object.keys(now)])) {
    if (base[p] !== now[p]) diffs.push(`${p}: ${base[p] || 'absent'} -> ${now[p] || 'absent'}`);
  }
  if (diffs.length) die(`protected tree changed:\n  ${diffs.join('\n  ')}`);
  console.log('harness-integrity: OK');
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `node --test interop/harness-integrity.test.js`
Expected: 6 pass, 0 fail.

- [ ] **Step 5: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add interop/harness-integrity.js interop/harness-integrity.test.js
git commit -s -m "interop: harness-integrity.js — snapshot/verify the protected tree between claims"
```

---

## Chunk 2: Dispatch workflow and its CI proofs

### Task 4: Pin the container image digest (verification-only task)

**Files:** none. Produces the digest Task 5 writes.

- [ ] **Step 1: Reuse the digest the registry already pins, after checking it is the full image**

`interop/claims.json` already pins `node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5` for the StillOS run. Check it has `git` (the full Debian image does; slim/alpine do not):
```bash
docker run --rm node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5 sh -c 'git --version && node --version'
```
Expected: `git version 2.x.y` and `v20.x.y`. If `git` is missing, instead run `docker pull node:20 && docker image inspect node:20 --format '{{index .RepoDigests 0}}'`, re-check with the same command, and use that digest. Write the chosen digest into `$RUNNER_HANDOFF` for Task 5:
```bash
echo "REPLAY_IMAGE=node:20@sha256:<the 64-hex you verified>" >> "${RUNNER_HANDOFF:-/tmp/plan-handoff.env}"; cat "${RUNNER_HANDOFF:-/tmp/plan-handoff.env}"
```

### Task 5: Rewrite `.github/workflows/interop-replay.yml`

**Files:**
- Modify: `.github/workflows/interop-replay.yml` (whole file)

- [ ] **Step 1: Behavioral checks that must pass after the rewrite (write them down before editing)**

These are the acceptance checks for the workflow; they are executed in Task 6 (in CI) because a workflow cannot run locally. Copy this list into `$RUNNER_HANDOFF` as `WORKFLOW_ACCEPTANCE` so Task 6 can tick each:
1. Dispatch with no inputs on the feature branch → `2/2 claims reproduced`, job green; mcp-use ran inside `docker run`, StillOS under `env -i`.
2. Dispatch with `ref` set and `claim` empty → job fails fast: `ref requires claim`.
3. Dispatch with `ref`=submission commit, `claim`=its new bolyra-suite id → overlay step prints `id<TAB>bolyra-suite<TAB>adapters/<name>.ts`, `--check` passes, exactly one claim replays.
4. Probe adapter (Task 6) → its job is red with `PROBE_ENV=NONE` and `PROBE_WRITE=EROFS` in the mismatch reason; the integrity check after it passes; the following claims still run.
5. Unknown `claim` → job fails on the plan step: `no claim with id`.
6. Wrong kind cannot reach the host branch: the `case` has a failing default (reviewed by reading the YAML).

- [ ] **Step 2: Replace the workflow file**

Write `.github/workflows/interop-replay.yml` exactly as below, substituting `REPLAY_IMAGE` from the handoff:

```yaml
name: Interop replay

# Mechanically re-verify published external interop claims at their pins
# (interop/claims.json). Manual dispatch only: this executes third-party
# code (pinned, --ignore-scripts) and needs network access to external repos.
#
# Trust model (spec docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md §3.3 step 4, §3.5):
#   * The harness is the commit this workflow file came from (github.sha).
#     Production dispatches use --ref main; the job prints the ref it ran
#     from. A submission's data is OVERLAID from `ref` as git blobs (never a
#     checkout); harness, runner, and every other adapter stay at github.sha.
#   * bolyra-suite  -> replay.js runs INSIDE a container: workspace mounted
#     READ-ONLY, scratch on a tmpfs, no runner environment.
#   * external-suite-> replay.js runs on the VM under env -i (it must drive
#     the host docker CLI); the implementer's code runs only inside
#     replay.js's own `docker run --network none` child.
#   * The protected tree is fingerprinted after the overlay and re-verified
#     after EVERY claim, so one claim cannot alter what a later one executes.
#   Runner tokens (GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN) are never visible to
#   third-party code. workflow_dispatch retains cache WRITE access, which is
#   why this matters even with cache-mode none.
on:
  workflow_dispatch:
    inputs:
      ref:
        description: 'Full 40-hex commit SHA to overlay interop/claims.json (+ one new adapter) FROM. Requires `claim`. Empty = registry as committed at the harness commit.'
        required: false
        default: ''
      claim:
        description: 'Claim id to replay. Required when `ref` is set. Empty = all claims.'
        required: false
        default: ''

# Third-party code executes in this job; give it nothing to steal.
permissions:
  contents: read

env:
  # Full Debian node:20 (NOT slim/alpine: git is required). Re-pin by digest only.
  REPLAY_IMAGE: node:20@sha256:<digest>
  REF: ${{ inputs.ref }}
  CLAIM: ${{ inputs.claim }}

jobs:
  replay:
    name: Replay published interop claims
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          # The harness is exactly the commit this workflow came from.
          ref: ${{ github.sha }}
          # git archive/show at historical suite pins needs full history
          fetch-depth: 0
          # do not leave the checkout token on disk where implementer
          # lifecycle code could read it
          persist-credentials: false

      - uses: actions/setup-node@v7
        with:
          node-version: 20
          package-manager-cache: false

      - name: Harness provenance
        run: |
          echo "harness commit: ${{ github.sha }} (ref ${{ github.ref_name }})"
          if [ "${{ github.ref_name }}" != "main" ]; then echo "::warning::harness is not main — acceptable for pre-merge proofs only"; fi

      - name: Overlay submission (data only)
        if: env.REF != ''
        run: |
          set -euo pipefail
          [ -n "$CLAIM" ] || { echo "::error::ref requires claim (a submission is exactly one claim)"; exit 1; }
          git fetch -q origin "$REF" || git fetch -q origin "+refs/pull/*/head:refs/remotes/origin/pr/*"
          node interop/submission-overlay.js --ref "$REF" --claim "$CLAIM" | tee "$RUNNER_TEMP/overlay.tsv"
          echo "overlaid:"; git status --porcelain -- interop

      - name: Offline registry + pin check (base code only)
        run: node interop/replay.js --check

      - name: Select claims
        run: |
          set -euo pipefail
          if [ -n "$CLAIM" ]; then node interop/replay.js --list --claim "$CLAIM" > "$RUNNER_TEMP/plan.tsv"
          else node interop/replay.js --list > "$RUNNER_TEMP/plan.tsv"; fi
          [ -s "$RUNNER_TEMP/plan.tsv" ] || { echo "::error::no claims selected"; exit 1; }
          echo "selected:"; cat "$RUNNER_TEMP/plan.tsv"

      - name: Snapshot protected tree (baseline includes the overlay)
        run: node interop/harness-integrity.js snapshot "$RUNNER_TEMP/integrity.json"

      - name: Replay claims under per-kind isolation
        run: |
          set -euo pipefail
          failed=0; total=0
          while IFS=$'\t' read -r id kind adapter; do
            total=$((total+1))
            echo "::group::replay $id ($kind)"
            case "$kind" in
              bolyra-suite)
                docker run --rm \
                  --user "$(id -u):$(id -g)" -e HOME=/tmp -e CLAIM_ID="$id" \
                  -v "$PWD:/work:ro" --tmpfs /tmp:rw,exec -w /work \
                  "$REPLAY_IMAGE" sh -c 'node interop/replay.js --claim "$CLAIM_ID"' </dev/null \
                  || failed=$((failed+1)) ;;
              external-suite)
                env -i PATH="$PATH" HOME="$HOME" CLAIM_ID="$id" \
                  node interop/replay.js --claim "$id" </dev/null \
                  || failed=$((failed+1)) ;;
              *) echo "::error::unknown kind '$kind' for $id"; exit 1 ;;
            esac
            echo "::endgroup::"
            node interop/harness-integrity.js verify "$RUNNER_TEMP/integrity.json"
          done < "$RUNNER_TEMP/plan.tsv"
          echo "$((total-failed))/$total claims reproduced"
          [ "$failed" -eq 0 ]
```

- [ ] **Step 3: Syntax check, then a local isolation probe in a STANDALONE clone**

Run: `ruby -ryaml -e 'YAML.load_file(".github/workflows/interop-replay.yml"); puts "yaml ok"'`
Expected: `yaml ok`.

The worktree's `.git` is a file; make a real clone for the container probe:
```bash
PROBE=$(mktemp -d) && git clone -q --no-local . "$PROBE/repo" && cd "$PROBE/repo" && git fetch -q origin 37b3fa631bcf50c1190474ca938b1846115a282a || true
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CLAIM_ID=probe \
  -v "$PWD:/work:ro" --tmpfs /tmp:rw,exec -w /work "node:20@sha256:<digest>" sh -c '
    echo "--- env names ---"; env | cut -d= -f1 | sort | tr "\n" " "; echo
    echo "--- write test ---"; (echo x > /work/interop/replay.js) 2>&1 | head -1 || true
    echo "--- tmpfs ---"; touch /tmp/ok && echo tmpfs-ok
    echo "--- git reads ---"; git -C /work rev-parse --short HEAD; git -C /work archive HEAD spec | tar -t | head -1
    echo "--- npm cache ---"; npm config get cache'
cd - >/dev/null
```
Expected: env names are only `CLAIM_ID HOME HOSTNAME NODE_VERSION PATH PWD YARN_VERSION` (no `GITHUB_*`, no `ACTIONS_*`, no `RUNNER_*`); write test prints `sh: 1: cannot create /work/interop/replay.js: Read-only file system`; `tmpfs-ok`; a short SHA and `spec/`; `/tmp/.npm`.

And the scrubbed-env shape: `env -i PATH="$PATH" HOME="$HOME" CLAIM_ID=probe node -e 'console.log(Object.keys(process.env).sort().join(" "))'` → `CLAIM_ID HOME PATH`.

- [ ] **Step 4: Commit and push**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add .github/workflows/interop-replay.yml
git commit -s -m "ci(interop-replay): ref/claim inputs; blob overlay; per-kind isolation; integrity check between claims

bolyra-suite replays run inside a read-only-mounted node:20 container with
a tmpfs scratch and no runner environment; external-suite replays run on
the VM under env -i (replay.js must drive the host docker CLI; the
implementer's code already runs only in replay.js's --network none child).
Closes a pre-existing exposure: workflow_dispatch retains cache-write
access and runner tokens were readable by third-party code."
git push -u origin public-conformance-claims
```

### Task 6: CI proofs (acceptance checks 1–5 from Task 5 Step 1)

**Files:** none merged. Two throwaway branches: `probe/isolation`, `probe/overlay`. Evidence goes into `$RUNNER_HANDOFF` as `PROOF_URLS` and later into the PR body.

Helper to identify a dispatched run unambiguously (define once in your shell; reuse):
```bash
dispatch_and_wait() { # $1=branch  $2..=extra -f inputs   → prints RUN_ID, waits, prints conclusion
  local branch="$1"; shift
  local ts head; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ); head=$(git rev-parse "origin/$branch")
  gh workflow run interop-replay.yml --repo bolyra/bolyra --ref "$branch" "$@"
  sleep 20
  RUN_ID=$(gh run list --repo bolyra/bolyra --workflow interop-replay.yml --branch "$branch" --json databaseId,createdAt,headSha \
    --jq "[.[] | select(.createdAt >= \"$ts\" and .headSha == \"$head\")] | if length == 1 then .[0].databaseId else error(\"expected exactly one run, got \" + (length|tostring)) end")
  echo "RUN_ID=$RUN_ID  https://github.com/bolyra/bolyra/actions/runs/$RUN_ID"
  gh run watch "$RUN_ID" --repo bolyra/bolyra --exit-status >/dev/null && echo "conclusion=success" || echo "conclusion=failure"
}
```

- [ ] **Step 1: Check 1 — baseline replay on the feature branch (no inputs)**

Run: `dispatch_and_wait public-conformance-claims`
Expected: `conclusion=success`. In the log (`gh run view $RUN_ID --repo bolyra/bolyra --log | grep -E "replay .* \((bolyra|external)-suite\)|claims reproduced|harness-integrity"`): `replay mcp-use-evc-example@17642a5/host_behavior@0.5.0 (bolyra-suite)`, `replay x402-authority-verifier-kit@35e209d/own-corpus (external-suite)`, two `harness-integrity: OK`, `2/2 claims reproduced`. Save the URL as `PROOF_BASELINE`.

- [ ] **Step 2: Check 2 — `ref` without `claim` fails fast**

Run: `dispatch_and_wait public-conformance-claims -f ref=$(git rev-parse origin/public-conformance-claims)`
Expected: `conclusion=failure`; log contains `ref requires claim`. Save as `PROOF_REF_REQUIRES_CLAIM`.

- [ ] **Step 3: Build the `probe/isolation` branch (checks 4 and the external-suite env proof)**

```bash
git checkout -q -b probe/isolation origin/public-conformance-claims
# bolyra-suite probe adapter: prints runner-env NAMES, tries to write the harness, exits 1 so the
# runner surfaces its stderr (a green host's stderr is discarded; a failing host's first 200 chars are kept).
cat > interop/adapters/probe-env.ts <<'EOF'
const leaked = Object.keys(process.env).filter((k) => /^(GITHUB_|ACTIONS_|RUNNER_)/.test(k));
process.stderr.write(`PROBE_ENV=${leaked.length ? leaked.join(',') : 'NONE'}\n`);
try { require('node:fs').writeFileSync('/work/interop/replay.js', 'x'); process.stderr.write('PROBE_WRITE=WRITABLE\n'); }
catch (e: any) { process.stderr.write(`PROBE_WRITE=${e.code}\n`); }
process.exit(1);
EOF
SHA=$(shasum -a 256 interop/adapters/probe-env.ts | cut -d' ' -f1)
# Insert the probe claim FIRST (mixed-kind proof: probe, then mcp-use, then StillOS), and an external-suite env probe LAST.
node - "$SHA" <<'EOF'
const fs = require('fs'); const sha = process.argv[2];
const reg = JSON.parse(fs.readFileSync('interop/claims.json', 'utf8'));
const mcp = reg.claims.find((c) => c.id.startsWith('mcp-use-evc-example@'));
const still = reg.claims.find((c) => c.kind === 'external-suite');
const probe = { ...mcp, id: 'probe-env@17642a5/host_behavior@0.5.0', adapter: 'adapters/probe-env.ts', adapter_sha256: sha, claim_text: 'PROBE: isolation proof, must be red', verified_on: '2026-09-10' };
const probeExt = { ...still, id: 'probe-ext@35e209d/env', claim_text: 'PROBE: external-suite env names, must be red (no summary line)', verified_on: '2026-09-10',
  run: { ...still.run, command: ['sh', '-c', 'env | cut -d= -f1 | sort'] } };
reg.claims = [probe, ...reg.claims, probeExt];
fs.writeFileSync('interop/claims.json', JSON.stringify(reg, null, 2) + '\n');
EOF
node interop/replay.js --check   # expect: probe rows OK (adapter exists, digest matches)
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add -A && git commit -s -q -m "probe: isolation proofs (never merge)" && git push -q -u origin probe/isolation
dispatch_and_wait probe/isolation
```
Expected: `conclusion=failure` (the two probes are designed red). In the log: for the probe claim a `REPLAY MISMATCH` reason containing `stderr="PROBE_ENV=NONE\nPROBE_WRITE=EROFS\n"`; immediately after it `harness-integrity: OK`; then mcp-use and StillOS both reproduce; for `probe-ext` the error `no machine-readable summary line in suite stdout; tail:` followed by env NAMES containing none of `GITHUB_`, `ACTIONS_`, `RUNNER_`; final line `2/4 claims reproduced`. Save as `PROOF_ISOLATION`.

- [ ] **Step 4: Check 3 — overlay path (`probe/overlay` off `probe/isolation`)**

```bash
git checkout -q -b probe/overlay
cp interop/adapters/mcp-use-evc-example-hut.ts interop/adapters/probe-overlay.ts
SHA=$(shasum -a 256 interop/adapters/probe-overlay.ts | cut -d' ' -f1)
node - "$SHA" <<'EOF'
const fs = require('fs'); const sha = process.argv[2];
const reg = JSON.parse(fs.readFileSync('interop/claims.json', 'utf8'));
const mcp = reg.claims.find((c) => c.id.startsWith('mcp-use-evc-example@'));
reg.claims.push({ ...mcp, id: 'probe-overlay@17642a5/host_behavior@0.5.0', adapter: 'adapters/probe-overlay.ts', adapter_sha256: sha, claim_text: 'PROBE: overlay path', verified_on: '2026-09-10' });
fs.writeFileSync('interop/claims.json', JSON.stringify(reg, null, 2) + '\n');
EOF
git add -A && git commit -s -q -m "probe: overlay submission (never merge)" && git push -q -u origin probe/overlay
OVERLAY_SHA=$(git rev-parse HEAD)
git checkout -q probe/isolation
dispatch_and_wait probe/isolation -f ref="$OVERLAY_SHA" -f claim="probe-overlay@17642a5/host_behavior@0.5.0"
```
Expected: `conclusion=success`; log shows the overlay step printing `probe-overlay@17642a5/host_behavior@0.5.0<TAB>bolyra-suite<TAB>adapters/probe-overlay.ts`, `--check` OK, `selected:` with exactly that one row, one `docker run` replay, `harness-integrity: OK`, `1/1 claims reproduced`. Save as `PROOF_OVERLAY`.

- [ ] **Step 5: Check 5 — unknown claim**

Run: `dispatch_and_wait probe/isolation -f claim=does-not-exist`
Expected: `conclusion=failure`; log: `no claim with id does-not-exist` in the "Select claims" step. Save as `PROOF_UNKNOWN_CLAIM`.

- [ ] **Step 6: Clean up and hand off**

```bash
git checkout -q public-conformance-claims
git push -q origin --delete probe/isolation probe/overlay
git branch -q -D probe/isolation probe/overlay
echo "PROOF_URLS: baseline=$PROOF_BASELINE ref_requires_claim=$PROOF_REF_REQUIRES_CLAIM isolation=$PROOF_ISOLATION overlay=$PROOF_OVERLAY unknown=$PROOF_UNKNOWN_CLAIM" >> "${RUNNER_HANDOFF:-/tmp/plan-handoff.env}"
```
Expected: both remote branches deleted; five URLs recorded.

---

## Chunk 3: Generator, page, CI drift guard

### Task 7: `landing/gen-conformance.js` — validation

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
    claim_text: "39/39 of the kit's own pinned corpus (NOT Bolyra-suite conformance)",
    verified_on: '2026-09-09',
    implementer: { repo: 'https://github.com/example/kit', commit: 'a'.repeat(40) },
    run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['npm', 'test', '--silent'], network: 'none', expect: { pass: 39, run: 39, scoped_out: 9 } },
    ...overrides,
  };
}
const has = (errs, re) => errs.some((e) => re.test(e));

test('valid external-suite registry passes', () => {
  assert.deepStrictEqual(validateRegistry({ claims: [ext()] }), []);
});
test('registry-level shape errors', () => {
  assert.deepStrictEqual(validateRegistry(null), ['registry.claims must be an array']);
  assert.deepStrictEqual(validateRegistry({ claims: 'x' }), ['registry.claims must be an array']);
});
test('non-object and malformed entries are rejected without throwing', () => {
  assert.ok(has(validateRegistry({ claims: [null] }), /claim #0: not an object/));
  assert.ok(has(validateRegistry({ claims: ['str'] }), /claim #0: not an object/));
  assert.ok(has(validateRegistry({ claims: [ext({ id: 42 })] }), /id must be a non-empty string/));
  assert.ok(has(validateRegistry({ claims: [ext({ claim_text: 7 })] }), /claim_text must be a non-empty string/));
  assert.ok(has(validateRegistry({ claims: [ext({ verified_on: 20260909 })] }), /verified_on must be YYYY-MM-DD/));
  assert.ok(has(validateRegistry({ claims: [ext({ verified_on: 'yesterday' })] }), /verified_on must be YYYY-MM-DD/));
});
test('kind: absent defaults; supplied invalid (incl. falsy) is rejected', () => {
  assert.ok(has(validateRegistry({ claims: [ext({ kind: 'mystery' })] }), /unknown kind mystery/));
  assert.ok(has(validateRegistry({ claims: [ext({ kind: '' })] }), /unknown kind/));
  assert.ok(has(validateRegistry({ claims: [ext({ kind: null })] }), /unknown kind/));
});
test('duplicate ids are rejected', () => {
  assert.ok(has(validateRegistry({ claims: [ext(), ext()] }), /duplicate id kit@abc\/own-corpus/));
});
test('implementer.repo must be https://github.com/<owner>/<repo> with no dot segments', () => {
  for (const repo of ['javascript:alert(1)', 'https://evil.example/x/y', 'https://github.com/only-owner', 'http://github.com/a/b',
                      'https://github.com/./b', 'https://github.com/a/..', 'https://github.com/a/b/c', 'https://github.com/a/b?x=1']) {
    assert.ok(has(validateRegistry({ claims: [ext({ implementer: { repo, commit: 'a'.repeat(40) } })] }), /implementer\.repo/), `should reject ${repo}`);
  }
  assert.ok(has(validateRegistry({ claims: [ext({ implementer: { repo: 'https://github.com/a/b', commit: 'zz' } })] }), /implementer\.commit/));
});
test('verification_run_url is rejected in v1', () => {
  assert.ok(has(validateRegistry({ claims: [ext({ verification_run_url: 'https://github.com/bolyra/bolyra/actions/runs/1' })] }), /verification_run_url/));
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
const REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const SHA40 = /^[0-9a-f]{40}$/;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const isStr = (v) => typeof v === 'string' && v.length > 0;

function validateRegistry(reg) {
  if (!reg || !Array.isArray(reg.claims)) return ['registry.claims must be an array'];
  const errors = [];
  const seen = new Set();
  reg.claims.forEach((c, i) => {
    if (!c || typeof c !== 'object' || Array.isArray(c)) { errors.push(`claim #${i}: not an object`); return; }
    const id = isStr(c.id) ? c.id : `#${i}`;
    if (!isStr(c.id)) errors.push(`${id}: id must be a non-empty string`);
    else if (seen.has(c.id)) errors.push(`${id}: duplicate id ${c.id}`);
    seen.add(c.id);
    const kind = c.kind === undefined ? 'bolyra-suite' : c.kind;
    if (!KINDS.has(kind)) errors.push(`${id}: unknown kind ${String(kind)}`);
    const impl = c.implementer && typeof c.implementer === 'object' ? c.implementer : {};
    const m = isStr(impl.repo) ? REPO_RE.exec(impl.repo) : null;
    if (!m || m[1] === '.' || m[1] === '..' || m[2] === '.' || m[2] === '..') errors.push(`${id}: implementer.repo must match https://github.com/<owner>/<repo>`);
    if (!isStr(impl.commit) || !SHA40.test(impl.commit)) errors.push(`${id}: implementer.commit must be a full 40-hex sha`);
    if ('verification_run_url' in c) errors.push(`${id}: verification_run_url is not rendered in v1; remove it`);
    if (!isStr(c.verified_on) || !DATE_RE.test(c.verified_on)) errors.push(`${id}: verified_on must be YYYY-MM-DD`);
    if (!isStr(c.claim_text)) errors.push(`${id}: claim_text must be a non-empty string`);
    if (c.scope !== undefined && typeof c.scope !== 'string') errors.push(`${id}: scope must be a string when present`);
    if (KINDS.has(kind) && isStr(c.id)) for (const e of validateClaim(c)) errors.push(`${id}: ${e}`);
  });
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
Expected: 7 pass. (`renderRegistry`, `checkFile`, `coveredClasses` are `undefined` — nothing calls them yet.)

- [ ] **Step 5: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add landing/gen-conformance.js landing/gen-conformance.test.js
git commit -s -m "landing: conformance generator — strict registry validation"
```

### Task 8: `gen-conformance.js` — rendering, drift check, CLI

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
test('render is deterministic and ordered by verified_on desc then id (code-unit order)', () => {
  const reg = { claims: [
    ext({ id: 'b', verified_on: '2026-01-01' }), ext({ id: 'a', verified_on: '2026-01-01' }),
    ext({ id: 'c', verified_on: '2026-02-01' }), ext({ id: 'Z', verified_on: '2026-01-01' }), ext({ id: 'é', verified_on: '2026-01-01' }),
  ] };
  const html1 = renderRegistry(reg);
  const html2 = renderRegistry({ claims: [...reg.claims].reverse() });
  assert.strictEqual(html1, html2);
  const pos = (id) => html1.indexOf(`<h2 class="claim-id">${id}</h2>`);
  // 'Z' (0x5A) < 'a' (0x61) < 'b' < 'é' (0xE9): code-unit order, not locale order
  assert.ok(pos('c') < pos('Z') && pos('Z') < pos('a') && pos('a') < pos('b') && pos('b') < pos('é'));
  assert.ok(!/generated (at|on)/i.test(html1), 'no generation timestamp');
});
test('render throws on an invalid registry', () => {
  assert.throws(() => renderRegistry({ claims: [ext({ kind: 'mystery' })] }), /unknown kind/);
});
test('the real registry renders: bolyra-suite row has covered classes and suite-commit link', () => {
  const reg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'interop', 'claims.json'), 'utf8'));
  const html = renderRegistry(reg);
  assert.ok(html.includes('<th>Covered classes</th><td>host_behavior</td>'));
  assert.ok(/href="https:\/\/github\.com\/bolyra\/bolyra\/commit\/[0-9a-f]{40}"/.test(html));
  assert.ok(html.includes('This is NOT Bolyra-suite conformance.'), 'StillOS row qualifier');
});
test('checkFile: identical passes, one-byte drift fails naming the line, missing file fails', () => {
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
Expected: the 8 new tests FAIL (`coveredClasses is not a function` / `renderRegistry is not a function`).

- [ ] **Step 3: Implement rendering, checkFile, CLI**

Replace the `module.exports` line and the `require.main` block at the bottom of `landing/gen-conformance.js` with:

```js
function coveredClasses(c) {
  if ((c.kind === undefined ? 'bolyra-suite' : c.kind) === 'external-suite') return 'not applicable (own corpus)';
  const args = (c.suite && Array.isArray(c.suite.runner_args)) ? c.suite.runner_args : [];
  const types = [];
  for (let i = 0; i + 1 < args.length; i++) if (args[i] === '--type') types.push(args[i + 1]);
  return types.length ? types.join(', ') : 'Not specified';
}

const EXTERNAL_QUALIFIER =
  "Own-corpus reproduction: the implementer's published numbers reproduce at the pin. This is NOT Bolyra-suite conformance.";

// Code-unit comparisons: identical output on every machine and in CI.
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
function sortClaims(claims) {
  return [...claims].sort((a, b) => cmp(b.verified_on, a.verified_on) || cmp(a.id, b.id));
}

function renderClaim(c) {
  const kind = c.kind === undefined ? 'bolyra-suite' : c.kind;
  const repo = c.implementer.repo;      // validated by REPO_RE
  const commit = c.implementer.commit;  // validated 40-hex
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
(The third link, `IMPLEMENTER.md`, is intentional and in addition to the two the spec names.)

- [ ] **Step 4: Run all generator tests**

Run: `node --test landing/gen-conformance.test.js`
Expected: 15 pass.

- [ ] **Step 5: Generate the real page, run the drift check, and its negative control**

```bash
node landing/gen-conformance.js && node landing/gen-conformance.js --check
sed -i.bak 's/Recorded verification date/Recorded verification dat/' landing/conformance.html && node landing/gen-conformance.js --check; echo "exit=$?"; mv landing/conformance.html.bak landing/conformance.html && node landing/gen-conformance.js --check
```
Expected: `wrote landing/conformance.html (2 claims)`, `--check OK`; then `--check FAILED` with `line N:` blocks and `exit=1`; then `--check OK` again.

- [ ] **Step 6: Commit (generator + generated page together)**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add landing/gen-conformance.js landing/gen-conformance.test.js landing/conformance.html
git commit -s -m "landing: conformance page generator, drift check, first generated page (2 claims)"
```

### Task 9: CI — offline pin check, new script tests, drift guard

**Files:**
- Modify: `.github/workflows/ci.yml` (the `evc-conformance` job only)

- [ ] **Step 1: Confirm the anchors, then edit**

Run: `grep -n "^  evc-conformance:\|Interop replay harness — offline regression tests" .github/workflows/ci.yml`
Expected: two lines (job header; the final step's `name:`), the second inside that job.

(a) In the `evc-conformance` job, replace its checkout step
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
(b) Replace the final step of that job
```yaml
      - name: Interop replay harness — offline regression tests
        run: node --test interop/replay.test.js
```
with
```yaml
      - name: Interop replay harness + dispatch building blocks — offline tests
        run: node --test interop/replay.test.js interop/submission-overlay.test.js interop/harness-integrity.test.js

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

- [ ] **Step 2: Validate and run the same commands locally**

Run: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); puts "yaml ok"' && node --test interop/replay.test.js interop/submission-overlay.test.js interop/harness-integrity.test.js && node interop/replay.js --check && node --test landing/gen-conformance.test.js && node landing/gen-conformance.js --check`
Expected: `yaml ok`; 36 tests pass (24 + 6 + 6); registry OK lines; 15 pass; `--check OK`.

- [ ] **Step 3: Commit, push, open the draft PR, watch CI**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add .github/workflows/ci.yml
git commit -s -m "ci: offline interop pin check, dispatch building-block tests, conformance page drift guard"
git push
gh pr create --repo bolyra/bolyra --base main --head public-conformance-claims --draft \
  --title "Public conformance claims (v1): page, generator, dispatch isolation, landing copy" \
  --body "Implements docs/superpowers/specs/2026-09-10-public-conformance-claims-design.md (v1 scope). Draft until Chunk 4 lands."
gh pr checks --repo bolyra/bolyra --watch
```
Expected: all checks green, including `EVC conformance — package sync & both reference hosts`.

---

## Chunk 4: Landing copy, deploy/verify, submission docs, end-to-end

### Task 10: `landing/index.html` copy changes (spec §3.4)

Line numbers are as of `f106b00`; confirm with `grep -n` first — the text is what matters.

**Files:**
- Modify: `landing/index.html`

- [ ] **Step 1: Baseline assertions (must hold BEFORE editing)**

```bash
grep -c "hosted verifier preview" landing/index.html                    # expect 2
grep -c "Hosted <code>POST /v1/verify</code> preview" landing/index.html # expect 1
grep -c "managed verifier path" landing/index.html                       # expect 1
grep -c "Managed operations when you need them" landing/index.html       # expect 1
grep -c "@bolyra/evc-conformance@0.5.0" landing/index.html               # expect 1
grep -c "40 wire-contract vectors" landing/index.html                    # expect 1
grep -c "10 domain-agnostic wire-envelope vectors" landing/index.html    # expect 1
grep -c 'href="/conformance"' landing/index.html                         # expect 0
```
(`grep -c` exits 1 when the count is 0; that is fine interactively — do not run these under `set -e`.)

- [ ] **Step 2: Lines 947–948 — the "Hosted or self-hosted" card** (heading rename is beyond the spec's literal list; it is intentional so the card stops promising a hosted option)

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

- [ ] **Step 3: Line 953 — the boundary paragraph**

Replace
```
Pilot against Bolyra's hosted verifier preview today, then keep the same boundary if you self-host or swap verifier implementations later. Bolyra maintains the spec, conformance vectors, reference hosts, and managed verifier path.
```
with
```
Run the published conformance suite, explore the reference implementations, or verify locally with <code>bolyra verify</code>. Bolyra maintains the spec, conformance vectors, and reference hosts.
```

- [ ] **Step 4: Line 954 — delete the whole line**

```html
        <p style="color: var(--cyan); margin: 14px 0 0; font-weight: 600;">Open contract. Managed operations when you need them.</p>
```

- [ ] **Step 5: Line 955 — count + link**

Replace `and 10 domain-agnostic wire-envelope vectors` with `and 11 domain-agnostic wire-envelope vectors`.
Replace `It is also listed in &sect;9 with the author's explicit permission:` with `It is also listed in &sect;9 with the author's explicit permission. Every published claim, with its pins, is on <a href="/conformance">the conformance page</a>:`.

- [ ] **Step 6: Line 1031 — package row**

Replace `<code>@bolyra/evc-conformance@0.5.0</code>` with `<code>@bolyra/evc-conformance@0.6.0</code>`; replace `40 wire-contract vectors` with `41 wire-contract vectors`; delete ` Hosted <code>POST /v1/verify</code> preview for design partners, same External Verifier Contract.` (including the leading space).

- [ ] **Step 7: Navigation** — after line 753 `<li><a href="/playground">Playground</a></li>` add `<li><a href="/conformance">Conformance</a></li>`; same after the footer's `<li><a href="/playground">Playground</a></li>` (line 1196).

- [ ] **Step 8: Post-edit assertions (all must hold)**

```bash
grep -c "hosted verifier preview" landing/index.html                    # expect 0
grep -c "Hosted <code>POST /v1/verify</code> preview" landing/index.html # expect 0
grep -c "managed verifier path" landing/index.html                       # expect 0
grep -c "Managed operations when you need them" landing/index.html       # expect 0
grep -c "@bolyra/evc-conformance@0.6.0" landing/index.html               # expect 1
grep -c "41 wire-contract vectors" landing/index.html                    # expect 1
grep -c "11 domain-agnostic wire-envelope vectors" landing/index.html    # expect 1
grep -c 'href="/conformance"' landing/index.html                         # expect 3
```

- [ ] **Step 9: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add landing/index.html
git commit -s -m "landing: drop hosted-verifier/managed-platform copy; evc-conformance 0.6.0 / 41 vectors; link /conformance"
```

### Task 11: `deploy.sh` and `verify.sh`

**Files:**
- Modify: `landing/deploy.sh`
- Modify: `landing/verify.sh`

- [ ] **Step 1: deploy.sh — page variable, pre-check, preflight, drift check**

After line 35 `PLAYGROUND="$SCRIPT_DIR/playground.html"` add `CONFORMANCE="$SCRIPT_DIR/conformance.html"`. In the `for f in ...` pre-check loop (line 37) append `"$CONFORMANCE"`. After line 59 `preflight_version "@bolyra/cli"     "@bolyra/cli@"` add:
```bash
preflight_version "@bolyra/evc-conformance" "@bolyra/evc-conformance@"
# The committed page must match the registry; deploying a stale page is a
# silent lie about which claims exist.
node "$SCRIPT_DIR/gen-conformance.js" --check || { echo "ERROR: landing/conformance.html drifts from interop/claims.json — run node landing/gen-conformance.js" >&2; exit 1; }
```

- [ ] **Step 2: deploy.sh — upload pair (after the agent-spend pair ending line 145)**

```bash
echo "→ uploading conformance.html to s3://$BUCKET/"
aws s3 cp "$CONFORMANCE" "s3://$BUCKET/conformance.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
aws s3 cp "$CONFORMANCE" "s3://$BUCKET/conformance" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "public, max-age=300"
```

- [ ] **Step 3: deploy.sh — invalidation** — in the `--paths` list (line 252) add `"/conformance.html" "/conformance"` after `"/agent-spend"`.

- [ ] **Step 4: verify.sh — guards and checks (after line 242 `guard_version "@bolyra/cli"     "@bolyra/cli@"`)**

```bash
guard_version "@bolyra/evc-conformance" "@bolyra/evc-conformance@"

# The advertised vector count must equal what the ADVERTISED package version
# actually loads. Pin npx to the version the page names (unpinned npx can
# serve the cache); guard_version above separately checks it is npm's latest.
EVC_ADVERTISED=$(grep -oE '@bolyra/evc-conformance@[0-9]+\.[0-9]+\.[0-9]+' <<< "$LIVE_HTML" | sed 's/.*@//' | sort -u)
[ "$(wc -l <<< "$EVC_ADVERTISED" | tr -d ' ')" = "1" ] && [ -n "$EVC_ADVERTISED" ] || fail "page must advertise exactly one @bolyra/evc-conformance version (got: '$EVC_ADVERTISED')"
ADVERTISED_COUNT=$(grep -oE '[0-9]+ wire-contract vectors' <<< "$LIVE_HTML" | head -1 | grep -oE '^[0-9]+' || true)
[ -n "$ADVERTISED_COUNT" ] || fail "page does not advertise a wire-contract vector count"
EVC_TMP=$(mktemp -d)
LOADED_COUNT=$( (cd "$EVC_TMP" && npx -y "@bolyra/evc-conformance@${EVC_ADVERTISED}" 2>/dev/null | grep -oE '^[0-9]+ test vectors loaded' | head -1 | grep -oE '^[0-9]+') || true )
rm -rf "$EVC_TMP"
[[ "$LOADED_COUNT" =~ ^[0-9]+$ ]] || fail "could not read '<N> test vectors loaded' from @bolyra/evc-conformance@$EVC_ADVERTISED (got '$LOADED_COUNT')"
if [ "$ADVERTISED_COUNT" = "$LOADED_COUNT" ]; then
  pass "vector count: page advertises $ADVERTISED_COUNT, @bolyra/evc-conformance@$EVC_ADVERTISED loads $LOADED_COUNT"
else
  fail "vector count drift: page advertises $ADVERTISED_COUNT but @bolyra/evc-conformance@$EVC_ADVERTISED loads $LOADED_COUNT"
fi

# Copy that promised a hosted/managed platform was removed on 2026-09-10 and
# must not come back (settled 2026-08-27 ruling: no hosted platform). The four
# patterns cover all five deleted phrases (two shared "hosted verifier preview").
for phrase in "hosted verifier preview" "Hosted <code>POST /v1/verify</code> preview" "managed verifier path" "Managed operations when you need them"; do
  if grep -qF "$phrase" <<< "$LIVE_HTML"; then fail "removed copy reappeared on the live page: '$phrase'"; fi
done
pass "no hosted-verifier / managed-platform copy on the live page"
grep -qF "11 domain-agnostic wire-envelope vectors" <<< "$LIVE_HTML" || fail "root page lacks '11 domain-agnostic wire-envelope vectors'"
grep -qF 'href="/conformance"' <<< "$LIVE_HTML" || fail "root page does not link /conformance"
pass "root page advertises 11 envelope vectors and links /conformance"

# The conformance page is live and carries both published claims.
CONF_HTML=$(curl -fsS "https://bolyra.ai/conformance?vguard=$(date +%s)") || fail "GET /conformance failed"
grep -qF "17642a5" <<< "$CONF_HTML" || fail "/conformance lacks the mcp-use claim pin 17642a5"
grep -qF "35e209d" <<< "$CONF_HTML" || fail "/conformance lacks the StillOS claim pin 35e209d"
grep -qF "This is NOT Bolyra-suite conformance." <<< "$CONF_HTML" || fail "/conformance lacks the own-corpus qualifier"
[ "$(grep -c '<h2 class="claim-id">' <<< "$CONF_HTML")" = "2" ] || fail "/conformance should show exactly 2 claims"
pass "/conformance is live with both claims and the own-corpus qualifier"
```

- [ ] **Step 5: Syntax-check both scripts and dry-run the count logic against the live package**

```bash
bash -n landing/deploy.sh && bash -n landing/verify.sh && echo syntax ok
T=$(mktemp -d); (cd "$T" && npx -y @bolyra/evc-conformance@0.6.0 2>/dev/null | grep -oE '^[0-9]+ test vectors loaded'); rm -rf "$T"
```
Expected: `syntax ok`; `41 test vectors loaded`.

- [ ] **Step 6: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add landing/deploy.sh landing/verify.sh
git commit -s -m "landing: deploy/verify the conformance page; evc-conformance version + vector-count guards; forbid hosted-platform copy"
```

### Task 12: `interop/SUBMITTING.md` and README pointer

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
These are review-gated rules (nothing mechanical enforces them yet);
submissions that do not follow them are not dispatched.
`external-suite` claims need a digest-pinned `node:` image
(`node:<tag>@sha256:<64 hex>`) and `"network": "none"`.

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
   runs the `Interop replay` workflow by dispatch with `ref=<that SHA>` and
   `claim=<your id>`. Only your registry entry and your one new adapter are
   taken from that SHA; the harness runs from `main`. Any push after that
   review needs a fresh review and a fresh dispatch.
7. Green dispatch on the reviewed SHA + code-owner review → merge → your row
   appears on https://bolyra.ai/conformance at the next deploy. The dispatch
   run URL is recorded in the merge commit.

## Rules (from README)

- A red replay means investigate, never edit the claim.
- Claims stay pinned; re-verification at a newer suite is a **new** row.
- `external-suite` results are own-corpus reproductions, not Bolyra-suite
  conformance; the page says so on every such row regardless of your text.
```

- [ ] **Step 2: README pointer** — at the end of `interop/README.md`'s `## Rules` section add:
```markdown
- **Submitting a claim**: see [SUBMITTING.md](SUBMITTING.md). `verification_run_url`
  is a reserved field (not rendered in v1; rejected on submissions).
```

- [ ] **Step 3: Commit**

```bash
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add interop/SUBMITTING.md interop/README.md
git commit -s -m "interop: SUBMITTING.md — maintainer-operated claim submissions"
git push
```

### Task 13: Submission proof, review, merge, deploy (in that order)

**Files:** none new; evidence in the PR body.

- [ ] **Step 1: Submission proof on a throwaway branch (uses the overlay path, like a real submission)**

```bash
git checkout -q -b probe/submission origin/public-conformance-claims
node - <<'EOF'
const fs = require('fs');
const reg = JSON.parse(fs.readFileSync('interop/claims.json', 'utf8'));
const still = reg.claims.find((c) => c.kind === 'external-suite');
reg.claims.push({ ...still, id: 'probe@35e209d/own-corpus', claim_text: 'PROBE submission (never merge)', verified_on: '2026-09-10' });
fs.writeFileSync('interop/claims.json', JSON.stringify(reg, null, 2) + '\n');
EOF
node landing/gen-conformance.js && node interop/replay.js --check
export GIT_AUTHOR_NAME="Viswanadha Pratap Kondoju" GIT_AUTHOR_EMAIL="kondojuviswanadha@gmail.com" GIT_COMMITTER_NAME="Viswanadha Pratap Kondoju" GIT_COMMITTER_EMAIL="saneGuy@users.noreply.github.com"
git add -A && git commit -s -q -m "probe: submission (never merge)" && git push -q -u origin probe/submission
GOOD_SHA=$(git rev-parse HEAD)
gh pr create --repo bolyra/bolyra --base public-conformance-claims --head probe/submission --draft --title "probe: submission proof (never merge)" --body "Evidence only."
gh pr checks --repo bolyra/bolyra --watch     # offline checks green; inspect the evc-conformance job log: only --check/tests/generator ran
git checkout -q public-conformance-claims
dispatch_and_wait public-conformance-claims -f ref="$GOOD_SHA" -f claim="probe@35e209d/own-corpus"    # helper from Task 6
```
Expected: `conclusion=success`, `1/1 claims reproduced`. Save as `PROOF_SUBMISSION_GREEN`.

Now the failing case (the spec's wording is "hash mismatch"; a bad `adapter_sha256` is caught OFFLINE by `--check` before any dispatch, so the dispatch-level failing case is an expectation mismatch):
```bash
git checkout -q probe/submission
node - <<'EOF'
const fs = require('fs'); const reg = JSON.parse(fs.readFileSync('interop/claims.json', 'utf8'));
reg.claims.find((c) => c.id === 'probe@35e209d/own-corpus').run.expect.pass = 38;
fs.writeFileSync('interop/claims.json', JSON.stringify(reg, null, 2) + '\n');
EOF
node landing/gen-conformance.js    # regenerate, or the drift guard fails for the wrong reason
git add -A && git commit -s -q -m "probe: expectation mismatch (never merge)" && git push -q
BAD_SHA=$(git rev-parse HEAD); git checkout -q public-conformance-claims
dispatch_and_wait public-conformance-claims -f ref="$BAD_SHA" -f claim="probe@35e209d/own-corpus"
```
Expected: `conclusion=failure`; log contains `REPLAY MISMATCH: expected 38/39 passed (9 scoped out), got 39/39 (9)`. Save as `PROOF_SUBMISSION_RED`. Then close the probe PR and delete the branch:
```bash
gh pr close --repo bolyra/bolyra probe/submission --delete-branch
```

- [ ] **Step 2: Mark the PR ready with all evidence, then Codex review, then merge**

Edit the PR body to list, under "Isolation proofs (spec §3.5)" and "Submission proofs (spec §6)": every URL from `PROOF_URLS` (Task 6) plus `PROOF_SUBMISSION_GREEN` / `PROOF_SUBMISSION_RED`, and the `REPLAY_IMAGE` digest with the reason (git required). Then `gh pr ready --repo bolyra/bolyra`. The workspace rule applies: Codex reviews the full diff before merge; fix, re-review, then rebase-merge:
```bash
gh pr merge --repo bolyra/bolyra --rebase --delete-branch
git fetch -q origin main && MERGE_SHA=$(git rev-parse origin/main) && echo "$MERGE_SHA"
```

- [ ] **Step 3: Deploy from the merge commit (never from the branch)**

```bash
DEPLOY=$(mktemp -d) && git clone -q --no-local --branch main . "$DEPLOY/repo" 2>/dev/null || git clone -q https://github.com/bolyra/bolyra "$DEPLOY/repo"
cd "$DEPLOY/repo" && git checkout -q "$MERGE_SHA" && ./landing/deploy.sh; cd - >/dev/null
```
Expected: preflight lines including `OK: local page advertises @bolyra/evc-conformance@0.6.0` and `gen-conformance --check OK`; uploads including `conformance.html`; invalidation id; then `verify.sh` runs automatically and its output ends with the new `OK:` lines (`vector count`, `no hosted-verifier`, `root page advertises 11`, `/conformance is live`).

- [ ] **Step 4: Live curls**

```bash
curl -fsS https://bolyra.ai/conformance | grep -c '<h2 class="claim-id">'   # expect 2
curl -fsS https://bolyra.ai/ | grep -c "hosted verifier preview"           # expect 0 (grep exits 1; that is the pass)
curl -fsS https://bolyra.ai/ | grep -c "@bolyra/evc-conformance@0.6.0"     # expect 1
```

- [ ] **Step 5: Record**

Append the deploy + verify output summary and the live curls to the merged PR as a comment. Append a line to `~/.claude/projects/-Users-lordviswa-Projects/memory/github_activity_bolyra.md` with the PR number, `MERGE_SHA`, and a one-line summary; **add** a pointer line for this build to `MEMORY.md` marked DONE.
