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
  git(repo, 'checkout', '-q', '--detach', baseSha); // back on base; independent of init.defaultBranch
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
  assert.match(r.stderr, /not a regular file \(mode 120000/);
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

test('destination safety: a dangling symlink where the new adapter would land is "already exists"', () => {
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/new.ts' };
  const { repo, subSha } = makeRepo((r) => {
    writeRegistry(r, [BASE_CLAIM, NEW]);
    fs.writeFileSync(path.join(r, 'interop', 'adapters', 'new.ts'), '// new adapter\n');
  });
  fs.symlinkSync('/nonexistent/target', path.join(repo, 'interop', 'adapters', 'new.ts')); // planted at the base, dangling
  const r = run(repo, ['--ref', subSha, '--claim', 'new@2']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /adapters\/new\.ts already exists/);
});

test('ids with control characters or a leading dash are rejected by the overlay too', () => {
  const { repo, subSha } = makeRepo((r) => writeRegistry(r, [BASE_CLAIM, { ...EXT_CLAIM, id: '--list' }, { ...EXT_CLAIM, id: 'x\ty' }]));
  let r = run(repo, ['--ref', subSha, '--claim', '--list']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /claim id not allowed/);
  r = run(repo, ['--ref', subSha, '--claim', 'x\ty']);
  assert.strictEqual(r.status, 1); assert.match(r.stderr, /claim id not allowed/);
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

test('sibling claims come from the BASE registry, never from the submission', () => {
  // The submission adds new@2 AND tampers base@1's adapter with a traversal path.
  // Only new@2 may be taken; base@1 must survive exactly as the base had it.
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/new.ts' };
  const TAMPERED_BASE = { ...BASE_CLAIM, adapter: '../../../../etc/passwd' };
  const { repo, subSha } = makeRepo((r) => {
    writeRegistry(r, [TAMPERED_BASE, NEW]);
    fs.writeFileSync(path.join(r, 'interop', 'adapters', 'new.ts'), '// new adapter\n');
  });
  const r = run(repo, ['--ref', subSha, '--claim', 'new@2']);
  assert.strictEqual(r.status, 0, r.stderr);
  const reg = JSON.parse(fs.readFileSync(path.join(repo, 'interop', 'claims.json'), 'utf8'));
  assert.deepStrictEqual(reg.claims.map((x) => x.id), ['base@1', 'new@2']);
  assert.deepStrictEqual(reg.claims[0], BASE_CLAIM, 'base@1 must be the BASE entry, not the submitted one');
  assert.strictEqual(reg.claims[1].id, 'new@2');
});

test('selecting a claim that already exists at the base is refused', () => {
  const { repo, subSha } = makeRepo((r) => writeRegistry(r, [BASE_CLAIM, { ...EXT_CLAIM }]));
  const r = run(repo, ['--ref', subSha, '--claim', 'base@1']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /already exists at the base; submissions may only ADD a claim/);
});

test('an external-suite claim carrying an adapter field is refused', () => {
  const { repo, subSha } = makeRepo((r) => writeRegistry(r, [BASE_CLAIM, { ...EXT_CLAIM, adapter: '../../../../etc/passwd' }]));
  const r = run(repo, ['--ref', subSha, '--claim', 'ext@1']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /must not carry an adapter field/);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(repo, 'interop', 'claims.json'), 'utf8')).claims.length, 1);
});

test('a failure after the adapter write removes only what this run created', () => {
  if (process.getuid && process.getuid() === 0) return;   // root ignores mode bits
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/new.ts' };
  const { repo, subSha } = makeRepo((r) => {
    writeRegistry(r, [BASE_CLAIM, NEW]);
    fs.writeFileSync(path.join(r, 'interop', 'adapters', 'new.ts'), '// new adapter\n');
  });
  const interopDir = path.join(repo, 'interop');
  const mode = fs.statSync(interopDir).mode;
  fs.chmodSync(interopDir, 0o555);            // adapters/ stays writable; the temp file in interop/ cannot be created
  let r;
  try { r = run(repo, ['--ref', subSha, '--claim', 'new@2']); } finally { fs.chmodSync(interopDir, mode); }
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /^submission-overlay: /);
  assert.ok(!/\n\s+at /.test(r.stderr), 'must be the error contract, not a raw stack trace');
  assert.ok(!fs.existsSync(path.join(repo, 'interop', 'adapters', 'new.ts')), 'the adapter this run created must be removed');
  assert.deepStrictEqual(fs.readdirSync(interopDir).filter((f) => f.startsWith('.claims.json.')), []);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(interopDir, 'claims.json'), 'utf8')).claims.length, 1, 'registry untouched');
});

test('no temp file survives, on success or on refusal', () => {
  const leftovers = (repo) => fs.readdirSync(path.join(repo, 'interop')).filter((f) => f.startsWith('.claims.json.'));
  const NEW = { ...BASE_CLAIM, id: 'new@2', adapter: 'adapters/new.ts' };
  const ok = makeRepo((r) => {
    writeRegistry(r, [BASE_CLAIM, NEW]);
    fs.writeFileSync(path.join(r, 'interop', 'adapters', 'new.ts'), '// new adapter\n');
  });
  assert.strictEqual(run(ok.repo, ['--ref', ok.subSha, '--claim', 'new@2']).status, 0);
  assert.deepStrictEqual(leftovers(ok.repo), []);
  const bad = makeRepo((r) => writeRegistry(r, [BASE_CLAIM, { ...EXT_CLAIM, id: 'k@4', kind: 'mystery' }]));
  assert.strictEqual(run(bad.repo, ['--ref', bad.subSha, '--claim', 'k@4']).status, 1);
  assert.deepStrictEqual(leftovers(bad.repo), []);
});
