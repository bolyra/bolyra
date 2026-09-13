'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

// The script is exercised from a COPY outside the repo, like the workflow does.
const COPY = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hi-copy-')), 'harness-integrity.js');
fs.copyFileSync(path.join(__dirname, 'harness-integrity.js'), COPY);

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
  fs.writeFileSync(path.join(repo, 'package.json'), '{}\n');
  fs.writeFileSync(path.join(repo, '.gitignore'), 'interop/*.log\n');
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'base');
  return repo;
}
function run(repo, ...args) {
  return spawnSync(process.execPath, [COPY, ...args, '--root', repo], { encoding: 'utf8', env: { PATH: process.env.PATH } });
}
function snap(repo) { const f = path.join(os.tmpdir(), `snap-${process.pid}-${Math.random()}.json`); const r = run(repo, 'snapshot', f); assert.strictEqual(r.status, 0, r.stderr); return f; }
const failsOn = (repo, f, re) => { const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1, 'expected verify to fail'); assert.match(r.stderr, re); };

test('unchanged tree verifies (from a copy, with a scrubbed environment)', () => {
  const repo = makeRepo(); const f = snap(repo);
  const r = run(repo, 'verify', f); assert.strictEqual(r.status, 0, r.stderr); assert.match(r.stdout, /harness-integrity: OK/);
});
test('overlaid (dirty) files are part of the baseline; tampering them afterwards fails', () => {
  const repo = makeRepo();
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), '{"claims":[1]}\n');
  fs.writeFileSync(path.join(repo, 'interop', 'adapters', 'new.ts'), '// new\n');
  const f = snap(repo);
  assert.strictEqual(run(repo, 'verify', f).status, 0);
  fs.writeFileSync(path.join(repo, 'interop', 'claims.json'), '{"claims":[2]}\n');
  failsOn(repo, f, /interop\/claims\.json/);
});
test('modifying a tracked harness file fails', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.writeFileSync(path.join(repo, 'interop', 'replay.js'), '// evil\n'); failsOn(repo, f, /interop\/replay\.js/);
});
test('an IGNORED file added under a protected dir fails (git-based enumeration would miss it)', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.writeFileSync(path.join(repo, 'interop', 'sneaky.log'), 'x\n'); failsOn(repo, f, /interop\/sneaky\.log/);
});
test('untracked file under a protected dir fails; a file outside protected roots is ignored', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.writeFileSync(path.join(repo, 'other', 'more.txt'), 'x\n');
  assert.strictEqual(run(repo, 'verify', f).status, 0, 'outside protected roots');
  fs.writeFileSync(path.join(repo, 'spec', 'sneaky.js'), 'x\n'); failsOn(repo, f, /spec\/sneaky\.js/);
});
test('root-level file change and .git/config change both fail', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.writeFileSync(path.join(repo, 'package.json'), '{"x":1}\n'); failsOn(repo, f, /package\.json/);
  const f2 = snap(repo);
  fs.appendFileSync(path.join(repo, '.git', 'config'), '[core]\n\tfsmonitor = /tmp/evil\n'); failsOn(repo, f2, /\.git\/config/);
});
test('a permission-bit-only change fails', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.chmodSync(path.join(repo, 'spec', 'runner.js'), 0o666); failsOn(repo, f, /spec\/runner\.js/);
});
test('replacing a file with a symlink, deleting a file, and adding a directory all fail', () => {
  const repo = makeRepo(); const f = snap(repo);
  fs.unlinkSync(path.join(repo, 'spec', 'runner.js')); fs.symlinkSync('/etc/hostname', path.join(repo, 'spec', 'runner.js')); failsOn(repo, f, /spec\/runner\.js/);
  const repo2 = makeRepo(); const g = snap(repo2);
  fs.unlinkSync(path.join(repo2, '.github', 'workflows', 'w.yml')); failsOn(repo2, g, /\.github\/workflows\/w\.yml/);
  const repo3 = makeRepo(); const h = snap(repo3);
  fs.mkdirSync(path.join(repo3, 'landing', 'evil')); failsOn(repo3, h, /landing\/evil/);
});
test('.git/objects is covered: an object-content change, an info/alternates file, and objects-as-symlink all fail', () => {
  const repo = makeRepo(); const f = snap(repo);
  const objDir = path.join(repo, '.git', 'objects');
  const some = fs.readdirSync(objDir).find((d) => /^[0-9a-f]{2}$/.test(d));
  const obj = path.join(objDir, some, fs.readdirSync(path.join(objDir, some))[0]);
  fs.chmodSync(obj, 0o644); fs.appendFileSync(obj, 'x'); failsOn(repo, f, /\.git\/objects\//);
  const repo2 = makeRepo(); const g = snap(repo2);
  fs.mkdirSync(path.join(repo2, '.git', 'objects', 'info'), { recursive: true });
  fs.writeFileSync(path.join(repo2, '.git', 'objects', 'info', 'alternates'), '/tmp/evil\n'); failsOn(repo2, g, /\.git\/objects\/info\/alternates/);
  const repo3 = makeRepo(); const h = snap(repo3);
  fs.renameSync(path.join(repo3, '.git', 'objects'), path.join(repo3, '.git', 'objects.real'));
  fs.symlinkSync('objects.real', path.join(repo3, '.git', 'objects')); failsOn(repo3, h, /\.git\/objects/);
});
test('a root-level file named __proto__ is fingerprinted (no prototype-setter swallowing)', () => {
  const repo = makeRepo(); fs.writeFileSync(path.join(repo, '__proto__'), 'a\n'); const f = snap(repo);
  assert.ok(Object.prototype.hasOwnProperty.call(JSON.parse(fs.readFileSync(f, 'utf8')), '__proto__'));
  fs.writeFileSync(path.join(repo, '__proto__'), 'b\n'); failsOn(repo, f, /__proto__/);
});
test('an unreadable entry is an error, not "absent"', () => {
  if (process.getuid && process.getuid() === 0) return; // root can read anything
  const repo = makeRepo(); const f = snap(repo);
  fs.chmodSync(path.join(repo, 'spec'), 0o000);
  try { const r = run(repo, 'verify', f); assert.strictEqual(r.status, 1); assert.match(r.stderr, /EACCES|EPERM/); }
  finally { fs.chmodSync(path.join(repo, 'spec'), 0o755); }
});
