// The tenants-check CLI as tenant.sh drives it: the growth warning (E15) goes to STDERR only,
// and `--pass` still copies exactly the validated map to stdout — the bytes that reach
// `wrangler secret put` must not change because a warning was printed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'pilot', 'tenants-check.mjs');
const KEY = '1:2';

/** A valid map of exactly `bytes` bytes (the same construction as test/tenants-check.spec.ts). */
function sizedMap(bytes) {
  const letter = (i) => String.fromCharCode(97 + i);
  const build = (lengths) => {
    const map = {};
    for (let i = 0; i < lengths.length / 2; i += 1) map[`org-${letter(i)}`] = { admin_token: letter(2 * i).repeat(lengths[2 * i]), verifier_token: letter(2 * i + 1).repeat(lengths[2 * i + 1]), trusted_operators: [KEY] };
    return JSON.stringify(map);
  };
  for (let count = 1; count <= 12; count += 1) {
    // Every token starts at the 32-character minimum and grows one character per byte, up to
    // 256, in order — so every size between this count's minimum and maximum is reachable.
    const lengths = new Array(2 * count).fill(32);
    let extra = bytes - build(lengths).length;
    if (extra < 0) break;
    for (let t = 0; t < lengths.length && extra > 0; t += 1) {
      const grow = Math.min(extra, 256 - 32);
      lengths[t] += grow;
      extra -= grow;
    }
    if (extra === 0) {
      const raw = build(lengths);
      if (raw.length === bytes) return raw;
    }
  }
  throw new Error(`no map of exactly ${bytes} bytes`);
}

const run = (input, ...args) => spawnSync(process.execPath, [CLI, ...args], { input, encoding: 'utf8' });

test('3276 bytes: no warning; --pass stdout is the map', () => {
  const raw = sizedMap(3276);
  const r = run(raw, '--pass');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, raw);
  assert.doesNotMatch(r.stderr, /warning/);
});

test('3277 bytes: the warning is on stderr and --pass stdout is unchanged', () => {
  const raw = sizedMap(3277);
  const r = run(raw, '--pass');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, raw);
  assert.match(r.stderr, /^tenants-check: warning: 3277\/4096 bytes \(819 left\) — plan tenant growth or raise the ceiling$/m);
  assert.match(r.stderr, /tenants-check: ok: \d+ tenant\(s\).*, 3277 bytes$/m);
});

test('4096 bytes: refused with the existing hard error, nothing on stdout', () => {
  const r = run(sizedMap(4096), '--pass');
  assert.equal(r.status, 1);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /serialized size must be under 4096 bytes \(is 4096\)/);
  assert.doesNotMatch(r.stderr, /warning/);
});

test('{} (the last tenant removed): exit 0, the empty-map warning on stderr, --pass stdout is exactly {}', () => {
  const r = run('{}', '--pass');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, '{}');
  assert.match(r.stderr, /^tenants-check: warning: empty map: every request will be denied until a tenant is added$/m);
  assert.match(r.stderr, /tenants-check: ok: 0 tenant\(s\) \[\], 2 bytes$/m);
});

test('empty stdin and a non-object stay refused', () => {
  for (const input of ['', '[]', 'null']) {
    const r = run(input, '--pass');
    assert.equal(r.status, 1, `input ${JSON.stringify(input)}: ${r.stderr}`);
    assert.equal(r.stdout, '');
  }
});
