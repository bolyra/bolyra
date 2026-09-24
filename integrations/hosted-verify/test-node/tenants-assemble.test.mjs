// pilot/tenants-assemble.mjs builds the TENANTS map tenant.sh validates and puts: registry
// files from a directory, tokens as "<org> <role> <token>" lines. Every refusal must name the
// file or org an operator has to fix (never a token), and the happy path must produce a map
// tenants-check.mjs accepts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assemble } from '../pilot/tenants-assemble.mjs';
import { checkTenants } from '../pilot/tenants-check.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'pilot', 'tenants-assemble.mjs');
const tok = (c) => c.repeat(40);
const TOKENS = {
  'acme admin': tok('a'),
  'acme verifier': tok('b'),
  'beta admin': tok('c'),
  'beta verifier': tok('d'),
};
const lines = (pairs) => Object.entries(pairs).map(([k, v]) => `${k} ${v}\n`).join('');

function withDir(files, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), 'tenants-assemble-'));
  try {
    for (const [name, body] of Object.entries(files)) {
      writeFileSync(path.join(dir, name), typeof body === 'string' ? body : JSON.stringify(body));
    }
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const rec = (org, extra = {}) => ({ org_id: org, status: 'active', trustedOperators: ['1:2'], ...extra });
/** Assert assemble() refuses with a message matching `re` that carries no token. */
function refuses(dir, tokenText, re) {
  assert.throws(() => assemble(dir, tokenText), (e) => {
    assert.match(e.message, re);
    for (const t of Object.values(TOKENS)) assert.ok(!e.message.includes(t), 'error message leaked a token');
    return true;
  });
}

test('happy path: active + disabled, deduped keys; tenants-check accepts the output', () =>
  withDir(
    {
      'acme.json': rec('acme', { trustedOperators: ['1:2', '3:4', '1:2'] }),
      'beta.json': rec('beta', { status: 'disabled' }),
      '.hidden.json': 'not json',
      'acme.policy.json': 'not json',
      'notes.txt': 'ignored',
    },
    (dir) => {
      const map = assemble(dir, lines(TOKENS));
      assert.deepEqual(map, {
        acme: { admin_token: tok('a'), verifier_token: tok('b'), trusted_operators: ['1:2', '3:4'] },
        beta: { admin_token: tok('c'), verifier_token: tok('d'), trusted_operators: ['1:2'], disabled: true },
      });
      const result = checkTenants(JSON.stringify(map));
      assert.equal(result.ok, true, JSON.stringify(result.errors));
      assert.deepEqual(result.orgs, ['acme', 'beta']);
    },
  ));

test('a removed tenant is excluded and needs no tokens', () =>
  withDir({ 'acme.json': rec('acme'), 'gone.json': rec('gone', { status: 'removed' }) }, (dir) => {
    const map = assemble(dir, lines({ 'acme admin': tok('a'), 'acme verifier': tok('b') }));
    assert.deepEqual(Object.keys(map), ['acme']);
  }));

test('bad JSON names the file', () =>
  withDir({ 'acme.json': '{"org_id":' }, (dir) => refuses(dir, lines(TOKENS), /^acme\.json: not valid JSON$/)));

for (const [name, body] of [
  ['null', 'null'],
  ['an array', '[]'],
  ['a string', '"acme"'],
  ['a number', '7'],
]) {
  test(`a record that is ${name} is refused by name, not with a TypeError`, () =>
    withDir({ 'acme.json': body }, (dir) => refuses(dir, lines(TOKENS), /^acme\.json: record must be a JSON object$/)));
}

test('org_id must match the file name', () =>
  withDir({ 'acme.json': rec('other') }, (dir) => refuses(dir, lines(TOKENS), /^acme\.json: org_id must equal the file name$/)));

test('an unknown status is refused', () =>
  withDir({ 'acme.json': rec('acme', { status: 'paused' }) }, (dir) =>
    refuses(dir, lines(TOKENS), /^acme\.json: status must be active, disabled, or removed$/)));

test('a missing token is refused by org', () =>
  withDir({ 'acme.json': rec('acme') }, (dir) =>
    refuses(dir, lines({ 'acme admin': tok('a') }), /^acme: missing a token for admin or verifier$/)));

test('trustedOperators must be an array', () =>
  withDir({ 'acme.json': rec('acme', { trustedOperators: '1:2' }) }, (dir) =>
    refuses(dir, lines(TOKENS), /^acme\.json: trustedOperators must be an array$/)));

test('a repeated "<org> <role>" token line is refused (it used to overwrite silently)', () =>
  withDir({ 'acme.json': rec('acme') }, (dir) =>
    refuses(dir, lines(TOKENS) + `acme admin ${tok('e')}\n`, /^token line 5: a second token for acme admin$/)));

test('an unknown role is refused', () =>
  withDir({ 'acme.json': rec('acme') }, (dir) =>
    refuses(dir, lines(TOKENS) + `acme owner ${tok('e')}\n`, /^token line 5: role must be admin or verifier$/)));

test('a malformed token line is refused', () =>
  withDir({ 'acme.json': rec('acme') }, (dir) =>
    refuses(dir, `acme admin ${tok('a')}\nacme verifier\n`, /^token line 2: malformed \(expected "<org_id> <role> <token>"\)$/)));

test('CLI: the map on stdout, refusals on stderr with exit 1, usage exit 2', () =>
  withDir({ 'acme.json': rec('acme'), 'beta.json': rec('beta') }, (dir) => {
    const ok = spawnSync(process.execPath, [CLI, dir], { input: lines(TOKENS), encoding: 'utf8' });
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(Object.keys(JSON.parse(ok.stdout)), ['acme', 'beta']);
    assert.equal(ok.stderr, '');

    writeFileSync(path.join(dir, 'beta.json'), 'null');
    const bad = spawnSync(process.execPath, [CLI, dir], { input: lines(TOKENS), encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.equal(bad.stdout, '');
    assert.equal(bad.stderr, 'tenants-assemble: beta.json: record must be a JSON object\n');

    const usage = spawnSync(process.execPath, [CLI], { input: '', encoding: 'utf8' });
    assert.equal(usage.status, 2);
    assert.match(usage.stderr, /^usage: tenants-assemble\.mjs/);
  }));

test('importing the module runs no CLI (no stdin read, no exit)', () => {
  // Reaching this line at all means the import above did not exit or block on stdin.
  assert.equal(typeof assemble, 'function');
});

test('a registry directory that is a subdirectory named x.json is skipped', () =>
  withDir({ 'acme.json': rec('acme') }, (dir) => {
    mkdirSync(path.join(dir, 'dir.json'));
    const map = assemble(dir, lines({ 'acme admin': tok('a'), 'acme verifier': tok('b') }));
    assert.deepEqual(Object.keys(map), ['acme']);
  }));

// E13: `{}` is now a VALID map downstream, so an assembler that turned an empty (or wrong)
// registry directory into `{}` would be one --allow-empty away from wiping every tenant. A
// directory with no record files is refused here, in the pipeline itself — tenant.sh's own
// check runs in a pipeline stage whose exit cannot stop the stages after it.
test('a directory with NO record files is refused (never assembled into {})', () =>
  withDir({ 'notes.txt': 'x', '.hidden.json': 'x', 'acme.policy.json': 'x' }, (dir) => {
    mkdirSync(path.join(dir, 'dir.json'));
    refuses(dir, '', /^no registry record files in .+$/);
    const cli = spawnSync(process.execPath, [CLI, dir], { input: '', encoding: 'utf8' });
    assert.equal(cli.status, 1);
    assert.equal(cli.stdout, '');
  }));

test('every record removed is the deliberate empty map {} (the flag is decided downstream)', () =>
  withDir({ 'acme.json': rec('acme', { status: 'removed' }) }, (dir) => {
    assert.deepEqual(assemble(dir, ''), {});
  }));
