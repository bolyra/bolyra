import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { validateTrialConfig, loadTrialConfig, TrialConfigError } from '../src/config';

const base = fs.mkdtempSync(path.join(os.tmpdir(), 'trial-config-'));

function valid(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    action: 'refund',
    method: 'POST',
    url: 'https://staging.example.com/v1/refunds',
    requiredPermission: 'WRITE_DATA',
    ...overrides,
  };
}

function rejects(input: Record<string, unknown>, fragment: string, env: NodeJS.ProcessEnv = {}) {
  assert.throws(
    () => validateTrialConfig(input, base, env),
    (err: unknown) => err instanceof TrialConfigError && err.message.includes(fragment),
    `expected TrialConfigError mentioning "${fragment}"`,
  );
}

test('accepts a minimal valid config', () => {
  const cfg = validateTrialConfig(valid(), base, {});
  assert.equal(cfg.action, 'refund');
  assert.equal(cfg.method, 'POST');
  assert.equal(cfg.url.hostname, 'staging.example.com');
  assert.deepEqual(cfg.headers, {});
  assert.equal(cfg.body, undefined);
  assert.equal(cfg.requiredPermission, 'WRITE_DATA');
  assert.deepEqual(cfg.secrets, []);
});

test('rejects unknown keys', () => rejects(valid({ extra: 1 }), 'unknown key: extra'));
test('rejects a bad action name', () => rejects(valid({ action: 'Refund!' }), 'action'));
test('rejects a bad method', () => rejects(valid({ method: 'OPTIONS' }), 'method'));
test('rejects a non-http scheme', () => rejects(valid({ url: 'ftp://x' }), 'scheme'));
test('rejects credentials in the URL', () => rejects(valid({ url: 'https://u:p@x.example/' }), 'credentials'));
test('rejects an unknown permission', () => rejects(valid({ requiredPermission: 'ROOT' }), 'requiredPermission'));

test('substitutes ${ENV} in header values and records the secret needles', () => {
  const cfg = validateTrialConfig(
    valid({ headers: { Authorization: 'Bearer ${T}', 'X-Static': 'plain' } }),
    base,
    { T: 'sekrit-123' },
  );
  assert.equal(cfg.headers.Authorization, 'Bearer sekrit-123');
  assert.equal(cfg.headers['X-Static'], 'plain');
  // Needles: each substituted env value, and each header value that contained a
  // substitution. Static header values are not needles (a short static value such
  // as "application/json" would false-positive against the bundle's own content).
  assert.deepEqual(cfg.secrets, ['sekrit-123', 'Bearer sekrit-123']);
});

test('fails on an unset ${ENV} before anything else runs (spec test 9)', () => {
  rejects(valid({ headers: { Authorization: 'Bearer ${MISSING}' } }), 'MISSING', {});
});

test('parse errors never echo file content', () => {
  const y = path.join(base, 'broken.yaml');
  fs.writeFileSync(y, 'action: refund\nheaders: {Authorization: "Bearer sekrit-in-file\n');
  assert.throws(
    () => loadTrialConfig(y, {}),
    (err: unknown) => err instanceof TrialConfigError && !err.message.includes('sekrit-in-file') && /could not be parsed/.test(err.message),
  );
});

test('rejects bodyFile with GET, HEAD, DELETE', () => {
  const bodyPath = path.join(base, 'b.json');
  fs.writeFileSync(bodyPath, '{}');
  for (const method of ['GET', 'HEAD', 'DELETE']) {
    rejects(valid({ method, bodyFile: 'b.json' }), 'bodyFile');
  }
});

test('reads bodyFile relative to the config directory, byte for byte', () => {
  fs.writeFileSync(path.join(base, 'body.bin'), Buffer.from([0, 255, 10, 13]));
  const cfg = validateTrialConfig(valid({ bodyFile: 'body.bin' }), base, {});
  assert.deepEqual(cfg.body, Buffer.from([0, 255, 10, 13]));
});

test('loadTrialConfig parses YAML and JSON', () => {
  const y = path.join(base, 'trial.yaml');
  fs.writeFileSync(y, 'action: refund\nmethod: POST\nurl: https://x.example/r\nrequiredPermission: READ_DATA\n');
  assert.equal(loadTrialConfig(y, {}).requiredPermission, 'READ_DATA');
  const j = path.join(base, 'trial.json');
  fs.writeFileSync(j, JSON.stringify(valid()));
  assert.equal(loadTrialConfig(j, {}).action, 'refund');
  assert.throws(() => loadTrialConfig(path.join(base, 'nope.yaml'), {}), TrialConfigError);
});
