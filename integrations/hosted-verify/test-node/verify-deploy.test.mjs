// scripts/lib/verify-deploy-core.mjs driven with canned responses: a fake Worker (in-memory
// registry, the real @bolyra/mpp for issuance and the binding digest) stands in for the
// deployment, so every leg — /health, the auth boundary, ABSENT → ACTIVE → REVOKED, and the
// cleanup decision table — is exercised without a network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { credentialId } from '../scripts/lib/credential-id.mjs';
import {
  AUDIENCE,
  BOGUS_TOKEN,
  MODEL,
  assessHealth,
  decideCleanup,
  parseCliArgs,
  parseWranglerVersion,
  runAuthBoundary,
  verifyDeploy,
} from '../scripts/lib/verify-deploy-core.mjs';

const require = createRequire(import.meta.url);
const mpp = require('@bolyra/mpp');

const URL_ = 'https://verify.example.test';
const ORG = 'canary-org';
const ADMIN = 'test-admin-token-aaaaaaaaaaaaaaaaaaaaaaaa';
const VERIFIER = 'test-verifier-token-bbbbbbbbbbbbbbbbbbbbb';
const VERSION = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
const SCALAR = 42n;

const makeIssuer = (scalar) => (agentName, expiry) =>
  mpp.issueMandate({ operatorPrivateKey: scalar, agentName, audience: AUDIENCE, model: MODEL, tier: 'small', expiry });

const OP = (await makeIssuer(SCALAR)('probe', Math.floor(Date.now() / 1000) + 3600)).operatorPublicKey;
const idOf = (binding) => credentialId({ x: BigInt(OP.x), y: BigInt(OP.y) }, mpp.bindingDigest(binding));

const HEALTHY = { status: 'ok', registry: 'ok', capability_map: 'ok', tenants: 'ok', registry_enforced: true, version: { id: VERSION, tag: '' } };

const timeoutError = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });

/**
 * A fake deployment. `registerMode`: 'normal' | 'commit-then-lose' (commits, then the response
 * is lost) | 'timeout-commit-later' (times out; the commit lands only when `commitLater()` runs)
 * | 'bad-request' (a parsed 400). `overrides` replaces whole routes' responses.
 */
function fakeWorker({ registerMode = 'normal', health = HEALTHY, overrides = {} } = {}) {
  const registry = new Map();
  const later = [];
  const calls = [];
  const json = (status, body, headers = {}) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const bearer = (init) => (init.headers?.authorization ?? '').replace(/^Bearer /, '');

  async function fetch(url, init = {}) {
    const u = new URL(url);
    const method = init.method ?? 'GET';
    calls.push(`${method} ${u.pathname}`);
    assert.ok(init.signal instanceof AbortSignal, `${method} ${u.pathname} has no timeout signal`);
    const key = `${method} ${u.pathname}`;
    if (overrides[key]) return overrides[key](init);
    if (key === 'GET /health') return json(200, health);
    if (key === 'POST /v1/verify') {
      if (bearer(init) !== VERIFIER) return json(401, { error: 'unauthorized' });
      const body = JSON.parse(init.body);
      const id = idOf(mpp.parseBundle(body.bundle).binding);
      if (registry.get(id) === 'ACTIVE') return json(200, { verdict: 'allow', kind: 'classical' }, { 'x-bolyra-credential-id': id });
      return json(200, { verdict: 'deny', kind: 'classical', code: 'untrusted_root', detail: { reason: 'credential_not_active', credential_id: id } });
    }
    if (key === 'POST /v1/credentials') {
      if (bearer(init) !== ADMIN) return json(401, { error: 'unauthorized' });
      const body = JSON.parse(init.body);
      assert.deepEqual(body.operator_pubkey, OP);
      const id = idOf(body.binding);
      switch (registerMode) {
        case 'normal':
          registry.set(id, 'ACTIVE');
          return json(201, { credential_id: id, status: 'ACTIVE' });
        case 'commit-then-lose':
          registry.set(id, 'ACTIVE');
          throw new TypeError('fetch failed');
        case 'timeout-commit-later':
          later.push(() => registry.set(id, 'ACTIVE'));
          throw timeoutError();
        case 'bad-request':
          return json(400, { error: 'binding_signature_invalid' });
      }
    }
    const m = /^\/v1\/credentials\/([0-9a-f]{64})(\/revoke)?$/.exec(u.pathname);
    if (m) {
      if (bearer(init) !== ADMIN) return json(401, { error: 'unauthorized' });
      if (m[2] && method === 'POST') {
        if (!registry.has(m[1])) return json(404, { error: 'not_found' });
        registry.set(m[1], 'REVOKED');
        return new Response(null, { status: 204 });
      }
      return json(404, { error: 'not_found' });
    }
    return json(404, { error: 'not_found' });
  }
  return { fetch, registry, calls, commitLater: () => later.splice(0).forEach((f) => f()) };
}

function memoryLog() {
  const lines = [];
  return {
    lines,
    append: (line) => lines.push(line),
    remove: (line) => {
      const i = lines.indexOf(line);
      if (i >= 0) lines.splice(i, 1);
    },
  };
}

function keychain(entries) {
  return (account) => (Object.hasOwn(entries, account) ? entries[account] : null);
}
const FULL_KEYCHAIN = {
  [`tenant-${ORG}-admin`]: ADMIN,
  [`tenant-${ORG}-verifier`]: VERIFIER,
  [`operator-${ORG}-scalar`]: '42',
};

async function run({ worker = fakeWorker(), args = [URL_, '--version', VERSION, '--tenant', ORG], secrets = FULL_KEYCHAIN, log = memoryLog(), wranglerOutput, sleeps = [] } = {}) {
  const out = [];
  const err = [];
  const code = await verifyDeploy(parseCliArgs(args), {
    fetch: worker.fetch,
    print: (l) => out.push(l),
    printErr: (l) => err.push(l),
    readSecret: keychain(secrets),
    devVarsSecrets: () => {
      throw new Error('not in these tests');
    },
    log,
    makeIssuer,
    now: () => Date.now(),
    wranglerOutput,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  return { code, out: out.join('\n'), err: err.join('\n'), log, worker, sleeps };
}

// ─── pure pieces ──────────────────────────────────────────────────────────────────────

test('parseWranglerVersion finds the Current Version ID (ANSI and surrounding noise tolerated)', () => {
  const text = `Total Upload: 812 KiB\n\x1b[32mUploaded\x1b[0m bolyra-hosted-verify (3.2 sec)\nDeployed bolyra-hosted-verify triggers (0.4 sec)\n  https://x.workers.dev\nCurrent Version ID: \x1b[1m${VERSION}\x1b[0m\n`;
  assert.equal(parseWranglerVersion(text), VERSION);
});

test('parseWranglerVersion returns null for a failed deploy (no version line)', () => {
  assert.equal(parseWranglerVersion(''), null);
  assert.equal(parseWranglerVersion('✘ [ERROR] A request to the Cloudflare API failed.\n'), null);
  assert.equal(parseWranglerVersion('Current Version ID: not-a-uuid\n'), null);
});

test('assessHealth: a healthy body with the expected version has no failures', () => {
  assert.deepEqual(assessHealth(HEALTHY, VERSION), []);
  assert.deepEqual(assessHealth(HEALTHY, null), []);
});

test('assessHealth: every required field fails on its own', () => {
  const cases = [
    ['status', 'degraded'],
    ['registry', 'timeout'],
    ['capability_map', 'invalid'],
    ['tenants', 'invalid'],
    ['registry_enforced', false],
  ];
  for (const [field, value] of cases) {
    const failures = assessHealth({ ...HEALTHY, [field]: value }, VERSION);
    assert.deepEqual(failures.map((f) => f.field), [field], field);
  }
  const missing = assessHealth({ ...HEALTHY, capability_map: undefined }, VERSION);
  assert.deepEqual(missing.map((f) => [f.field, f.observed]), [['capability_map', 'absent']]);
});

test('assessHealth: a version mismatch or a missing version fails when a version is expected', () => {
  assert.deepEqual(assessHealth({ ...HEALTHY, version: { id: 'aaaaaaaa-0000-0000-0000-000000000000' } }, VERSION).map((f) => f.field), ['version.id']);
  assert.deepEqual(assessHealth({ ...HEALTHY, version: null }, VERSION).map((f) => f.field), ['version.id']);
  assert.deepEqual(assessHealth('not an object', null).map((f) => f.field), ['body']);
});

test('assessHealth never echoes an unexpected string value', () => {
  const failures = assessHealth({ ...HEALTHY, status: 'Bearer secret-ish', version: { id: 'x y z' } }, VERSION);
  for (const f of failures) assert.doesNotMatch(f.observed, /secret-ish|x y z/);
});

test('decideCleanup: the decision table', () => {
  assert.equal(decideCleanup({ registration: 'committed', revokeStatus: 204 }), 'cleaned');
  assert.equal(decideCleanup({ registration: 'indeterminate', revokeStatus: 204 }), 'cleaned');
  assert.equal(decideCleanup({ registration: 'not_committed', revokeStatus: 204 }), 'cleaned');
  assert.equal(decideCleanup({ registration: 'not_committed', revokeStatus: 404 }), 'nothing_committed');
  assert.equal(decideCleanup({ registration: 'indeterminate', revokeStatus: 404 }), 'unconfirmed');
  assert.equal(decideCleanup({ registration: 'committed', revokeStatus: 404 }), 'unconfirmed');
  assert.equal(decideCleanup({ registration: 'committed', revokeStatus: 500 }), 'unconfirmed');
  assert.equal(decideCleanup({ registration: 'not_committed', revokeStatus: 'network_error' }), 'unconfirmed');
});

test('parseCliArgs: --version and --from-wrangler are exclusive; env selects the keychain service', () => {
  assert.throws(() => parseCliArgs([URL_, '--version', VERSION, '--from-wrangler']), /exclusive/);
  assert.equal(parseCliArgs([URL_]).env, 'production');
  assert.equal(parseCliArgs([URL_]).keychainService, 'bolyra-hosted-verify');
  assert.equal(parseCliArgs([URL_, '--env', 'staging']).keychainService, 'bolyra-hosted-verify-staging');
  assert.throws(() => parseCliArgs([URL_, '--env', 'prod']), /--env/);
  assert.throws(() => parseCliArgs(['http://verify.example.test']), /https/);
  assert.throws(() => parseCliArgs([]), /usage/i);
});

test('parseCliArgs: the URL falls back to VERIFY_URL (with-worker.sh exports it); a positional wins', () => {
  assert.equal(parseCliArgs(['--env', 'local'], { fallbackUrl: 'http://127.0.0.1:8787' }).url, 'http://127.0.0.1:8787');
  assert.equal(parseCliArgs([URL_], { fallbackUrl: 'http://127.0.0.1:8787' }).url, URL_);
  assert.throws(() => parseCliArgs(['--env', 'local'], {}), /usage/i);
  assert.throws(() => parseCliArgs(['--env', 'local'], { fallbackUrl: '' }), /usage/i);
});

test('parseCliArgs: --secrets-from-dev-vars is refused for production and staging', () => {
  assert.throws(() => parseCliArgs([URL_, '--env', 'production', '--tenant', 'local', '--secrets-from-dev-vars']), /local only/);
  assert.throws(() => parseCliArgs([URL_, '--env', 'staging', '--tenant', 'local', '--secrets-from-dev-vars']), /local only/);
  assert.throws(() => parseCliArgs(['http://127.0.0.1:8787', '--env', 'local', '--secrets-from-dev-vars']), /--tenant/);
  assert.equal(parseCliArgs(['http://127.0.0.1:8787', '--env', 'local', '--tenant', 'local', '--secrets-from-dev-vars']).secretsFromDevVars, true);
  assert.throws(() => parseCliArgs(['https://remote.example.test', '--env', 'local']), /loopback/);
});

// ─── auth boundary ────────────────────────────────────────────────────────────────────

test('runAuthBoundary: /health plus the three 401s pass against a healthy deployment', async () => {
  const worker = fakeWorker();
  const lines = [];
  const ok = await runAuthBoundary({ fetch: worker.fetch, url: URL_, expectedVersion: VERSION, print: (l) => lines.push(l) });
  assert.equal(ok, true, lines.join('\n'));
  assert.deepEqual(worker.calls, ['GET /health', 'POST /v1/verify', 'POST /v1/verify', `GET /v1/credentials/${'0'.repeat(64)}`]);
  assert.equal(lines.filter((l) => l.includes('FAIL')).length, 0);
});

test('runAuthBoundary: a bogus token that is accepted fails the leg', async () => {
  const worker = fakeWorker({ overrides: { 'POST /v1/verify': () => new Response('{"verdict":"deny"}', { status: 200 }) } });
  const lines = [];
  const ok = await runAuthBoundary({ fetch: worker.fetch, url: URL_, expectedVersion: null, print: (l) => lines.push(l) });
  assert.equal(ok, false);
  assert.equal(lines.filter((l) => l.includes('FAIL')).length, 2, lines.join('\n'));
  assert.ok(!lines.join('\n').includes(BOGUS_TOKEN), 'the bogus token itself is not printed');
});

test('runAuthBoundary: a degraded 503 /health fails and names the component', async () => {
  const worker = fakeWorker({ overrides: { 'GET /health': () => new Response(JSON.stringify({ ...HEALTHY, status: 'degraded', registry: 'timeout' }), { status: 503 }) } });
  const lines = [];
  assert.equal(await runAuthBoundary({ fetch: worker.fetch, url: URL_, expectedVersion: VERSION, print: (l) => lines.push(l) }), false);
  assert.match(lines.join('\n'), /registry.*timeout/);
});

// ─── whole runs ───────────────────────────────────────────────────────────────────────

test('--from-wrangler with no version id fails before any request', async () => {
  const worker = fakeWorker();
  const r = await run({ worker, args: [URL_, '--from-wrangler', '--tenant', ORG], wranglerOutput: '✘ [ERROR] deploy failed\n' });
  assert.equal(r.code, 1);
  assert.match(r.err, /Current Version ID/);
  assert.deepEqual(worker.calls, []);
});

test('--from-wrangler checks /health against the parsed version id', async () => {
  const r = await run({ args: [URL_, '--from-wrangler', '--tenant', ORG], wranglerOutput: `Current Version ID: ${VERSION}\n` });
  assert.equal(r.code, 0, r.out + r.err);
  const stale = await run({ args: [URL_, '--from-wrangler', '--tenant', ORG], wranglerOutput: 'Current Version ID: 11111111-2222-3333-4444-555555555555\n' });
  assert.equal(stale.code, 1);
});

test('behavioral happy path: ABSENT → ACTIVE → REVOKED on one derived id, cleaned, nothing secret printed', async () => {
  const r = await run();
  assert.equal(r.code, 0, r.out + r.err);
  const ids = new Set(r.out.match(/[0-9a-f]{64}/g));
  ids.delete('0'.repeat(64));
  assert.equal(ids.size, 1, `exactly one canary id is printed: ${[...ids]}`);
  const [id] = ids;
  assert.equal(r.worker.registry.get(id), 'REVOKED');
  for (const step of ['ABSENT', 'ACTIVE', 'REVOKED']) assert.match(r.out, new RegExp(`ok .*${step}`), step);
  assert.match(r.out, /cleanup: cleaned/);
  assert.equal(r.log.lines.length, 0, 'the pending entry is removed');
  assert.doesNotMatch(r.out + r.err, /FAIL/);
  for (const secret of [ADMIN, VERIFIER, BOGUS_TOKEN]) assert.ok(!(r.out + r.err).includes(secret));
  // the registration is posted only after the pending entry exists
  assert.ok(r.worker.calls.indexOf('POST /v1/credentials') > r.worker.calls.indexOf('GET /health'));
});

test('the pending entry is written BEFORE the registration request', async () => {
  const log = memoryLog();
  let seenAtRegistration = null;
  const base = fakeWorker();
  const worker = {
    ...base,
    fetch: (url, init = {}) => {
      if ((init.method ?? 'GET') === 'POST' && new URL(url).pathname === '/v1/credentials') seenAtRegistration = [...log.lines];
      return base.fetch(url, init);
    },
  };
  const r = await run({ worker, log });
  assert.equal(r.code, 0, r.out + r.err);
  assert.equal(seenAtRegistration.length, 1);
  assert.match(seenAtRegistration[0], new RegExp(`^\\d{4}-\\d\\d-\\d\\dT\\S+Z production ${ORG} [0-9a-f]{64} pending$`));
});

test('(a) registration commits but its response is lost → cleanup revokes (cleaned), still exits non-zero', async () => {
  const worker = fakeWorker({ registerMode: 'commit-then-lose' });
  const r = await run({ worker });
  assert.equal(r.code, 1);
  assert.match(r.out, /cleanup: cleaned/);
  assert.equal(r.log.lines.length, 0);
  const [id] = [...worker.registry.keys()];
  assert.equal(worker.registry.get(id), 'REVOKED');
  assert.match(r.out, /FAIL .*ACTIVE/);
  assert.doesNotMatch(r.err, /UNCONFIRMED/);
});

test('(b) registration times out, cleanup sees 404, the commit lands later → unconfirmed, entry KEPT', async () => {
  const worker = fakeWorker({ registerMode: 'timeout-commit-later' });
  const r = await run({ worker });
  assert.equal(r.code, 1);
  assert.equal(r.log.lines.length, 1, 'the pending entry is kept');
  const id = r.log.lines[0].split(' ')[3];
  assert.match(r.err, new RegExp(`CANARY CLEANUP UNCONFIRMED credential_id=${id}`));
  assert.match(r.out, /FAIL present registered → ACTIVE: not observed: the registration was not confirmed/);
  worker.commitLater();
  assert.equal(worker.registry.get(id), 'ACTIVE', 'why the entry must be kept: the registration committed after the cleanup');
});

test('(c) registration answers a parsed 400 → cleanup 404 → nothing_committed, entry removed', async () => {
  const r = await run({ worker: fakeWorker({ registerMode: 'bad-request' }) });
  assert.equal(r.code, 1);
  assert.match(r.out, /cleanup: nothing_committed/);
  assert.equal(r.log.lines.length, 0);
  assert.doesNotMatch(r.err, /UNCONFIRMED/);
});

test('a revoke that network-fails during cleanup → unconfirmed, entry kept', async () => {
  let revokes = 0;
  const base = fakeWorker();
  const worker = {
    ...base,
    fetch: (url, init = {}) => {
      if (/\/revoke$/.test(new URL(url).pathname) && ++revokes === 2) return Promise.reject(new TypeError('fetch failed'));
      return base.fetch(url, init);
    },
  };
  const r = await run({ worker });
  assert.equal(r.code, 1);
  assert.equal(r.log.lines.length, 1);
  assert.match(r.err, /CANARY CLEANUP UNCONFIRMED/);
});

test('a history_write_failed revoke is reported but does not fail the REVOKED check', async () => {
  const base = fakeWorker();
  const worker = {
    ...base,
    fetch: async (url, init = {}) => {
      const res = await base.fetch(url, init);
      if (/\/revoke$/.test(new URL(url).pathname) && res.status === 204) return new Response(null, { status: 204, headers: { 'x-bolyra-audit': 'history_write_failed' } });
      return res;
    },
  };
  const r = await run({ worker });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /x-bolyra-audit history_write_failed/);
});

test('missing keychain entry → non-zero, naming the missing account', async () => {
  const { [`tenant-${ORG}-verifier`]: _v, ...partial } = FULL_KEYCHAIN;
  const worker = fakeWorker();
  const r = await run({ worker, secrets: partial });
  assert.equal(r.code, 1);
  assert.match(r.err, new RegExp(`tenant-${ORG}-verifier`));
  assert.ok(!worker.calls.includes('POST /v1/credentials'));
});

test('missing keychain entries with --allow-missing-tenant → skip message, exit 0 after the auth-boundary leg', async () => {
  const worker = fakeWorker();
  const r = await run({ worker, secrets: {}, args: [URL_, '--version', VERSION, '--tenant', ORG, '--allow-missing-tenant'] });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, new RegExp(`enforcement NOT verified on this target \\(tenant ${ORG} has no keychain entries\\)`));
  assert.ok(worker.calls.includes('GET /health'));
  assert.ok(!worker.calls.includes('POST /v1/credentials'));
});

test('--allow-missing-tenant does not rescue a failing auth-boundary leg', async () => {
  const worker = fakeWorker({ health: { ...HEALTHY, registry_enforced: false } });
  const r = await run({ worker, secrets: {}, args: [URL_, '--version', VERSION, '--tenant', ORG, '--allow-missing-tenant'] });
  assert.equal(r.code, 1);
});

test('a malformed operator scalar is refused without echoing it', async () => {
  const r = await run({ secrets: { ...FULL_KEYCHAIN, [`operator-${ORG}-scalar`]: 'not-a-number-SECRETISH' } });
  assert.equal(r.code, 1);
  assert.match(r.err, new RegExp(`operator-${ORG}-scalar`));
  assert.ok(!(r.out + r.err).includes('SECRETISH'));
});

test('a 0x-hex operator scalar is accepted', async () => {
  const r = await run({ secrets: { ...FULL_KEYCHAIN, [`operator-${ORG}-scalar`]: '0x2a' } });
  assert.equal(r.code, 0, r.out + r.err);
});

// ─── version propagation wait ─────────────────────────────────────────────────────────

/** A /health that reports the old version until the `matchOn`-th request (Infinity: never). */
function propagating(matchOn) {
  let n = 0;
  return fakeWorker({
    overrides: {
      'GET /health': () => {
        n++;
        const id = n >= matchOn ? VERSION : 'aaaaaaaa-0000-0000-0000-000000000000';
        return new Response(JSON.stringify({ ...HEALTHY, version: { id } }), { status: 200 });
      },
    },
  });
}
const healthCalls = (worker) => worker.calls.filter((c) => c === 'GET /health').length;

test('version wait: a version already live → no wait', async () => {
  const r = await run({ worker: propagating(1) });
  assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(r.sleeps, []);
  assert.doesNotMatch(r.out, /waiting for version/);
});

test('version wait: the version appears on the 3rd poll → 2 waits of 5 s, then both legs run', async () => {
  const worker = propagating(3);
  const r = await run({ worker });
  assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(r.sleeps, [5000, 5000]);
  assert.match(r.out, new RegExp(`--  waiting for version ${VERSION} \\(1/12\\)`));
  assert.match(r.out, new RegExp(`--  waiting for version ${VERSION} \\(2/12\\)`));
  assert.ok(worker.calls.includes('POST /v1/credentials'));
});

test('version wait: never live → fails after 12 polls, no behavioral leg, no pending entry', async () => {
  const worker = propagating(Infinity);
  const log = memoryLog();
  let appended = 0;
  const r = await run({ worker, log: { ...log, append: (l) => (appended++, log.append(l)) } });
  assert.equal(r.code, 1);
  assert.equal(r.sleeps.length, 11, 'twelve polls, eleven 5 s waits');
  assert.equal(healthCalls(worker), 13, 'twelve polls, then the auth leg reports the mismatch');
  assert.match(r.out, /FAIL \/health version\.id: aaaaaaaa-0000-0000-0000-000000000000 \(expected /);
  assert.ok(!worker.calls.includes('POST /v1/credentials'));
  assert.doesNotMatch(r.out, /behavioral \(tenant/);
  assert.equal(appended, 0);
});

test('version wait: no expected version → no polling', async () => {
  const worker = propagating(Infinity);
  const r = await run({ worker, args: [URL_, '--tenant', ORG] });
  assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(r.sleeps, []);
  assert.equal(healthCalls(worker), 1);
});
