/**
 * Post-deploy verification of a hosted-verify Worker (backlog E14) — the testable core.
 * scripts/verify-deploy.mjs wires it to real `fetch`, the macOS keychain, the pending log
 * file, and @bolyra/mpp; test-node/verify-deploy.test.mjs drives it with canned responses.
 *
 * Two legs:
 *   auth boundary (always) — /health is 200 and every component "ok", registry_enforced,
 *     the expected version id; /v1/verify refuses no token and a bogus token (401); a
 *     credential read refuses no token (401).
 *   behavioral (with a tenant) — a fresh operator-signed canary binding is presented
 *     unregistered (deny credential_not_active: ABSENT), registered (201), presented (allow:
 *     ACTIVE), revoked (204), presented again (deny credential_not_active: REVOKED), and
 *     revoked again in cleanup, whatever happened in between.
 *
 * Printing: status codes, closed enums (`verdict`, `code`, `detail.reason`, the /health
 * component states), 64-hex credential ids and the version id. Never a response body, a
 * token, or the operator scalar; anything outside the allowlist prints as withheld.
 */
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { parseArgs } from 'node:util';
import { credentialId } from './credential-id.mjs';

const require = createRequire(import.meta.url);
const { bindingDigest, parseBundle, tierCapability } = require('@bolyra/mpp');

/** The example's request vocabulary (examples/managed-revocation/src/server.ts). */
export const AUDIENCE = 'api.merchant.example';
export const MODEL = 'opus-4.1';
export const REQUEST_TIMEOUT_MS = 15_000;
/** Version propagation: poll /health every 5 s, at most 12 times (~60 s). */
export const VERSION_POLL_INTERVAL_MS = 5_000;
export const VERSION_POLLS = 12;
/** Well-formed (TOKEN_PATTERN) and never issued: it must be refused like no token. */
export const BOGUS_TOKEN = 'bogus-token-000000000000000000000000';
const ZERO_ID = '0'.repeat(64);

/** `--env` → keychain service (mirrors pilot/tenant.sh). `local` is `wrangler dev` only. */
export const ENVIRONMENTS = {
  production: 'bolyra-hosted-verify',
  staging: 'bolyra-hosted-verify-staging',
  local: 'bolyra-hosted-verify-local',
};

const ORG_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/; // src/tenants.ts
const TOKEN_PATTERN = /^[A-Za-z0-9._~+/-]{32,256}$/; // src/tenants.ts
const ID_PATTERN = /^[0-9a-f]{64}$/;
const VERSION_PATTERN = /^[A-Za-z0-9-]{1,64}$/;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

const VERDICTS = ['allow', 'deny'];
const DENY_CODES = [
  'missing_authorization', 'malformed_input', 'unsupported_version', 'invalid_bundle', 'invalid_proof',
  'invalid_signature', 'untrusted_root', 'delegation_invalid', 'request_mismatch', 'model_mismatch',
  'unknown_capability', 'scope_exceeded', 'expired', 'nonce_missing', 'nonce_replayed', 'internal_error',
];
const REASONS = ['credential_not_active'];
const AUDIT = ['history_write_failed', 'history_conflict'];
const HEALTH_FIELDS = {
  status: ['ok', 'degraded'],
  registry: ['ok', 'unavailable', 'timeout'],
  capability_map: ['ok', 'invalid'],
  tenants: ['ok', 'invalid'],
};

/** An error whose message is ours (an account name, a route, a status) and so printable. */
export class DiagnosticError extends Error {
  name = 'DiagnosticError';
}

/** Show `value` only when it is allowlisted; booleans, numbers and absence as such. */
function shown(value, allowed) {
  if (value === undefined || value === null) return 'absent';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  return typeof value === 'string' && allowed.includes(value) ? value : '<withheld>';
}

function sameId(value, id) {
  if (value === undefined || value === null) return 'absent';
  if (value === id) return 'the canary id';
  return typeof value === 'string' && ID_PATTERN.test(value) ? `a DIFFERENT id ${value}` : '<withheld>';
}

// ─── CLI arguments ────────────────────────────────────────────────────────────────────

const USAGE =
  'usage: node scripts/verify-deploy.mjs <url> [--version <id> | --from-wrangler] [--env production|staging|local] ' +
  '[--tenant <org>] [--allow-missing-tenant] [--pending-log <path>] [--secrets-from-dev-vars (local only)]';

/** @param {{ fallbackUrl?: string }} [defaults] fallbackUrl: VERIFY_URL (scripts/with-worker.sh exports it) */
export function parseCliArgs(argv, { fallbackUrl } = {}) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        version: { type: 'string' },
        'from-wrangler': { type: 'boolean', default: false },
        env: { type: 'string', default: 'production' },
        tenant: { type: 'string' },
        'allow-missing-tenant': { type: 'boolean', default: false },
        'secrets-from-dev-vars': { type: 'boolean', default: false },
        'pending-log': { type: 'string' },
      },
    });
  } catch (e) {
    throw new DiagnosticError(`${e instanceof Error ? e.message : 'bad arguments'}\n${USAGE}`);
  }
  const { values: v, positionals } = parsed;
  if (positionals.length > 1) throw new DiagnosticError(USAGE);
  const rawUrl = positionals[0] ?? (fallbackUrl || undefined);
  if (rawUrl === undefined) throw new DiagnosticError(`${USAGE}\n(no <url>, and VERIFY_URL is not set)`);
  if (!Object.hasOwn(ENVIRONMENTS, v.env)) throw new DiagnosticError(`--env must be production, staging or local\n${USAGE}`);
  if (v.version !== undefined && v['from-wrangler']) throw new DiagnosticError('--version and --from-wrangler are mutually exclusive');
  if (v.version !== undefined && !VERSION_PATTERN.test(v.version)) throw new DiagnosticError('--version must match ^[A-Za-z0-9-]{1,64}$');
  if (v.tenant !== undefined && !ORG_ID_PATTERN.test(v.tenant)) throw new DiagnosticError('--tenant must be an org id (^[a-z0-9][a-z0-9-]{1,62}$)');
  if (v['secrets-from-dev-vars']) {
    if (v.env !== 'local') throw new DiagnosticError('--secrets-from-dev-vars is for --env local only (wrangler dev placeholders); refused for production and staging');
    if (v.tenant === undefined) throw new DiagnosticError('--secrets-from-dev-vars needs --tenant');
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new DiagnosticError(`not a URL: the first argument\n${USAGE}`);
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '' || (url.pathname !== '/' && url.pathname !== '')) {
    throw new DiagnosticError('the URL must be a bare origin (no path, query, fragment, or credentials)');
  }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (v.env === 'local') {
    if (!loopback) throw new DiagnosticError('--env local targets a loopback wrangler dev only');
  } else if (url.protocol !== 'https:') {
    throw new DiagnosticError(`--env ${v.env} needs an https URL (tokens are sent)`);
  }

  return {
    url: url.origin,
    version: v.version ?? null,
    fromWrangler: v['from-wrangler'],
    env: v.env,
    keychainService: ENVIRONMENTS[v.env],
    tenant: v.tenant ?? null,
    allowMissingTenant: v['allow-missing-tenant'],
    secretsFromDevVars: v['secrets-from-dev-vars'],
    pendingLog: v['pending-log'] ?? null,
  };
}

/** The `Current Version ID: <uuid>` of `wrangler deploy` output, or null (a failed deploy prints none). */
export function parseWranglerVersion(text) {
  // eslint-disable-next-line no-control-regex
  const plain = String(text).replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');
  let found = null;
  for (const m of plain.matchAll(/Current Version ID:\s*(\S+)/g)) {
    found = UUID.test(m[1]) && m[1].match(UUID)[0] === m[1] ? m[1] : null;
  }
  return found;
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────────────

/** A request that did not produce a readable response: `kind` is 'timeout' or 'network_error'. */
class RequestError extends Error {
  constructor(kind) {
    super(kind);
    this.kind = kind;
  }
}

/** One request under its own deadline; the body is parsed as JSON (null when it is not). */
async function call(fetch, url, path, init, timeoutMs) {
  try {
    const res = await fetch(`${url}${path}`, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    const text = await res.text();
    let body = null;
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) body = parsed;
    } catch {
      /* not JSON */
    }
    return { status: res.status, headers: res.headers, body };
  } catch (e) {
    throw new RequestError(e?.name === 'TimeoutError' || e?.name === 'AbortError' ? 'timeout' : 'network_error');
  }
}

function checker(print) {
  let failed = 0;
  return {
    check(step, ok, expected, observed) {
      print(`${ok ? '  ok ' : ' FAIL'} ${step}: ${observed}${ok ? '' : ` (expected ${expected})`}`);
      if (!ok) failed++;
      return ok;
    },
    get failed() {
      return failed;
    },
  };
}

// ─── auth-boundary leg ────────────────────────────────────────────────────────────────

/** Every /health failure as { field, expected, observed } (observed is allowlisted). */
export function assessHealth(body, expectedVersion) {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return [{ field: 'body', expected: 'a JSON object', observed: 'not a JSON object' }];
  }
  const failures = [];
  for (const [field, allowed] of Object.entries(HEALTH_FIELDS)) {
    if (body[field] !== 'ok') failures.push({ field, expected: 'ok', observed: shown(body[field], allowed) });
  }
  if (body.registry_enforced !== true) {
    failures.push({ field: 'registry_enforced', expected: 'true', observed: shown(body.registry_enforced, []) });
  }
  if (expectedVersion !== null) {
    const id = body.version?.id;
    if (id !== expectedVersion) {
      const observed = id === undefined || id === null ? 'absent' : typeof id === 'string' && VERSION_PATTERN.test(id) ? id : '<withheld>';
      failures.push({ field: 'version.id', expected: expectedVersion, observed });
    }
  }
  return failures;
}

export async function runAuthBoundary({ fetch, url, expectedVersion, print, timeoutMs = REQUEST_TIMEOUT_MS }) {
  const c = checker(print);
  const attempt = async (step, path, init, expectStatus) => {
    try {
      return await call(fetch, url, path, init, timeoutMs);
    } catch (e) {
      c.check(step, false, String(expectStatus), e instanceof RequestError ? e.kind : 'request failed');
      return null;
    }
  };

  const h = await attempt('GET /health', '/health', { method: 'GET' }, 200);
  if (h !== null) {
    c.check('GET /health', h.status === 200, '200', String(h.status));
    const failures = assessHealth(h.body, expectedVersion);
    const fields = ['status', 'registry', 'capability_map', 'tenants', 'registry_enforced', ...(expectedVersion !== null ? ['version.id'] : [])];
    for (const field of fields) {
      const f = failures.find((x) => x.field === field);
      c.check(`/health ${field}`, f === undefined, f?.expected ?? '', f === undefined ? (field === 'version.id' ? expectedVersion : field === 'registry_enforced' ? 'true' : 'ok') : f.observed);
    }
    const bodyFailure = failures.find((x) => x.field === 'body');
    if (bodyFailure) c.check('/health body', false, bodyFailure.expected, bodyFailure.observed);
    if (expectedVersion === null) print('  --  /health version.id not checked (no --version / --from-wrangler)');
  }

  const probe = JSON.stringify({ version: 1 });
  const json = { 'content-type': 'application/json' };
  for (const [step, headers] of [
    ['POST /v1/verify without a token', json],
    ['POST /v1/verify with a bogus token', { ...json, authorization: `Bearer ${BOGUS_TOKEN}` }],
  ]) {
    const r = await attempt(step, '/v1/verify', { method: 'POST', headers, body: probe }, 401);
    if (r !== null) c.check(step, r.status === 401, '401', String(r.status));
  }
  const step = 'GET /v1/credentials/{64 zeros} without a token';
  const r = await attempt(step, `/v1/credentials/${ZERO_ID}`, { method: 'GET' }, 401);
  if (r !== null) c.check(step, r.status === 401, '401', String(r.status));

  return c.failed === 0;
}

/**
 * Wait for a fresh deploy to propagate: poll /health until `version.id` is `expected`,
 * every VERSION_POLL_INTERVAL_MS, at most VERSION_POLLS times. Mid-propagation /health and
 * /v1/verify may be served by different isolates, so a match means "at least one isolate
 * reports this version", not that every isolate runs it.
 * @returns {Promise<boolean>} whether the version was seen
 */
export async function waitForVersion({ fetch, url, expected, print, sleep, timeoutMs = REQUEST_TIMEOUT_MS }) {
  for (let n = 1; n <= VERSION_POLLS; n++) {
    try {
      const r = await call(fetch, url, '/health', { method: 'GET' }, timeoutMs);
      if (r.body?.version?.id === expected) return true;
    } catch {
      /* not reachable yet: keep polling */
    }
    if (n < VERSION_POLLS) {
      print(`  --  waiting for version ${expected} (${n}/${VERSION_POLLS})`);
      await sleep(VERSION_POLL_INTERVAL_MS);
    }
  }
  return false;
}

// ─── behavioral leg ───────────────────────────────────────────────────────────────────

/**
 * What to do with a canary id after the cleanup revoke.
 *   204                                  → cleaned: remove the pending entry
 *   404 after a parsed 4xx registration  → nothing_committed: remove it
 *   404 after an unobserved registration → unconfirmed: it may still commit — keep it
 *   anything else                        → unconfirmed: keep it
 * registration: 'committed' (a 2xx naming the id was parsed) | 'not_committed' (a parsed
 * 4xx) | 'indeterminate' (timeout, network error, 5xx, unparseable).
 */
export function decideCleanup({ registration, revokeStatus }) {
  if (revokeStatus === 204) return 'cleaned';
  if (revokeStatus === 404 && registration === 'not_committed') return 'nothing_committed';
  return 'unconfirmed';
}

/** The registration body — the signed binding lifted from a presentation (examples/…/verifier.ts `registrationOf`). */
export function registrationOf(mandate) {
  const p = parseBundle(mandate.presentation);
  return {
    version: 1,
    binding: p.binding,
    signature: { R8: { x: p.sig.R8.x, y: p.sig.R8.y }, S: p.sig.S },
    operator_pubkey: mandate.operatorPublicKey,
  };
}

/** The /v1/verify body the gate sends (examples/…/verifier.ts `verify`). */
function verifyBody(mandate, nowMs) {
  return {
    version: 1,
    bundle: mandate.presentation,
    request: {
      agent_name: mandate.agentName,
      project_key: mandate.audience,
      program: mandate.program,
      model: mandate.model,
      granted_capabilities: [tierCapability(mandate.tier)],
    },
    now_unix: Math.floor(nowMs / 1000),
  };
}

/**
 * @param {object} o
 * @param {typeof fetch} o.fetch
 * @param {string} o.url
 * @param {string} o.env
 * @param {string} o.org
 * @param {{ adminToken: string, verifierToken: string }} o.secrets
 * @param {{ append(line: string): void, remove(line: string): void }} o.log the pending log
 * @param {(agentName: string, expiry: number) => Promise<import('@bolyra/mpp').IssuedMandate>} o.issue
 * @param {() => number} o.now epoch ms
 * @returns {Promise<boolean>} every check passed and cleanup is confirmed
 */
export async function runBehavioral({ fetch, url, env, org, secrets, log, issue, now, print, printErr, random, timeoutMs = REQUEST_TIMEOUT_MS }) {
  const c = checker(print);
  const admin = { authorization: `Bearer ${secrets.adminToken}` };
  const verifier = { authorization: `Bearer ${secrets.verifierToken}`, 'content-type': 'application/json' };
  const agent = `verify-deploy-${random ? random() : randomBytes(4).toString('hex')}`;
  const expiry = Math.floor(now() / 1000) + 3600;

  // Derive the id BEFORE any request, and record it before the registration can commit.
  let first;
  try {
    first = await issue(agent, expiry);
  } catch {
    c.check('issue the canary mandate', false, 'a mandate', 'issueMandate threw (details withheld)');
    return false;
  }
  const registration = registrationOf(first);
  const id = credentialId(
    { x: BigInt(registration.operator_pubkey.x), y: BigInt(registration.operator_pubkey.y) },
    bindingDigest(registration.binding),
  );
  print(`  --  canary ${agent}: credential_id=${id}`);
  const targets = [{ id, line: `${new Date(now()).toISOString()} ${env} ${org} ${id} pending`, registration: 'not_attempted' }];
  log.append(targets[0].line);

  const present = async (step, expect) => {
    try {
      const m = await issue(agent, expiry); // a fresh presentation of the same signed binding
      const r = await call(fetch, url, '/v1/verify', { method: 'POST', headers: verifier, body: JSON.stringify(verifyBody(m, now())) }, timeoutMs);
      expect(r);
    } catch (e) {
      c.check(step, false, 'a verdict', e instanceof RequestError ? e.kind : 'request failed (details withheld)');
    }
  };
  const expectDeny = (step) => (r) => {
    const d = typeof r.body?.detail === 'object' && r.body.detail !== null ? r.body.detail : {};
    c.check(
      step,
      r.status === 200 && r.body?.verdict === 'deny' && r.body?.code === 'untrusted_root' && d.reason === 'credential_not_active' && d.credential_id === id,
      '200 deny untrusted_root credential_not_active, detail.credential_id = the canary id',
      `${r.status} ${shown(r.body?.verdict, VERDICTS)} ${shown(r.body?.code, DENY_CODES)} ${shown(d.reason, REASONS)}, detail.credential_id ${sameId(d.credential_id, id)}`,
    );
  };

  let cleanupOk = true;
  try {
    await present('present unregistered → ABSENT', expectDeny('present unregistered → ABSENT'));

    targets[0].registration = 'indeterminate';
    const step = 'POST /v1/credentials';
    try {
      const r = await call(fetch, url, '/v1/credentials', { method: 'POST', headers: { ...admin, 'content-type': 'application/json' }, body: JSON.stringify(registration) }, timeoutMs);
      const returned = r.body?.credential_id;
      if ((r.status === 201 || r.status === 200) && typeof returned === 'string' && ID_PATTERN.test(returned)) {
        if (returned === id) {
          targets[0].registration = 'committed';
        } else {
          // The Worker committed under an id we did not derive: track that one too.
          targets[0].registration = 'not_committed';
          const extra = { id: returned, line: `${new Date(now()).toISOString()} ${env} ${org} ${returned} pending`, registration: 'committed' };
          log.append(extra.line);
          targets.push(extra);
        }
      } else if (r.status >= 400 && r.status < 500 && typeof r.body?.error === 'string') {
        targets[0].registration = 'not_committed';
      }
      c.check(step, r.status === 201 && returned === id, '201, credential_id = the canary id', `${r.status}, credential_id ${sameId(returned, id)}`);
    } catch (e) {
      c.check(step, false, '201, credential_id = the canary id', e instanceof RequestError ? e.kind : 'request failed');
    }

    if (targets[0].registration === 'committed') {
      await present('present registered → ACTIVE', (r) => {
        const header = r.headers.get('x-bolyra-credential-id');
        c.check(
          'present registered → ACTIVE',
          r.status === 200 && r.body?.verdict === 'allow' && header === id,
          '200 allow, x-bolyra-credential-id = the canary id',
          `${r.status} ${shown(r.body?.verdict, VERDICTS)}${r.body?.verdict === 'deny' ? ` ${shown(r.body?.code, DENY_CODES)}` : ''}, x-bolyra-credential-id ${sameId(header, id)}`,
        );
      });
      const rstep = `POST /v1/credentials/${id}/revoke`;
      try {
        const r = await call(fetch, url, `/v1/credentials/${id}/revoke`, { method: 'POST', headers: admin }, timeoutMs);
        const audit = r.headers.get('x-bolyra-audit');
        c.check(rstep, r.status === 204, '204', `${r.status}, x-bolyra-audit ${shown(audit, AUDIT)}`);
        if (audit === 'history_write_failed') {
          print(`  --  the revocation's audit row is owed (x-bolyra-audit history_write_failed): run repair-history for ${id} (pilot/RUNBOOK.md §3); not a failure of this check`);
        }
      } catch (e) {
        c.check(rstep, false, '204', e instanceof RequestError ? e.kind : 'request failed');
      }
      await present('present revoked → REVOKED', expectDeny('present revoked → REVOKED'));
    } else {
      c.check('present registered → ACTIVE', false, '200 allow', 'not observed: the registration was not confirmed');
      c.check('present revoked → REVOKED', false, '200 deny credential_not_active', 'not observed: the registration was not confirmed');
    }
  } finally {
    // Cleanup after ANY registration attempt: revoke is idempotent (204 for ACTIVE or REVOKED).
    for (const t of targets) {
      if (t.registration === 'not_attempted') {
        log.remove(t.line); // nothing was sent that could commit
        continue;
      }
      let revokeStatus;
      try {
        revokeStatus = (await call(fetch, url, `/v1/credentials/${t.id}/revoke`, { method: 'POST', headers: admin }, timeoutMs)).status;
      } catch {
        revokeStatus = 'network_error';
      }
      const decision = decideCleanup({ registration: t.registration, revokeStatus });
      const ok = decision !== 'unconfirmed';
      c.check(`cleanup credential_id=${t.id}`, ok, 'cleaned or nothing_committed', `cleanup: ${decision} (revoke → ${revokeStatus})`);
      if (ok) {
        log.remove(t.line);
      } else {
        cleanupOk = false;
        printErr(`CANARY CLEANUP UNCONFIRMED credential_id=${t.id} — kept in the pending log; clear it by hand (pilot/RUNBOOK.md, post-deploy verification)`);
      }
    }
  }
  return c.failed === 0 && cleanupOk;
}

// ─── the whole run ────────────────────────────────────────────────────────────────────

/** A keychain value that must be a bearer token; the value is never echoed. */
function tokenFrom(value, account) {
  if (!TOKEN_PATTERN.test(value)) throw new DiagnosticError(`keychain account ${account} does not hold a token of the Worker's shape (value withheld)`);
  return value;
}

/** Decimal or 0x-hex, positive. */
export function parseScalar(value, account) {
  const v = String(value).trim();
  if (/^[0-9]{1,80}$/.test(v) || /^0x[0-9a-fA-F]{1,64}$/.test(v)) {
    const n = BigInt(v);
    if (n > 0n) return n;
  }
  throw new DiagnosticError(`keychain account ${account} is not a positive decimal or 0x-hex scalar (value withheld)`);
}

/**
 * @param {ReturnType<typeof parseCliArgs>} opts
 * @param {object} deps
 * @param {typeof fetch} deps.fetch
 * @param {(line: string) => void} deps.print
 * @param {(line: string) => void} deps.printErr
 * @param {(account: string) => string | null} deps.readSecret null when the account is absent
 * @param {(org: string) => { adminToken: string, verifierToken: string, scalar: bigint }} deps.devVarsSecrets
 * @param {{ append(line: string): void, remove(line: string): void }} deps.log
 * @param {(scalar: bigint) => (agentName: string, expiry: number) => Promise<unknown>} deps.makeIssuer
 * @param {() => number} deps.now
 * @param {(ms: number) => Promise<void>} deps.sleep
 * @param {string} [deps.wranglerOutput] stdin, with --from-wrangler
 * @returns {Promise<number>} the exit code
 */
export async function verifyDeploy(opts, deps) {
  const { print, printErr } = deps;
  let expectedVersion = opts.version;
  if (opts.fromWrangler) {
    expectedVersion = parseWranglerVersion(deps.wranglerOutput ?? '');
    if (expectedVersion === null) {
      printErr('FAIL the wrangler output on stdin has no "Current Version ID: <uuid>" line: the deploy did not complete. Nothing was verified.');
      return 1;
    }
  }

  // Secrets are resolved before any request, so a bad keychain entry sends nothing.
  let tenantSecrets = null;
  let missing = [];
  if (opts.tenant !== null) {
    const org = opts.tenant;
    try {
      if (opts.secretsFromDevVars) {
        tenantSecrets = deps.devVarsSecrets(org);
      } else {
        const accounts = { admin: `tenant-${org}-admin`, verifier: `tenant-${org}-verifier`, scalar: `operator-${org}-scalar` };
        const values = Object.fromEntries(Object.entries(accounts).map(([k, a]) => [k, deps.readSecret(a)]));
        missing = Object.entries(values).filter(([, v]) => v === null || v === undefined || v === '').map(([k]) => accounts[k]);
        if (missing.length === 0) {
          tenantSecrets = {
            adminToken: tokenFrom(values.admin, accounts.admin),
            verifierToken: tokenFrom(values.verifier, accounts.verifier),
            scalar: parseScalar(values.scalar, accounts.scalar),
          };
        }
      }
    } catch (e) {
      printErr(e instanceof DiagnosticError ? `FAIL ${e.message}` : `FAIL reading the tenant's secrets: ${e?.name ?? typeof e} (details withheld)`);
      return 1;
    }
  }

  print(`verify-deploy ${opts.url} (env ${opts.env}${expectedVersion !== null ? `, version ${expectedVersion}` : ''})`);
  if (expectedVersion !== null) {
    // A timeout is not reported here: the auth leg's /health check fails with the mismatch.
    await waitForVersion({ fetch: deps.fetch, url: opts.url, expected: expectedVersion, print, sleep: deps.sleep });
  }
  print('auth boundary:');
  const authOk = await runAuthBoundary({ fetch: deps.fetch, url: opts.url, expectedVersion, print });

  if (opts.tenant === null) {
    print('behavioral leg not run (no --tenant): enforcement NOT verified on this target');
    return authOk ? 0 : 1;
  }
  if (missing.length > 0) {
    if (opts.allowMissingTenant) {
      print(`enforcement NOT verified on this target (tenant ${opts.tenant} has no keychain entries)`);
      print(`  --  missing in keychain service ${opts.keychainService}: ${missing.join(', ')}`);
      return authOk ? 0 : 1;
    }
    printErr(`FAIL missing keychain entr${missing.length === 1 ? 'y' : 'ies'} in service ${opts.keychainService}: ${missing.join(', ')} (pilot/RUNBOOK.md, post-deploy verification)`);
    return 1;
  }
  if (!authOk) {
    print('behavioral leg skipped: the auth-boundary leg failed, so no canary is written to this target');
    return 1;
  }

  print(`behavioral (tenant ${opts.tenant}):`);
  const ok = await runBehavioral({
    fetch: deps.fetch,
    url: opts.url,
    env: opts.env,
    org: opts.tenant,
    secrets: { adminToken: tenantSecrets.adminToken, verifierToken: tenantSecrets.verifierToken },
    log: deps.log,
    issue: deps.makeIssuer(tenantSecrets.scalar),
    now: deps.now,
    print,
    printErr,
    random: deps.random,
  });
  print(ok ? 'verify-deploy: all checks passed' : 'verify-deploy: FAILED');
  return ok ? 0 : 1;
}
