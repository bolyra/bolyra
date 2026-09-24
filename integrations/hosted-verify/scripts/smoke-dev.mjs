// Smoke-checks a hosted-verify Worker booted by scripts/with-worker.sh (VERIFY_URL), in
// order, stopping at the first failure:
//
//   (0) GET /health                                           → 200, status ok, tenants ok,
//       registry_enforced true
//   (a) POST /v1/verify without Authorization                → 401
//   (b) POST /v1/verify as the verifier, unregistered binding → 200 deny untrusted_root,
//       detail.reason credential_not_active, detail.credential_id a 64-hex id
//   (c) POST /v1/credentials as the admin                     → 201 with that same id;
//       then (b) again                                        → 200 allow, and the
//       x-bolyra-credential-id header carries that id
//
// Tokens are read from the documented placeholder tenant of .dev.vars.example (the same
// TENANTS line dev-vars.mjs writes) — not secrets, and never printed. Response bodies are
// never printed: only status codes and allowlisted fields (verdict, identifier-shaped code
// and detail.reason, 64-hex ids) are shown; anything else is withheld. Exit 0 only when every
// check passed.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = path.resolve(here, '..');
const url = (process.env.VERIFY_URL ?? 'http://127.0.0.1:8787').replace(/\/+$/, '');
const { ADMIN_TOKEN, VERIFIER_TOKEN } = placeholderTokens();
const requestBody = readFileSync(path.join(pkg, 'examples', 'request.allow.json'), 'utf8');
const registrationBody = readFileSync(path.join(pkg, 'examples', 'registration.allow.json'), 'utf8');

/** The `local` tenant's tokens from the single TENANTS= line of .dev.vars.example. */
function placeholderTokens() {
  const example = readFileSync(path.join(pkg, '.dev.vars.example'), 'utf8');
  const lines = example.split(/\r?\n/).filter((line) => line.startsWith('TENANTS='));
  if (lines.length !== 1) {
    throw new Error(`.dev.vars.example must have exactly one TENANTS line; found ${lines.length}`);
  }
  let tenants;
  try {
    tenants = JSON.parse(lines[0].slice('TENANTS='.length));
  } catch {
    throw new Error('.dev.vars.example TENANTS value is not valid JSON');
  }
  const admin = tenants?.local?.admin_token;
  const verifier = tenants?.local?.verifier_token;
  if (typeof admin !== 'string' || admin === '' || typeof verifier !== 'string' || verifier === '') {
    throw new Error('.dev.vars.example TENANTS has no local.admin_token / local.verifier_token');
  }
  return { ADMIN_TOKEN: admin, VERIFIER_TOKEN: verifier };
}

// ─── What may be printed. Anything else the Worker sends back is withheld. ─────────────
const WITHHELD = '<withheld>';
const ID = /^[0-9a-f]{64}$/;
const VERDICTS = ['allow', 'deny'];
/** Deny `code` and `detail.reason` are identifiers, not secrets: shown when identifier-shaped. */
const IDENT = /^[a-z_]{1,40}$/;
const TENANT_STATES = ['ok', 'invalid'];
const CAPABILITY_MAP_STATES = ['ok', 'invalid'];
const REGISTRY_STATES = ['ok', 'unavailable', 'timeout'];

function shown(value, allowed) {
  if (value === undefined || value === null) return 'absent';
  return typeof value === 'string' && allowed.includes(value) ? value : WITHHELD;
}
function shownIdent(value) {
  if (value === undefined || value === null) return 'absent';
  return typeof value === 'string' && IDENT.test(value) ? value : WITHHELD;
}
function shownBool(value) {
  if (value === undefined || value === null) return 'absent';
  return typeof value === 'boolean' ? String(value) : WITHHELD;
}
function shownId(value) {
  if (value === undefined || value === null) return 'absent';
  return typeof value === 'string' && ID.test(value) ? value : WITHHELD;
}

function pass(check, observed) {
  console.log(`  ok  ${check}: ${observed}`);
}
function fail(check, expected, observed) {
  console.error(` FAIL ${check}: expected ${expected}; observed ${observed}`);
  process.exit(1);
}

/** Per-request deadline: the wrapper's 90 s readiness bound covers boot only, not a request that stalls afterwards. */
const REQUEST_TIMEOUT_MS = 15_000;

async function get(route) {
  let res;
  try {
    res = await fetch(`${url}${route}`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (e) {
    return { status: `no response (${e?.cause?.code ?? e?.cause?.errors?.[0]?.code ?? e?.name ?? 'error'})`, json: undefined };
  }
  let json;
  try {
    json = await res.json();
  } catch {
    json = undefined;
  }
  return { status: res.status, json };
}

async function post(route, token, body) {
  const headers = { 'content-type': 'application/json' };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`${url}${route}`, { method: 'POST', headers, body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (e) {
    return { status: `no response (${e?.cause?.code ?? e?.cause?.errors?.[0]?.code ?? e?.name ?? 'error'})`, json: undefined, headers: new Headers() };
  }
  let json;
  try {
    json = await res.json();
  } catch {
    json = undefined;
  }
  return { status: res.status, json, headers: res.headers };
}

/** Status, verdict, code, detail.reason, detail.credential_id — allowlisted. */
function describeVerify(r) {
  const j = r.json ?? {};
  return `status ${r.status}, verdict ${shown(j.verdict, VERDICTS)}, code ${shownIdent(j.code)}, ` +
    `detail.reason ${shownIdent(j.detail?.reason)}, detail.credential_id ${shownId(j.detail?.credential_id)}`;
}

// (0) /health → 200, status ok, tenants ok, registry_enforced true
{
  const check = '(0) health';
  const r = await get('/health');
  const j = r.json ?? {};
  // registry and capability_map are shown so a degraded (503) local Worker says why.
  const observed = `status ${r.status}, status field ${shown(j.status, ['ok', 'degraded'])}, tenants ${shown(j.tenants, TENANT_STATES)}, ` +
    `capability_map ${shown(j.capability_map, CAPABILITY_MAP_STATES)}, registry ${shown(j.registry, REGISTRY_STATES)}, ` +
    `registry_enforced ${shownBool(j.registry_enforced)}`;
  if (r.status !== 200 || j.status !== 'ok' || j.tenants !== 'ok' || j.registry_enforced !== true) {
    fail(check, 'status 200, status field ok, tenants ok, registry_enforced true', observed);
  }
  pass(check, observed);
}

// (a) no Authorization → 401
{
  const check = '(a) verify without Authorization';
  const r = await post('/v1/verify', undefined, requestBody);
  if (r.status !== 401) fail(check, 'status 401', `status ${r.status}`);
  pass(check, `status ${r.status}`);
}

// (b) authenticated, unregistered binding → deny untrusted_root / credential_not_active
let deniedId;
{
  const check = '(b) verify of an unregistered binding';
  const r = await post('/v1/verify', VERIFIER_TOKEN, requestBody);
  const j = r.json ?? {};
  const ok = r.status === 200 && j.verdict === 'deny' && j.code === 'untrusted_root' &&
    j.detail?.reason === 'credential_not_active' && typeof j.detail?.credential_id === 'string' &&
    ID.test(j.detail.credential_id);
  const expected = 'status 200, verdict deny, code untrusted_root, detail.reason credential_not_active, detail.credential_id <64 hex>';
  if (!ok) fail(check, expected, describeVerify(r));
  deniedId = j.detail.credential_id;
  pass(check, describeVerify(r));
}

// (c) register → 201 with the same id; then verify → allow with the id in the header
{
  const check = '(c) register the binding';
  const r = await post('/v1/credentials', ADMIN_TOKEN, registrationBody);
  const id = r.json?.credential_id;
  const expected = `status 201, credential_id ${deniedId}`;
  const observed = `status ${r.status}, credential_id ${shownId(id)}`;
  if (r.status !== 201 || typeof id !== 'string' || !ID.test(id) || id !== deniedId) fail(check, expected, observed);
  pass(check, observed);
}
{
  const check = '(c) verify of the registered binding';
  const r = await post('/v1/verify', VERIFIER_TOKEN, requestBody);
  const j = r.json ?? {};
  const header = r.headers.get('x-bolyra-credential-id');
  const expected = `status 200, verdict allow, x-bolyra-credential-id ${deniedId}`;
  const observed = `status ${r.status}, verdict ${shown(j.verdict, VERDICTS)}, code ${shownIdent(j.code)}, x-bolyra-credential-id ${shownId(header)}`;
  if (r.status !== 200 || j.verdict !== 'allow' || header !== deniedId) fail(check, expected, observed);
  pass(check, observed);
}

console.log('smoke:dev passed — the Worker boots under wrangler dev and serves auth, deny, register, allow');
