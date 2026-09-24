// Smoke-checks a hosted-verify Worker booted by scripts/with-worker.sh (VERIFY_URL), in
// order, stopping at the first failure:
//
//   (a) POST /v1/verify without Authorization                → 401
//   (b) POST /v1/verify as the verifier, unregistered binding → 200 deny untrusted_root,
//       detail.reason credential_not_active, detail.credential_id a 64-hex id
//   (c) POST /v1/credentials as the admin                     → 201 with that same id;
//       then (b) again                                        → 200 allow, and the
//       x-bolyra-credential-id header carries that id
//
// Tokens are the documented placeholder tenant of .dev.vars.example — not secrets. Response
// bodies are never printed: only status codes and allowlisted fields (verdict, code,
// detail.reason, 64-hex ids) are shown; anything else is withheld. Exit 0 only when every
// check passed.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = path.resolve(here, '..');
const url = (process.env.VERIFY_URL ?? 'http://127.0.0.1:8787').replace(/\/+$/, '');
const ADMIN_TOKEN = 'local-admin-token-000000000000000000';
const VERIFIER_TOKEN = 'local-verifier-token-0000000000000000';
const requestBody = readFileSync(path.join(pkg, 'examples', 'request.allow.json'), 'utf8');
const registrationBody = readFileSync(path.join(pkg, 'examples', 'registration.allow.json'), 'utf8');

// ─── What may be printed. Anything else the Worker sends back is withheld. ─────────────
const WITHHELD = '<withheld>';
const ID = /^[0-9a-f]{64}$/;
const VERDICTS = ['allow', 'deny'];
const DENY_CODES = [
  'missing_authorization', 'malformed_input', 'unsupported_version', 'invalid_bundle', 'invalid_proof',
  'invalid_signature', 'untrusted_root', 'delegation_invalid', 'request_mismatch', 'model_mismatch',
  'unknown_capability', 'scope_exceeded', 'expired', 'nonce_missing', 'nonce_replayed', 'internal_error',
];
const REASONS = ['credential_not_active'];

function shown(value, allowed) {
  if (value === undefined || value === null) return 'absent';
  return typeof value === 'string' && allowed.includes(value) ? value : WITHHELD;
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

async function post(route, token, body) {
  const headers = { 'content-type': 'application/json' };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`${url}${route}`, { method: 'POST', headers, body });
  } catch (e) {
    return { status: `no response (${e?.cause?.code ?? e?.name ?? 'error'})`, json: undefined, headers: new Headers() };
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
  return `status ${r.status}, verdict ${shown(j.verdict, VERDICTS)}, code ${shown(j.code, DENY_CODES)}, ` +
    `detail.reason ${shown(j.detail?.reason, REASONS)}, detail.credential_id ${shownId(j.detail?.credential_id)}`;
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
  const observed = `status ${r.status}, verdict ${shown(j.verdict, VERDICTS)}, code ${shown(j.code, DENY_CODES)}, x-bolyra-credential-id ${shownId(header)}`;
  if (r.status !== 200 || j.verdict !== 'allow' || header !== deniedId) fail(check, expected, observed);
  pass(check, observed);
}

console.log('smoke:dev passed — the Worker boots under wrangler dev and serves auth, deny, register, allow');
