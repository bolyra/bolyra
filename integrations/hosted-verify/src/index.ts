/**
 * Bolyra hosted verify — DESIGN PARTNER PREVIEW.
 *
 * External Verifier Contract v1 over HTTP (spec/external-verifier-contract-v1.md):
 *
 *   POST /v1/verify   Verifier-token auth. Body = the spec §2.1 request object
 *                     (the same JSON `bolyra verify` reads on stdin). Response
 *                     body = exactly one strict §3.4 verdict object, always
 *                     `kind: "classical"` (spec §3.5). Fail-closed everywhere.
 *                     An allow additionally requires the signed binding to be
 *                     ACTIVE in the tenant's registry.
 *   GET  /health      Unauthenticated status + preview labeling + the exact
 *                     list of checks this preview does / does not perform.
 *                     Probes TENANTS, CAPABILITY_MAP and the registry; 503
 *                     `status: "degraded"` when any of them fails.
 *
 *   POST /v1/credentials               Admin-token auth. Register an operator-signed
 *   GET  /v1/credentials/{id}          binding in the tenant's managed credential
 *   POST /v1/credentials/{id}/revoke   registry (src/registry.ts); read it; revoke it.
 *   POST /v1/credentials/{id}/repair-history
 *                                      write a revocation's owed audit row (a 204
 *                                      revoke that carried x-bolyra-audit).
 *
 * Tenancy and roles (src/tenants.ts): the `TENANTS` secret maps an org id to
 * an admin token, a verifier token and that tenant's trusted operator keys.
 * Tenant and role derive exclusively from which token matched; no route
 * accepts an org id from the request, and the ONLY code path that obtains a
 * tenant's registry stub is `registryFor(env, auth)` below — authenticated
 * routing is the isolation control. (`/health` probes one constant, non-tenant
 * object, `__health__`; see src/health-probe.ts.)
 *
 *   request ──► loadTenants(TENANTS) + loadCapabilityMap ──defect──► 500
 *                    │                     (verify: deny internal_error verdict;
 *                    ▼                      registry routes: { error: "internal_error" })
 *              resolveAuth(token) ──none──► 401
 *                    │
 *                    ├── tenant.disabled ─► verify: 500 verdict · registry: 503 tenant_disabled
 *                    ├── wrong role ──────► 403 { error: "forbidden" }
 *                    └── ok ──► verify: verifyClassical(body, tenant.trusted_operators, capabilityMap)
 *                              │         ──deny──► that verdict (the registry is never read)
 *                              │         ──allow─► credentialId(verified operator, verified binding)
 *                              │                   → TenantRegistry.status, 2 s deadline
 *                              │                   → ACTIVE  : allow + x-bolyra-credential-id
 *                              │                   → REVOKED/ABSENT : deny untrusted_root
 *                              │                   → error/timeout  : deny internal_error (500)
 *                              registry: trust → signature → expiry → credentialId → TenantRegistry RPC
 *
 * HTTP mapping of the CLI exit-code semantics (§7.1): every decision-level
 * verdict (allow or policy/crypto deny) is HTTP 200; `deny internal_error`
 * (the CLI's "non-zero exit" case) is HTTP 500. Auth/transport failures
 * (401/403/404/405) happen BEFORE the contract and carry an `{ "error": ... }`
 * body, not a verdict. The registry routes are HTTP resources, not verifiers:
 * their non-2xx bodies are `{ "error", "message" }` (the 403 stays exactly
 * `{ "error": "forbidden" }`).
 *
 * NOT in this preview (deliberately): SLAs, billing, dashboards, tenant
 * self-service, zk verification, custom policy UI, customer-managed keys.
 * Observability IS here: Workers Logs + one Analytics Engine data point per
 * request (labels/verdicts/latency only — see README "Observability").
 */

import {
  verifyClassical,
  type VerifiedClassical,
  CHECKS_AUTHENTICATED,
  CHECKS_CONSISTENCY,
  CHECKS_NOT_PERFORMED,
} from './verify/core';
import { loadCapabilityMap, type CapabilityMap } from './verify/capabilities';
import { deny, isVerifyDenial, type DenyVerdict, type Verdict } from './verify/verdict';
import { bindingDigest, verifyBindingSig } from './verify/binding';
import { operatorKeyId } from './verify/operators';
import { canonicalize } from '@bolyra/receipts';
import { loadTenants, resolveAuth, type AuthResult, type Role, type TenantConfig } from './tenants';
import { buildReceiptHeader, buildSignerDiscoveryDoc } from './receipt';
import { BODY_READ_DEADLINE_MS, TIMEOUT, withDeadline, withRegistryDeadline } from './deadlines';
import { cachedProbeRegistry } from './health-probe';
import { credentialId, CREDENTIAL_ID_PATTERN, CREDENTIAL_ID_VERSION } from './credential-id';
import { parseRegistration, type RegistryErrorCode } from './routes/credentials';
import { MAX_ACTIVE_CREDENTIALS, type TenantRegistry } from './registry';

// Durable Object classes must be exported from the Worker's main module.
export { TenantRegistry } from './registry';

export interface Env {
  /**
   * Secret. JSON object: org_id → { admin_token, verifier_token,
   * trusted_operators: ["x:y", …], disabled? }. See src/tenants.ts.
   */
  TENANTS?: string;
  /** Optional JSON capability → permission-name map, merged over the built-in default. */
  CAPABILITY_MAP?: string;
  RECEIPT_SIGNER_KEY?: string;
  RECEIPT_ISSUER?: string;
  RECEIPT_KEY_ID?: string;
  /** Workers Analytics Engine dataset for usage data points (optional). */
  USAGE?: AnalyticsEngineDataset;
  /** The per-tenant credential registry (src/registry.ts); one object per org_id. */
  TENANT: DurableObjectNamespace<TenantRegistry>;
  /**
   * The `version_metadata` binding (wrangler.jsonc): the deployed Worker version, echoed on
   * /health. Optional because a local run may not provide it; /health then reports `null`.
   */
  CF_VERSION_METADATA?: Partial<WorkerVersionMetadata> & Pick<WorkerVersionMetadata, 'id' | 'tag'>;
}

/** Request-body bound for /v1/verify — mirrors the spec §6 1 MiB stdin bound. */
const MAX_BODY_BYTES = 1_048_576;

/** Request-body bound for a registration (a binding plus a signature is well under 4 KiB). */
const MAX_REGISTRATION_BYTES = 65_536;

const PREVIEW_HEADERS: Record<string, string> = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-bolyra-preview': 'design-partner-preview',
};

function json(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...PREVIEW_HEADERS, ...extra },
  });
}

/**
 * The one shape for non-verdict error bodies: `{ "error": <code>, ...extra }`.
 * `/v1/verify`'s 401 keeps its historical `hint` member; other routes add a
 * `message`. Never a verdict object (those are HTTP 200/500 decisions).
 */
function errorJson(
  status: number,
  code: string,
  extra?: Record<string, unknown>,
  headers?: Record<string, string>,
): Response {
  return json(status, { error: code, ...extra }, headers);
}

/** Registry-route error body: `{ error, message }`. */
function registryError(status: number, code: RegistryErrorCode, message: string): Response {
  return errorJson(status, code, { message });
}

/** Reserved usage label recorded for requests with no valid bearer token. */
const UNAUTHENTICATED = 'unauthenticated';

/**
 * Usage label for an authenticated request: `<org_id>:<role>`. This is the ONLY
 * projection of an AuthResult that may reach a log line, a data point, or a
 * response — never the object itself.
 */
function tenantLabel(auth: AuthResult): string {
  return `${auth.org_id}:${auth.role}`;
}

/**
 * The request id: ALWAYS server-generated (a UUID), never taken from the request. It is
 * recorded in registry history, the log lines and analytics, and returned as the
 * `x-bolyra-request-id` response header, so an audit row can never carry a value a client
 * chose.
 */
function newRequestId(): string {
  return crypto.randomUUID();
}

/**
 * The `cf-ray` id, kept as a SEPARATE correlation field (logs and analytics only; never
 * history). It is assigned at Cloudflare's edge in production, but in `wrangler dev` and
 * tests a client can supply any value — so only the documented shape
 * (`<16 hex>[-<3 uppercase>]`) is accepted; anything else is `undefined`.
 */
const CF_RAY_PATTERN = /^[0-9a-f]{16}(-[A-Z]{3})?$/;
function cfRayFrom(request: Request): string | undefined {
  const ray = request.headers.get('cf-ray');
  return ray !== null && CF_RAY_PATTERN.test(ray) ? ray : undefined;
}

/**
 * The outcome of reading a request body. Every failure is a value, never a throw, so the
 * caller always reaches its verdict (and its analytics point):
 *   too_large     over the byte cap (declared or streamed)
 *   stream_error  the body stream errored (client reset, malformed chunked encoding)
 *   stall         the body did not finish within BODY_READ_DEADLINE_MS
 */
type BodyRead = { kind: 'ok'; text: string } | { kind: 'too_large' } | { kind: 'stream_error' } | { kind: 'stall' };

/** The wire message for a body stream that errored; never the error's own text. */
const BODY_STREAM_ERROR_MESSAGE = 'request body could not be read';
const BODY_STALL_MESSAGE = 'request body stalled';

/** `reader.cancel()` is best-effort: a cancel that throws or rejects changes nothing. */
function cancelQuietly(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.cancel().catch(() => {});
  } catch {
    // best-effort
  }
}

/** Read the request body with a hard byte cap and a deadline (`BodyRead`). */
async function readBodyCapped(request: Request, maxBytes: number): Promise<BodyRead> {
  const declared = request.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) return { kind: 'too_large' };

  const reader = request.body?.getReader();
  if (reader === undefined) return { kind: 'ok', text: '' };
  const outcome = await withDeadline(drainCapped(reader, maxBytes), BODY_READ_DEADLINE_MS);
  if (outcome === TIMEOUT) {
    cancelQuietly(reader); // settles the pending read; the orphaned drain's result is ignored
    return { kind: 'stall' };
  }
  return outcome;
}

/** The read loop behind `readBodyCapped`. Never rejects. */
async function drainCapped(reader: ReadableStreamDefaultReader<Uint8Array>, maxBytes: number): Promise<BodyRead> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        cancelQuietly(reader);
        return { kind: 'too_large' };
      }
      chunks.push(value);
    }
  } catch {
    return { kind: 'stream_error' };
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { kind: 'ok', text: new TextDecoder('utf-8').decode(merged) };
}

/** The one wire message for every fail-closed configuration or quarantine 500. */
const CONFIG_ERROR_MESSAGE = 'missing or invalid trust configuration';

function verdictResponse(verdict: Verdict, body: unknown, env: Env): Response {
  // §7.1 nuance mapped to HTTP: internal_error is the fail-closed
  // "could not produce a trustworthy verdict" signal → 500.
  const status = verdict.verdict === 'deny' && verdict.code === 'internal_error' ? 500 : 200;
  const receipt = buildReceiptHeader(verdict, body, env);
  return json(status, verdict, receipt !== undefined ? { 'x-bolyra-receipt': receipt } : undefined);
}

/**
 * A configuration defect is a fail-closed 500 VERDICT (`deny internal_error`),
 * never an allow and never a bare error body — the gate on the other side
 * treats it as a deny. Details are logged server-side only (spec §3.3: wire
 * messages never carry config internals).
 * Because configuration is checked before the body is read, the signed receipt
 * on such a 500 is the anonymous form (no credential attribution).
 */
function configErrorVerdict(e: unknown): DenyVerdict {
  console.error(
    'hosted-verify configuration error:',
    isVerifyDenial(e) ? `${e.code}: ${e.message}` : e instanceof Error ? e.stack : String(e),
    isVerifyDenial(e) ? (e.detail ?? {}) : {},
  );
  return deny('internal_error', CONFIG_ERROR_MESSAGE);
}

/**
 * A quarantined tenant is refused with the same fail-closed 500 verdict as a
 * configuration defect, but it is NOT one: logged at warn level, no stack, so
 * an alert on configuration errors never fires on parked-tenant traffic.
 */
function quarantineVerdict(orgId: string): DenyVerdict {
  console.warn('hosted-verify tenant disabled:', { org_id: orgId });
  return deny('internal_error', CONFIG_ERROR_MESSAGE);
}

/** Outcome of authenticating a request for a route that requires `required`. */
type Gate =
  | { kind: 'config_error'; verdict: DenyVerdict }
  | { kind: 'unauthenticated' }
  | { kind: 'forbidden'; auth: AuthResult }
  | { kind: 'disabled'; auth: AuthResult }
  | { kind: 'ok'; auth: AuthResult; capabilityMap: CapabilityMap };

/**
 * configuration → auth → quarantine → role, in that order. BOTH configuration
 * inputs are validated before any auth outcome, so a configuration defect is
 * the 500 verdict for every caller — never a 401/403 that hides an outage.
 * The tenant map is re-parsed per request (≤ 4 KiB; a rotated secret takes
 * effect on the next request).
 */
function authorize(request: Request, env: Env, required: Role): Gate {
  let tenants: Map<string, TenantConfig>;
  let capabilityMap: CapabilityMap;
  try {
    tenants = loadTenants(env.TENANTS);
    capabilityMap = loadCapabilityMap(env.CAPABILITY_MAP);
  } catch (e) {
    return { kind: 'config_error', verdict: configErrorVerdict(e) };
  }
  const auth = resolveAuth(request, tenants);
  if (auth === null) return { kind: 'unauthenticated' };
  // Quarantine outranks role: NO route serves a disabled tenant, whichever of
  // its tokens is presented.
  if (auth.disabled) return { kind: 'disabled', auth };
  if (auth.role !== required) return { kind: 'forbidden', auth };
  return { kind: 'ok', auth, capabilityMap };
}

/**
 * The ONLY way a TENANT's registry stub is obtained: from a resolved authentication result.
 * The one other stub path is `/health`'s liveness probe (`probeRegistry`, src/health-probe.ts),
 * which names the constant `HEALTH_PROBE_ID` — never anything from the request.
 */
function registryFor(env: Env, auth: AuthResult): DurableObjectStub<TenantRegistry> {
  return env.TENANT.get(env.TENANT.idFromName(auth.org_id));
}

/** Result of the registry membership check that follows the classical checks. */
type Membership =
  | { kind: 'active'; credential_id: string }
  | { kind: 'not_active'; credential_id: string }
  | { kind: 'unavailable'; message: 'registry unavailable' | 'registry timeout' };

/** Race the registry read against the deadline (`withRegistryDeadline`) and classify it. */
async function readMembership(
  registry: DurableObjectStub<TenantRegistry>,
  credential_id: string,
): Promise<Membership> {
  const read = registry.status(credential_id);
  try {
    const outcome = await withRegistryDeadline(read);
    if (outcome === TIMEOUT) return { kind: 'unavailable', message: 'registry timeout' };
    switch (outcome) {
      case 'ACTIVE':
        return { kind: 'active', credential_id };
      case 'REVOKED':
      case 'ABSENT':
        return { kind: 'not_active', credential_id };
      case 'invalid_input':
      case 'storage_error':
        return { kind: 'unavailable', message: 'registry unavailable' };
    }
    return unknownStatus(outcome);
  } catch {
    return { kind: 'unavailable', message: 'registry unavailable' };
  }
}

/** A status the declared union does not name (a rolling deploy): fail closed. */
function unknownStatus(outcome: never): Membership {
  const value: unknown = outcome;
  const shape = typeof value === 'object' && value !== null ? Object.keys(value).sort().join(',') : typeof value;
  console.error('hosted-verify registry returned an unknown status:', { operation: 'status', shape });
  return { kind: 'unavailable', message: 'registry unavailable' };
}

/** What a decision needs to report: the verdict, the response, and (on allow) the credential id. */
interface Decision {
  verdict: Verdict;
  response: Response;
  credential_id?: string;
}

/**
 * The verify decision: classical checks FIRST, in their existing order, then —
 * only for a presentation every classical check accepted — the registry read.
 * Registry-first would let invalid bundles probe registry state; both orders
 * fail closed because a lookup failure never allows. The credential id is
 * derived from the VERIFIED binding and the VERIFIED operator key.
 */
async function handleVerify(
  request: Request,
  auth: AuthResult,
  capabilityMap: CapabilityMap,
  env: Env,
): Promise<Decision> {
  const read = await readBodyCapped(request, MAX_BODY_BYTES);
  if (read.kind !== 'ok') {
    const verdict =
      read.kind === 'too_large'
        ? deny('malformed_input', `request body exceeds the ${MAX_BODY_BYTES}-byte bound`)
        : read.kind === 'stream_error'
          ? deny('malformed_input', BODY_STREAM_ERROR_MESSAGE)
          : deny('internal_error', BODY_STALL_MESSAGE); // no trustworthy input to judge: the §7.1 500
    return { verdict, response: verdictResponse(verdict, undefined, env) };
  }

  let body: unknown;
  try {
    body = JSON.parse(read.text);
  } catch {
    const verdict = deny('malformed_input', 'request body is not valid JSON');
    return { verdict, response: verdictResponse(verdict, undefined, env) };
  }

  const classical = verifyClassical(body, auth.trusted_operators, capabilityMap);
  if (classical.verified === undefined) {
    return { verdict: classical.verdict, response: verdictResponse(classical.verdict, body, env) };
  }

  const membership = await membershipOf(env, auth, classical.verified);
  switch (membership.kind) {
    case 'active': {
      const verdict = classical.verdict;
      const response = verdictResponse(verdict, body, env);
      // Unsigned operational correlation — never an authorization input.
      response.headers.set('x-bolyra-credential-id', membership.credential_id);
      return { verdict, response, credential_id: membership.credential_id };
    }
    case 'not_active': {
      // One verifier-visible reason for revoked and never-registered alike;
      // revoked-vs-unregistered is admin-only. The id is derivable from the
      // bundle the verifier already holds, so exposing it reveals nothing new.
      const verdict = deny(
        'untrusted_root',
        "the presented binding is not an active credential in this tenant's registry",
        { reason: 'credential_not_active', credential_id: membership.credential_id },
      );
      return { verdict, response: verdictResponse(verdict, body, env) };
    }
    case 'unavailable': {
      console.error('hosted-verify registry read failed:', { org_id: auth.org_id, message: membership.message });
      const verdict = deny('internal_error', membership.message);
      return { verdict, response: verdictResponse(verdict, undefined, env) };
    }
  }
}

/** Derive the id from what was verified, obtain the stub from the auth result only, read. */
async function membershipOf(env: Env, auth: AuthResult, verified: VerifiedClassical): Promise<Membership> {
  const id = credentialId(verified.operator, bindingDigest(verified.binding));
  try {
    return await readMembership(registryFor(env, auth), id);
  } catch {
    // A missing or unapplied TENANT Durable Object binding fails here, not as a bare exception.
    return { kind: 'unavailable', message: 'registry unavailable' };
  }
}

/**
 * A registry-route outcome: the response plus the code recorded in analytics
 * ('' on a clean success; a success can carry a code, e.g. revoke_history_failed).
 */
interface RouteOutcome {
  response: Response;
  code: string;
  /** The credential the route created or affirmed (register only); ids from the path are logged by the caller. */
  credential_id?: string;
}

function fail(status: number, code: RegistryErrorCode, message: string): RouteOutcome {
  return { response: registryError(status, code, message), code };
}

/**
 * A registry result the declared union does not name: log its shape (never its
 * content), fail closed. Typed `never` so a forgotten arm in the caller's switch
 * is a compile error (the value is not `never` until every declared arm returns)
 * while a value outside the union still lands here at runtime.
 */
function unknownOutcome(operation: string, result: never): RouteOutcome {
  const value: unknown = result;
  const shape = typeof value === 'object' && value !== null ? Object.keys(value).sort().join(',') : typeof value;
  console.error('hosted-verify registry returned an unknown outcome:', { operation, shape });
  return fail(500, 'internal_error', 'registry storage failure');
}

/** Server time, unix seconds — the registry's clock for expiry and timestamps. */
function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * POST /v1/credentials — checks in order, all fail-closed:
 *   parse → trust membership (403) → signature (400) → expiry (400) → id → RPC.
 * Trust membership is a separate assertion from the signature check:
 * `verifyBindingSig` only proves a signature against the key the caller supplied.
 */
async function handleRegister(
  request: Request,
  auth: AuthResult,
  registry: DurableObjectStub<TenantRegistry>,
  requestId: string,
): Promise<RouteOutcome> {
  const read = await readBodyCapped(request, MAX_REGISTRATION_BYTES);
  switch (read.kind) {
    case 'too_large':
      return fail(400, 'malformed_input', `request body exceeds the ${MAX_REGISTRATION_BYTES}-byte bound`);
    case 'stream_error':
      return fail(400, 'malformed_input', BODY_STREAM_ERROR_MESSAGE);
    case 'stall':
      return fail(500, 'internal_error', BODY_STALL_MESSAGE);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(read.text);
  } catch {
    return fail(400, 'malformed_input', 'request body is not valid JSON');
  }
  const parsed = parseRegistration(raw);
  if (!parsed.ok) return fail(400, 'malformed_input', parsed.message);
  const { binding, signature, operator_pubkey } = parsed.value;

  let pub: { x: bigint; y: bigint };
  let sig: { R8: { x: bigint; y: bigint }; S: bigint };
  try {
    pub = { x: BigInt(operator_pubkey.x), y: BigInt(operator_pubkey.y) };
    sig = { R8: { x: BigInt(signature.R8.x), y: BigInt(signature.R8.y) }, S: BigInt(signature.S) };
  } catch {
    return fail(400, 'malformed_input', 'operator_pubkey and signature must be decimal integers');
  }
  const keyId = operatorKeyId(pub.x, pub.y);
  if (!auth.trusted_operators.has(keyId)) {
    return fail(403, 'untrusted_operator', "operator key is not in this tenant's trusted operators");
  }
  try {
    verifyBindingSig(binding, sig, pub);
  } catch (e) {
    if (isVerifyDenial(e)) {
      return fail(400, 'binding_signature_invalid', 'binding signature does not verify against the operator key');
    }
    throw e;
  }
  const now = nowUnix();
  if (binding.expiry <= now) {
    return fail(400, 'binding_expired', 'binding.expiry is not in the future');
  }

  // Only now — after the trust check and the signature verified against `pub` —
  // is `pub` a key we may derive an identity from.
  const digest = bindingDigest(binding);
  const id = credentialId(pub, digest); // coordinates, never the request's spelling of them
  const result = await registry.register({
    credential_id: id,
    operator_key: keyId,
    binding_digest_hex: digest.toString(16).padStart(64, '0'),
    binding_json: canonicalize(binding),
    expiry: binding.expiry,
    now,
    request_id: requestId,
  });
  switch (result.outcome) {
    case 'created':
      return { response: json(201, { credential_id: id, status: 'ACTIVE', registered_at: result.registered_at }), code: '', credential_id: id };
    case 'unchanged':
      return { response: json(200, { credential_id: id, status: 'ACTIVE', registered_at: result.registered_at }), code: '', credential_id: id };
    case 'revoked':
      return fail(409, 'credential_revoked', 'this credential was revoked; revocation is terminal');
    case 'quota_exceeded':
      // No Retry-After: time frees nothing, only a revocation does.
      return fail(
        429,
        'quota_exceeded',
        `this tenant has reached its active credential limit (${MAX_ACTIVE_CREDENTIALS}); revoke credentials before registering more`,
      );
    case 'expired':
      return fail(400, 'binding_expired', 'binding.expiry is not in the future');
    case 'mismatch':
      // The same derived id already holds a different key or binding: an
      // id-derivation defect or a collision, never a client error to paper over.
      console.error('hosted-verify registry id mismatch:', { org_id: auth.org_id, credential_id: id, request_id: requestId });
      // Wire body stays the fixed internal_error shape; analytics get their own code.
      return { response: registryError(500, 'internal_error', 'registry integrity failure'), code: 'registry_mismatch' };
    case 'invalid_input':
    case 'storage_error':
      return fail(500, 'internal_error', 'registry storage failure');
  }
  // Unreachable for the declared union (the switch above is exhaustive and a
  // forgotten arm is a compile error), but an outcome outside the union can
  // arrive across a rolling deploy — fail closed rather than return undefined.
  return unknownOutcome('register', result);
}

async function handleGet(registry: DurableObjectStub<TenantRegistry>, id: string): Promise<RouteOutcome> {
  const result = await registry.get(id);
  switch (result.outcome) {
    case 'found': {
      // Rendered from the STORED record, never from a request.
      const { binding_json, ...rest } = result.record;
      return { response: json(200, { ...rest, binding: JSON.parse(binding_json) as unknown }), code: '' };
    }
    case 'absent':
      return fail(404, 'not_found', 'no such credential');
    case 'invalid_input':
    case 'storage_error':
      return fail(500, 'internal_error', 'registry storage failure');
  }
  return unknownOutcome('get', result);
}

async function handleRevoke(
  registry: DurableObjectStub<TenantRegistry>,
  id: string,
  requestId: string,
): Promise<RouteOutcome> {
  const result = await registry.revoke(id, nowUnix(), requestId);
  switch (result) {
    case 'revoked':
    case 'unchanged':
      return { response: revoked(), code: '' };
    case 'revoked_history_failed':
      // The credential IS revoked (verify denies it); only its audit row is owed.
      // Consumers keep their 204 contract; the header and the logged code carry
      // the gap to the operator (pilot/RUNBOOK.md: repair-history).
      return { response: revoked({ 'x-bolyra-audit': 'history_write_failed' }), code: 'revoke_history_failed' };
    case 'revoked_history_conflict':
      // A retry met a revoked event that is not ours (or unusable metadata): still
      // revoked, still 204; a human compares the rows (pilot/RUNBOOK.md).
      return { response: revoked({ 'x-bolyra-audit': 'history_conflict' }), code: 'revoke_history_conflict' };
    case 'absent':
      return fail(404, 'not_found', 'no such credential');
    case 'invalid_input':
    case 'storage_error':
      return fail(500, 'internal_error', 'registry storage failure');
  }
  return unknownOutcome('revoke', result);
}

function revoked(extra?: Record<string, string>): Response {
  return new Response(null, {
    status: 204,
    headers: { 'cache-control': 'no-store', 'x-bolyra-preview': 'design-partner-preview', ...extra },
  });
}

/** POST /v1/credentials/{id}/repair-history — idempotent; see `TenantRegistry.repairHistory`. */
async function handleRepairHistory(registry: DurableObjectStub<TenantRegistry>, id: string): Promise<RouteOutcome> {
  const result = await registry.repairHistory(id);
  switch (result) {
    case 'repaired':
    case 'clean':
      return { response: json(200, { credential_id: id, audit: result }), code: '' };
    case 'conflict':
      return fail(
        409,
        'history_conflict',
        'a different revoked event is already recorded for this credential; it needs operator review. The credential is revoked either way',
      );
    case 'absent':
      return fail(404, 'not_found', 'no such credential');
    case 'invalid_input':
    case 'storage_error':
      return fail(500, 'internal_error', 'registry storage failure');
  }
  return unknownOutcome('repair_history', result);
}

/** `/v1/credentials`, `/v1/credentials/{id}`, `…/{id}/revoke`, `…/{id}/repair-history` — nothing else. */
const CREDENTIALS_ROUTE = /^\/v1\/credentials(?:\/([^/]+)(\/revoke|\/repair-history)?)?$/;

async function handleHealth(env: Env): Promise<Response> {
  // /health is the diagnostic surface: a broken TENANTS or CAPABILITY_MAP, or an
  // unreachable registry, is REPORTED here, never thrown (the authenticated routes are
  // the ones that fail closed). A degraded service answers 503 so a probe that checks
  // only the HTTP status cannot mistake it for healthy.
  let tenants: 'ok' | 'invalid' = 'ok';
  try {
    loadTenants(env.TENANTS);
  } catch {
    tenants = 'invalid';
  }
  let capability_map: 'ok' | 'invalid' = 'ok';
  try {
    loadCapabilityMap(env.CAPABILITY_MAP);
  } catch {
    capability_map = 'invalid';
  }
  const registry = await cachedProbeRegistry(env.TENANT);
  const meta = env.CF_VERSION_METADATA;
  // Copied field by field: the binding is a runtime object, and a timestamp is echoed only when present.
  const version =
    meta === undefined
      ? null
      : { id: meta.id, tag: meta.tag, ...(meta.timestamp !== undefined ? { timestamp: meta.timestamp } : {}) };
  const healthy = tenants === 'ok' && capability_map === 'ok' && registry === 'ok';
  return json(healthy ? 200 : 503, {
    status: healthy ? 'ok' : 'degraded',
    service: 'bolyra-hosted-verify',
    phase: 'DESIGN PARTNER PREVIEW — not a production service, no SLA',
    contract: 'external-verifier-contract-v1 (spec/external-verifier-contract-v1.md)',
    verifier_kind: 'classical',
    nonce_mode: 'host',
    tenants,
    capability_map,
    registry,
    registry_kind: 'durable-object',
    credential_id_version: CREDENTIAL_ID_VERSION,
    // The deployed Worker version (informational; never affects `status`). null when unbound.
    version,
    // Build marker: true for every build that consults the registry on /v1/verify.
    // worker.spec.ts asserts it; a deploy check can assert it against the live URL.
    registry_enforced: true,
    receipts_enabled: env.RECEIPT_SIGNER_KEY !== undefined && env.RECEIPT_SIGNER_KEY !== '',
    trust_model:
      'an allow means an operator the calling tenant configured as trusted signed a binding ' +
      "authorizing this exact request AND that signed binding is ACTIVE in the tenant's managed " +
      'registry. The proof itself is NOT verified — the Merkle root and all public signals are ' +
      'unverified. Sound scope/expiry enforcement requires the zk-class `bolyra verify` CLI.',
    trust_policy:
      'For this verifier, the configured trusted-root source (spec §9, untrusted_root) is ' +
      "active signer-binding membership in the tenant's registry, in addition to operator-key " +
      'membership. A credential that is not ACTIVE in the registry is outside the trusted-root ' +
      'source, and revocation is trust-anchor removal. The EVC spec does not define a revocation ' +
      'mechanism; this is a documented verifier policy, permitted because untrusted_root is ' +
      'proof-system-agnostic and the deny schema is unchanged.',
    checks_authenticated: CHECKS_AUTHENTICATED,
    checks_consistency_only: CHECKS_CONSISTENCY,
    checks_not_performed: CHECKS_NOT_PERFORMED,
  });
}

/**
 * One structured Analytics Engine data point per request — and NOTHING else.
 * Explicitly never stored: request bodies, proofs, credentials, bearer
 * tokens, IPs, credential ids. Documented in README "Observability".
 *
 *   blobs   = [route, label, verdict, code, proof_kind, request_id, cf_ray]
 *   doubles = [latency_ms, http_status]
 *   indexes = [label]
 *
 * `route` is one of a fixed set (`/v1/verify`, `/v1/credentials`, `/health`,
 * `/.well-known/bolyra-signers.json`, `other`) — never a raw path. `label` is
 * `<org_id>:<role>` for an authenticated request (including one refused for
 * the wrong role), or `unauthenticated`. `verdict` is `allow`/`deny` only for
 * verifier verdicts; a successful resource route records `ok`, so verifier
 * allow-rate queries stay pure without a route filter. `request_id` is the
 * server-generated UUID (also the `x-bolyra-request-id` header); `cf_ray` is the
 * edge ray id when it has the documented shape, else '' — appended last so no
 * earlier blob position moved when it was added.
 */
interface Usage {
  route: string;
  label: string;
  /** `allow`/`deny` are verifier verdicts; `ok` is a successful resource route; `error` is any non-2xx non-verdict. */
  verdict: 'allow' | 'deny' | 'ok' | 'error';
  code: string; // deny code, transport-error code, or '' on success
  kind: string; // verdict proof kind ('classical'), '' for non-verdicts
  requestId: string;
  /** The validated `cf-ray`, or '' (a correlation field, never an identifier we issue). */
  cfRay: string;
  latencyMs: number;
  status: number;
}

/** Fire-and-forget: an Analytics Engine outage must never affect verdicts. */
function writeUsage(env: Env, usage: Usage): void {
  try {
    env.USAGE?.writeDataPoint({
      blobs: [usage.route, usage.label, usage.verdict, usage.code, usage.kind, usage.requestId, usage.cfRay],
      doubles: [usage.latencyMs, usage.status],
      indexes: [usage.label],
    });
  } catch {
    // Observability failures are swallowed by design.
  }
}

export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    const start = Date.now();
    const requestId = newRequestId();
    const cfRay = cfRayFrom(request);
    const correlation = cfRay !== undefined ? { cf_ray: cfRay } : {};
    const url = new URL(request.url);

    let route = 'other';
    let label = UNAUTHENTICATED;
    let outcome: Usage['verdict'] = 'error';
    let code = '';
    let kind = '';
    // Left uninitialized on purpose: a Gate case that forgets to assign it is a
    // compile error (definite assignment), so the switches stay exhaustive.
    let response: Response;
    const credentials = CREDENTIALS_ROUTE.exec(url.pathname);

    if (url.pathname === '/health') {
      route = '/health';
      if (request.method !== 'GET') {
        code = 'method_not_allowed';
        response = errorJson(405, 'method_not_allowed', undefined, { allow: 'GET' });
      } else {
        response = await handleHealth(env);
        if (response.ok) {
          outcome = 'ok'; // a resource route, not a verifier verdict
        } else {
          code = 'degraded';
        }
      }
    } else if (url.pathname === '/v1/verify') {
      route = '/v1/verify';
      if (request.method !== 'POST') {
        code = 'method_not_allowed';
        response = errorJson(405, 'method_not_allowed', undefined, { allow: 'POST' });
      } else {
        const gate = authorize(request, env, 'verifier');
        switch (gate.kind) {
          case 'config_error': {
            outcome = 'deny';
            code = gate.verdict.code;
            kind = gate.verdict.kind;
            response = verdictResponse(gate.verdict, undefined, env);
            break;
          }
          case 'unauthenticated': {
            code = 'unauthorized';
            response = errorJson(401, 'unauthorized', { hint: 'Authorization: Bearer <token>' });
            break;
          }
          case 'forbidden': {
            label = tenantLabel(gate.auth);
            code = 'forbidden';
            response = errorJson(403, 'forbidden');
            break;
          }
          case 'disabled': {
            label = tenantLabel(gate.auth);
            const verdict = quarantineVerdict(gate.auth.org_id);
            outcome = 'deny';
            code = verdict.code;
            kind = verdict.kind;
            response = verdictResponse(verdict, undefined, env);
            break;
          }
          case 'ok': {
            label = tenantLabel(gate.auth);
            const decision = await handleVerify(request, gate.auth, gate.capabilityMap, env);
            response = decision.response;
            outcome = decision.verdict.verdict;
            code = decision.verdict.verdict === 'deny' ? decision.verdict.code : '';
            kind = decision.verdict.kind;
            // One structured line per decision (Workers Logs). Never a body, token or IP.
            console.info('hosted-verify decision', {
              request_id: requestId,
              ...correlation,
              org_id: gate.auth.org_id,
              role: gate.auth.role,
              route,
              verdict: outcome,
              code,
              ...(decision.credential_id !== undefined ? { credential_id: decision.credential_id } : {}),
              latency_ms: Date.now() - start,
            });
            break;
          }
        }
      }
    } else if (credentials !== null) {
      // Registry routes: the analytics route is the family name, never a path with an id in it.
      route = '/v1/credentials';
      const id = credentials[1];
      const action = credentials[2]; // '/revoke' | '/repair-history' | undefined
      const method = id === undefined || action !== undefined ? 'POST' : 'GET';
      if (id !== undefined && !CREDENTIAL_ID_PATTERN.test(id)) {
        // Before method and auth: a malformed id is "no such credential" for every
        // caller, so the response cannot depend on who asks or how.
        code = 'not_found';
        response = registryError(404, 'not_found', 'no such credential');
      } else if (request.method !== method) {
        code = 'method_not_allowed';
        response = errorJson(405, 'method_not_allowed', { message: `use ${method}` }, { allow: method });
      } else {
        const gate = authorize(request, env, 'admin');
        switch (gate.kind) {
          case 'config_error': {
            code = 'internal_error';
            response = registryError(500, 'internal_error', CONFIG_ERROR_MESSAGE);
            break;
          }
          case 'unauthenticated': {
            code = 'unauthorized';
            response = registryError(401, 'unauthorized', 'Authorization: Bearer <admin token>');
            break;
          }
          case 'forbidden': {
            label = tenantLabel(gate.auth);
            code = 'forbidden';
            response = errorJson(403, 'forbidden');
            break;
          }
          case 'disabled': {
            label = tenantLabel(gate.auth);
            console.warn('hosted-verify tenant disabled:', { org_id: gate.auth.org_id });
            code = 'tenant_disabled';
            response = registryError(503, 'tenant_disabled', 'this tenant is disabled');
            break;
          }
          case 'ok': {
            label = tenantLabel(gate.auth);
            let result: RouteOutcome;
            try {
              // Inside the guard: a missing or unapplied TENANT Durable Object binding fails here,
              // not as a bare exception.
              const registry = registryFor(env, gate.auth);
              if (id === undefined) {
                result = await handleRegister(request, gate.auth, registry, requestId);
              } else {
                switch (action) {
                  case '/revoke':
                    result = await handleRevoke(registry, id, requestId);
                    break;
                  case '/repair-history':
                    result = await handleRepairHistory(registry, id);
                    break;
                  default:
                    result = await handleGet(registry, id);
                }
              }
            } catch (e) {
              // The object itself never throws, but the RPC transport can (the
              // object was reset or evicted mid-call, a connection was lost), an
              // outcome outside the union can arrive across a rolling deploy, and
              // stored text is re-parsed once. Every such failure is the documented
              // 500 with its analytics point — never a bare runtime exception.
              // Static metadata only: a JSON.parse SyntaxError quotes the offending
              // text, and stored text is tenant data — never put it in a log line.
              console.error('hosted-verify registry call failed:', {
                org_id: gate.auth.org_id,
                request_id: requestId,
                error: e instanceof Error ? e.name : typeof e,
              });
              result = fail(500, 'internal_error', 'registry storage failure');
            }
            response = result.response;
            code = result.code;
            outcome = response.status < 300 ? 'ok' : 'error';
            // One structured line per registry request (Workers Logs). Never a body, token or IP.
            const loggedId = result.credential_id ?? id;
            console.info('hosted-verify registry request', {
              request_id: requestId,
              ...correlation,
              org_id: gate.auth.org_id,
              role: gate.auth.role,
              route,
              verdict: outcome,
              code,
              ...(loggedId !== undefined ? { credential_id: loggedId } : {}),
              latency_ms: Date.now() - start,
            });
            break;
          }
        }
      }
    } else if (url.pathname === '/.well-known/bolyra-signers.json') {
      // Receipt Signer Discovery v1 (spec/receipt-signer-discovery-v1.md):
      // public, like /health — publishing the signer address is the point.
      route = '/.well-known/bolyra-signers.json';
      if (request.method !== 'GET') {
        code = 'method_not_allowed';
        response = errorJson(405, 'method_not_allowed', undefined, { allow: 'GET' });
      } else {
        const doc = buildSignerDiscoveryDoc(env);
        if (doc === undefined) {
          code = 'not_found';
          response = errorJson(404, 'not_found', { hint: 'receipt signing is not configured' });
        } else {
          outcome = 'allow';
          response = json(200, doc);
        }
      }
    } else {
      code = 'not_found';
      response = errorJson(404, 'not_found', {
        routes: [
          'GET /health',
          'POST /v1/verify',
          'POST /v1/credentials',
          'GET /v1/credentials/{id}',
          'POST /v1/credentials/{id}/revoke',
          'POST /v1/credentials/{id}/repair-history',
          'GET /.well-known/bolyra-signers.json',
        ],
      });
    }

    const usage: Usage = {
      route,
      label,
      verdict: outcome,
      code,
      kind,
      requestId,
      cfRay: cfRay ?? '',
      latencyMs: Date.now() - start,
      status: response.status,
    };
    // After the response is decided; writeDataPoint itself is non-blocking.
    if (ctx !== undefined) {
      ctx.waitUntil(Promise.resolve().then(() => writeUsage(env, usage)));
    } else {
      writeUsage(env, usage);
    }

    // Every response, whatever route produced it, names its request id. Rebuilt rather than
    // mutated: a Response's headers may be immutable. A null body (the 204) stays null.
    const tagged = new Response(response.body, response);
    tagged.headers.set('x-bolyra-request-id', requestId);
    return tagged;
  },
};
