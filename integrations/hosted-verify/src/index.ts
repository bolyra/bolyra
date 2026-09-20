/**
 * Bolyra hosted verify — DESIGN PARTNER PREVIEW.
 *
 * External Verifier Contract v1 over HTTP (spec/external-verifier-contract-v1.md):
 *
 *   POST /v1/verify   Verifier-token auth. Body = the spec §2.1 request object
 *                     (the same JSON `bolyra verify` reads on stdin). Response
 *                     body = exactly one strict §3.4 verdict object, always
 *                     `kind: "classical"` (spec §3.5). Fail-closed everywhere.
 *   GET  /health      Unauthenticated status + preview labeling + the exact
 *                     list of checks this preview does / does not perform.
 *
 * Tenancy and roles (src/tenants.ts): the `TENANTS` secret maps an org id to
 * an admin token, a verifier token and that tenant's trusted operator keys.
 * Tenant and role derive exclusively from which token matched; no route
 * accepts an org id from the request.
 *
 *   request ──► loadTenants(TENANTS) ──defect──► 500 deny internal_error
 *                    │                            (/health: tenants:"invalid")
 *                    ▼
 *              resolveAuth(token) ──none──► 401 { error: "unauthorized" }
 *                    │
 *                    ├── role ≠ verifier ──► 403 { error: "forbidden" }
 *                    ├── tenant.disabled ─► 500 deny internal_error
 *                    └── ok ──► verifyClassical(body, tenant.trusted_operators, capabilityMap)
 *
 * HTTP mapping of the CLI exit-code semantics (§7.1): every decision-level
 * verdict (allow or policy/crypto deny) is HTTP 200; `deny internal_error`
 * (the CLI's "non-zero exit" case) is HTTP 500. Auth/transport failures
 * (401/403/404/405) happen BEFORE the contract and carry an `{ "error": ... }`
 * body, not a verdict.
 *
 * NOT in this preview (deliberately): SLAs, billing, dashboards, tenant
 * self-service, zk verification, custom policy UI, customer-managed keys.
 * Observability IS here: Workers Logs + one Analytics Engine data point per
 * request (labels/verdicts/latency only — see README "Observability").
 */

import {
  verifyClassical,
  CHECKS_AUTHENTICATED,
  CHECKS_CONSISTENCY,
  CHECKS_NOT_PERFORMED,
} from './verify/core';
import { loadCapabilityMap, type CapabilityMap } from './verify/capabilities';
import { deny, isVerifyDenial, type DenyVerdict, type Verdict } from './verify/verdict';
import { loadTenants, resolveAuth, type AuthResult, type Role, type TenantConfig } from './tenants';
import { buildReceiptHeader, buildSignerDiscoveryDoc } from './receipt';

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
}

/** Request-body bound — mirrors the spec §6 1 MiB stdin bound. */
const MAX_BODY_BYTES = 1_048_576;

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
 * Read the request body with a hard byte cap. Returns the decoded text, or
 * null when the body exceeds the bound (a fail-closed `malformed_input`).
 */
async function readBodyCapped(request: Request): Promise<string | null> {
  const declared = request.headers.get('content-length');
  if (declared !== null && Number(declared) > MAX_BODY_BYTES) return null;

  const reader = request.body?.getReader();
  if (reader === undefined) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8').decode(merged);
}

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
  return deny('internal_error', 'missing or invalid trust configuration');
}

/**
 * A quarantined tenant is refused with the same fail-closed 500 verdict as a
 * configuration defect, but it is NOT one: logged at warn level, no stack, so
 * an alert on configuration errors never fires on parked-tenant traffic.
 */
function quarantineVerdict(orgId: string): DenyVerdict {
  console.warn('hosted-verify tenant disabled:', { org_id: orgId });
  return deny('internal_error', 'missing or invalid trust configuration');
}

/** Outcome of authenticating a request for a route that requires `required`. */
type Gate =
  | { kind: 'config_error'; verdict: DenyVerdict }
  | { kind: 'unauthenticated' }
  | { kind: 'forbidden'; auth: AuthResult }
  | { kind: 'disabled'; auth: AuthResult }
  | { kind: 'ok'; auth: AuthResult };

/**
 * auth → quarantine → role, in that order. The tenant map is re-parsed per
 * request (≤ 4 KiB; a rotated secret takes effect on the next request).
 */
function authorize(request: Request, env: Env, required: Role): Gate {
  let tenants: Map<string, TenantConfig>;
  try {
    tenants = loadTenants(env.TENANTS);
  } catch (e) {
    return { kind: 'config_error', verdict: configErrorVerdict(e) };
  }
  const auth = resolveAuth(request, tenants);
  if (auth === null) return { kind: 'unauthenticated' };
  // Quarantine outranks role: NO route serves a disabled tenant, whichever of
  // its tokens is presented.
  if (auth.disabled) return { kind: 'disabled', auth };
  if (auth.role !== required) return { kind: 'forbidden', auth };
  return { kind: 'ok', auth };
}

async function handleVerify(
  request: Request,
  trustedOperators: ReadonlySet<string>,
  env: Env,
): Promise<{ verdict: Verdict; response: Response }> {
  // Configuration first: a defect must not depend on what the body says.
  let capabilityMap: CapabilityMap;
  try {
    capabilityMap = loadCapabilityMap(env.CAPABILITY_MAP);
  } catch (e) {
    const verdict = configErrorVerdict(e);
    return { verdict, response: verdictResponse(verdict, undefined, env) };
  }

  const text = await readBodyCapped(request);
  if (text === null) {
    const verdict = deny('malformed_input', `request body exceeds the ${MAX_BODY_BYTES}-byte bound`);
    return { verdict, response: verdictResponse(verdict, undefined, env) };
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    const verdict = deny('malformed_input', 'request body is not valid JSON');
    return { verdict, response: verdictResponse(verdict, undefined, env) };
  }

  const verdict = verifyClassical(body, trustedOperators, capabilityMap);
  return { verdict, response: verdictResponse(verdict, body, env) };
}

function handleHealth(env: Env): Response {
  // /health is the diagnostic surface: a broken TENANTS is REPORTED here at
  // 200, never thrown (the authenticated routes are the ones that fail closed).
  let tenants: 'ok' | 'invalid' = 'ok';
  try {
    loadTenants(env.TENANTS);
  } catch {
    tenants = 'invalid';
  }
  return json(200, {
    status: 'ok',
    service: 'bolyra-hosted-verify',
    phase: 'DESIGN PARTNER PREVIEW — not a production service, no SLA',
    contract: 'external-verifier-contract-v1 (spec/external-verifier-contract-v1.md)',
    verifier_kind: 'classical',
    nonce_mode: 'host',
    tenants,
    receipts_enabled: env.RECEIPT_SIGNER_KEY !== undefined && env.RECEIPT_SIGNER_KEY !== '',
    trust_model:
      'an allow means an operator the calling tenant configured as trusted signed a binding ' +
      'authorizing this exact request. The proof itself is NOT verified — the Merkle root and ' +
      'all public signals are unverified. Sound scope/expiry enforcement requires the zk-class ' +
      '`bolyra verify` CLI.',
    checks_authenticated: CHECKS_AUTHENTICATED,
    checks_consistency_only: CHECKS_CONSISTENCY,
    checks_not_performed: CHECKS_NOT_PERFORMED,
  });
}

/**
 * One structured Analytics Engine data point per request — and NOTHING else.
 * Explicitly never stored: request bodies, proofs, credentials, bearer
 * tokens, IPs. Documented in README "Observability" (trust statement).
 *
 *   blobs   = [route, label, verdict, code, proof_kind, request_id]
 *   doubles = [latency_ms, http_status]
 *   indexes = [label]
 *
 * `label` is `<org_id>:<role>` for an authenticated request (including one
 * refused for the wrong role), or `unauthenticated`.
 */
interface Usage {
  route: string; // '/v1/verify' | '/health' | 'other' (never raw paths)
  label: string; // '<org_id>:<role>' or 'unauthenticated'
  verdict: 'allow' | 'deny' | 'error';
  code: string; // deny code, transport-error code, or '' on allow
  kind: string; // verdict proof kind ('classical'), '' for non-verdicts
  requestId: string;
  latencyMs: number;
  status: number;
}

/** Fire-and-forget: an Analytics Engine outage must never affect verdicts. */
function writeUsage(env: Env, usage: Usage): void {
  try {
    env.USAGE?.writeDataPoint({
      blobs: [usage.route, usage.label, usage.verdict, usage.code, usage.kind, usage.requestId],
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
    const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID();
    const url = new URL(request.url);

    let route = 'other';
    let label = UNAUTHENTICATED;
    let outcome: Usage['verdict'] = 'error';
    let code = '';
    let kind = '';
    // Left uninitialized on purpose: a Gate case that forgets to assign it is a
    // compile error (definite assignment), so the switch stays exhaustive.
    let response: Response;

    if (url.pathname === '/health') {
      route = '/health';
      if (request.method !== 'GET') {
        code = 'method_not_allowed';
        response = errorJson(405, 'method_not_allowed', undefined, { allow: 'GET' });
      } else {
        outcome = 'allow';
        response = handleHealth(env);
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
            const { verdict, response: verdictRes } = await handleVerify(request, gate.auth.trusted_operators, env);
            response = verdictRes;
            outcome = verdict.verdict;
            code = verdict.verdict === 'deny' ? verdict.code : '';
            kind = verdict.kind;
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
        routes: ['GET /health', 'POST /v1/verify', 'GET /.well-known/bolyra-signers.json'],
      });
    }

    const usage: Usage = {
      route,
      label,
      verdict: outcome,
      code,
      kind,
      requestId,
      latencyMs: Date.now() - start,
      status: response.status,
    };
    // After the response is decided; writeDataPoint itself is non-blocking.
    if (ctx !== undefined) {
      ctx.waitUntil(Promise.resolve().then(() => writeUsage(env, usage)));
    } else {
      writeUsage(env, usage);
    }

    return response;
  },
};
