/**
 * Bolyra hosted verify — DESIGN PARTNER PREVIEW.
 *
 * External Verifier Contract v1 over HTTP (spec/external-verifier-contract-v1.md):
 *
 *   POST /v1/verify   Bearer-auth'd. Body = the spec §2.1 request object (the
 *                     same JSON `bolyra verify` reads on stdin). Response body
 *                     = exactly one strict §3.4 verdict object, always
 *                     `kind: "classical"` (spec §3.5). Fail-closed everywhere.
 *   GET  /health      Unauthenticated status + preview labeling + the exact
 *                     list of checks this preview does / does not perform.
 *
 * HTTP mapping of the CLI exit-code semantics (§7.1): every decision-level
 * verdict (allow or policy/crypto deny) is HTTP 200; `deny internal_error`
 * (the CLI's "non-zero exit" case) is HTTP 500. Auth/transport failures
 * (401/404/405) happen BEFORE the contract and carry an `{ "error": ... }`
 * body, not a verdict.
 *
 * NOT in this preview (deliberately): SLAs, billing, dashboards,
 * multi-tenancy, zk verification, custom policy UI, customer-managed keys.
 * Observability IS here: Workers Logs + one Analytics Engine data point per
 * request (labels/verdicts/latency only — see README "Observability").
 */

import {
  verifyClassical,
  CHECKS_AUTHENTICATED,
  CHECKS_CONSISTENCY,
  CHECKS_NOT_PERFORMED,
} from './verify/core';
import { deny, type Verdict } from './verify/verdict';
import { buildReceiptHeader, buildSignerDiscoveryDoc } from './receipt';

export interface Env {
  PREVIEW_TOKEN?: string;
  /** JSON object mapping partner label → bearer token, e.g. {"theseus":"…"}. */
  PARTNER_TOKENS?: string;
  TRUSTED_OPERATORS?: string;
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

/** Constant-time byte comparison (no early exit on mismatch). */
function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) {
    diff |= (ab[i % ab.length] ?? 0) ^ (bb[i % bb.length] ?? 0);
  }
  return diff === 0;
}

/** Reserved partner label recorded for requests with no valid bearer token. */
const UNAUTHENTICATED = 'unauthenticated';

/**
 * Resolve the presented bearer token to a partner label, or null.
 *
 * Two token sources, both optional (no source configured = fail closed):
 *   - PARTNER_TOKENS: JSON object mapping label → token. Named bearer tokens
 *     only — NOT multi-tenant admin. Malformed JSON, non-string tokens, empty
 *     labels/tokens, and the reserved "unauthenticated" label grant nothing.
 *   - PREVIEW_TOKEN: the legacy shared token, kept working as label "preview".
 *
 * Every candidate token is compared with the constant-time comparator, and
 * ALL candidates are always scanned (no early exit on match).
 */
function authenticate(request: Request, env: Env): string | null {
  const header = request.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match === null || match[1] === undefined) return null;
  const presented = match[1];

  let label: string | null = null;

  if (env.PARTNER_TOKENS !== undefined && env.PARTNER_TOKENS !== '') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(env.PARTNER_TOKENS);
    } catch {
      parsed = undefined; // malformed mapping grants nothing (fail closed)
    }
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      for (const [name, token] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof token !== 'string' || token === '') continue;
        if (name === '' || name === UNAUTHENTICATED) continue;
        if (timingSafeEqual(presented, token) && label === null) label = name;
      }
    }
  }

  if (
    env.PREVIEW_TOKEN !== undefined &&
    env.PREVIEW_TOKEN !== '' &&
    timingSafeEqual(presented, env.PREVIEW_TOKEN) &&
    label === null
  ) {
    label = 'preview';
  }

  return label;
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

async function handleVerify(
  request: Request,
  env: Env,
): Promise<{ verdict: Verdict; response: Response }> {
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

  const verdict = verifyClassical(body, env);
  return { verdict, response: verdictResponse(verdict, body, env) };
}

function handleHealth(env: Env): Response {
  return json(200, {
    status: 'ok',
    service: 'bolyra-hosted-verify',
    phase: 'DESIGN PARTNER PREVIEW — not a production service, no SLA',
    contract: 'external-verifier-contract-v1 (spec/external-verifier-contract-v1.md)',
    verifier_kind: 'classical',
    nonce_mode: 'host',
    receipts_enabled: env.RECEIPT_SIGNER_KEY !== undefined && env.RECEIPT_SIGNER_KEY !== '',
    trust_model:
      'an allow means a configured trusted operator (TRUSTED_OPERATORS) signed a binding ' +
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
 *   blobs   = [route, partner_label, verdict, code, proof_kind, request_id]
 *   doubles = [latency_ms, http_status]
 *   indexes = [partner_label]
 */
interface Usage {
  route: string; // '/v1/verify' | '/health' | 'other' (never raw paths)
  label: string; // partner label, or 'unauthenticated'
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
    let response: Response;

    if (url.pathname === '/health') {
      route = '/health';
      if (request.method !== 'GET') {
        code = 'method_not_allowed';
        response = json(405, { error: 'method_not_allowed' }, { allow: 'GET' });
      } else {
        outcome = 'allow';
        response = handleHealth(env);
      }
    } else if (url.pathname === '/v1/verify') {
      route = '/v1/verify';
      if (request.method !== 'POST') {
        code = 'method_not_allowed';
        response = json(405, { error: 'method_not_allowed' }, { allow: 'POST' });
      } else {
        const partner = authenticate(request, env);
        if (partner === null) {
          code = 'unauthorized';
          response = json(401, { error: 'unauthorized', hint: 'Authorization: Bearer <token>' });
        } else {
          label = partner;
          const { verdict, response: verdictRes } = await handleVerify(request, env);
          response = verdictRes;
          outcome = verdict.verdict;
          code = verdict.verdict === 'deny' ? verdict.code : '';
          kind = verdict.kind;
        }
      }
    } else if (url.pathname === '/.well-known/bolyra-signers.json') {
      // Receipt Signer Discovery v1 (spec/receipt-signer-discovery-v1.md):
      // public, like /health — publishing the signer address is the point.
      route = '/.well-known/bolyra-signers.json';
      if (request.method !== 'GET') {
        code = 'method_not_allowed';
        response = json(405, { error: 'method_not_allowed' }, { allow: 'GET' });
      } else {
        const doc = buildSignerDiscoveryDoc(env);
        if (doc === undefined) {
          code = 'not_found';
          response = json(404, { error: 'not_found', hint: 'receipt signing is not configured' });
        } else {
          outcome = 'allow';
          response = json(200, doc);
        }
      }
    } else {
      code = 'not_found';
      response = json(404, {
        error: 'not_found',
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
