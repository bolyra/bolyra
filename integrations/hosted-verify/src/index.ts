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
 * NOT in this preview (deliberately): SLAs, billing, metering, dashboards,
 * multi-tenancy, zk verification, custom policy UI, customer-managed keys.
 */

import {
  verifyClassical,
  CHECKS_AUTHENTICATED,
  CHECKS_CONSISTENCY,
  CHECKS_NOT_PERFORMED,
} from './verify/core';
import { deny, type Verdict } from './verify/verdict';
import { buildReceiptHeader } from './receipt';

export interface Env {
  PREVIEW_TOKEN?: string;
  TRUSTED_OPERATORS?: string;
  CAPABILITY_MAP?: string;
  RECEIPT_SIGNER_KEY?: string;
  RECEIPT_ISSUER?: string;
  RECEIPT_KEY_ID?: string;
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

function authorized(request: Request, env: Env): boolean {
  const token = env.PREVIEW_TOKEN;
  if (token === undefined || token === '') return false; // fail closed
  const header = request.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match === null || match[1] === undefined) return false;
  return timingSafeEqual(match[1], token);
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

async function handleVerify(request: Request, env: Env): Promise<Response> {
  if (!authorized(request, env)) {
    return json(401, { error: 'unauthorized', hint: 'Authorization: Bearer <preview token>' });
  }

  const text = await readBodyCapped(request);
  if (text === null) {
    return verdictResponse(
      deny('malformed_input', `request body exceeds the ${MAX_BODY_BYTES}-byte bound`),
      undefined,
      env,
    );
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return verdictResponse(deny('malformed_input', 'request body is not valid JSON'), undefined, env);
  }

  return verdictResponse(verifyClassical(body, env), body, env);
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      if (request.method !== 'GET') {
        return json(405, { error: 'method_not_allowed' }, { allow: 'GET' });
      }
      return handleHealth(env);
    }

    if (url.pathname === '/v1/verify') {
      if (request.method !== 'POST') {
        return json(405, { error: 'method_not_allowed' }, { allow: 'POST' });
      }
      return handleVerify(request, env);
    }

    return json(404, { error: 'not_found', routes: ['GET /health', 'POST /v1/verify'] });
  },
};
