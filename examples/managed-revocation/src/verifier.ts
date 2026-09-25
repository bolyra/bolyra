/**
 * Direct calls to the hosted verifier — the evidence the gate does not put on the wire.
 * The gate's `callUrlVerifier` returns the verdict only and discards response headers;
 * `callUrlVerifierWithEvidence` (@bolyra/mpp 0.7.0) makes the same fail-closed call and
 * keeps the HTTP status and the raw `x-bolyra-credential-id` / `x-bolyra-receipt` headers,
 * so `verify()` below no longer hand-rolls the transport. The signed receipt header, the
 * credential id header, and a deny's structured `detail` are read here, from the verifier
 * itself; registration, revocation, and /health are plain admin calls.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  callUrlVerifierWithEvidence,
  parseBundle,
  tierCapability,
  type IssuedMandate,
  type Verdict,
  type VerifierRequest,
} from '@bolyra/mpp';

/**
 * An error whose message is ours — a route, a status, a byte count — and therefore safe
 * to print. Any other error's message may quote server- or environment-supplied text
 * (Node quotes an invalid header value, for instance), so run.ts prints only these.
 */
export class DiagnosticError extends Error {
  override readonly name = 'DiagnosticError' as const;
}

export interface HostedVerifier {
  url: string;
  adminToken: string;
  verifierToken: string;
}

/**
 * Every route here is `${url}/<route>`, so `url` must be the verifier's origin: a path
 * prefix would reach /health and /v1/credentials and then fail closed on /v1/verify.
 * Throws a DiagnosticError in our words for anything but `http(s)://host[:port][/]`
 * or for a spelling the URL parser still refuses (its message may quote the input,
 * so it is never surfaced).
 */
export function assertVerifierOrigin(url: string): void {
  // Judged on the spelling as written, not on the parsed URL: `new URL()` collapses dot
  // segments and trims whitespace, so `https://host/prefix/..` would parse as a bare origin
  // while the gate (which reads the string as written) would POST somewhere else. An
  // http(s) scheme, a host (DNS name, IPv4, or bracketed IPv6), an optional port, and at
  // most one trailing slash; no userinfo, path, query, fragment, backslash or whitespace.
  const refuse = (): never => { throw new DiagnosticError('VERIFY_URL must be the verifier origin with no path (value withheld)'); };
  if (!/^https?:\/\/(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?\/?$/.test(url)) refuse();
  // Well-spelled is not parseable (a port above 65535, a malformed IP literal): the parser's
  // TypeError would otherwise surface later as a generic failure instead of this diagnostic.
  try {
    new URL(url);
  } catch {
    refuse();
  }
}

export interface Health {
  registry_enforced?: unknown;
  receipts_enabled?: unknown;
  tenants?: unknown;
}

/**
 * Read a JSON body, or an empty object when the response is not JSON. Only the byte count
 * is handed back for error messages: a response body is never printed, so a proxy or a
 * misconfigured URL that echoes request headers cannot put a bearer token on stderr.
 */
async function jsonOf(res: Response): Promise<{ bytes: number; body: Record<string, unknown> }> {
  const text = await res.text();
  const bytes = Buffer.byteLength(text);
  try {
    const parsed: unknown = JSON.parse(text);
    return { bytes, body: typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {} };
  } catch {
    return { bytes, body: {} };
  }
}

export async function health(v: HostedVerifier): Promise<Health> {
  const res = await fetch(`${v.url}/health`);
  const { bytes, body } = await jsonOf(res);
  if (res.status !== 200) throw new DiagnosticError(`GET /health → HTTP ${res.status} (${bytes}-byte body withheld)`);
  return body as Health;
}

/** The registration body is the signed binding lifted out of a presentation the operator just issued. */
export function registrationOf(mandate: IssuedMandate): {
  version: 1;
  binding: unknown;
  signature: { R8: { x: string; y: string }; S: string };
  operator_pubkey: { x: string; y: string };
} {
  const p = parseBundle(mandate.presentation);
  return {
    version: 1,
    binding: p.binding,
    signature: { R8: { x: p.sig.R8.x, y: p.sig.R8.y }, S: p.sig.S },
    operator_pubkey: mandate.operatorPublicKey,
  };
}

export interface RegisterOutcome {
  status: number;
  /** Present on 201 (created) and 200 (already ACTIVE); absent on 409 (revoked, terminal). */
  credential_id?: string;
  error?: string;
}

export async function register(v: HostedVerifier, mandate: IssuedMandate): Promise<RegisterOutcome> {
  const res = await fetch(`${v.url}/v1/credentials`, {
    method: 'POST',
    headers: { authorization: `Bearer ${v.adminToken}`, 'content-type': 'application/json' },
    body: JSON.stringify(registrationOf(mandate)),
  });
  const { bytes, body } = await jsonOf(res);
  if (res.status === 201 || res.status === 200) {
    if (typeof body.credential_id !== 'string' || !/^[0-9a-f]{64}$/.test(body.credential_id)) {
      throw new DiagnosticError(`POST /v1/credentials → HTTP ${res.status} without a credential_id`);
    }
    return { status: res.status, credential_id: body.credential_id };
  }
  if (res.status === 409) return { status: 409, error: typeof body.error === 'string' ? body.error : undefined };
  throw new DiagnosticError(`POST /v1/credentials → HTTP ${res.status} (${bytes}-byte body withheld)`);
}

export async function revoke(v: HostedVerifier, credentialId: string): Promise<number> {
  const res = await fetch(`${v.url}/v1/credentials/${credentialId}/revoke`, {
    method: 'POST',
    headers: { authorization: `Bearer ${v.adminToken}` },
  });
  if (res.status !== 204) throw new DiagnosticError(`POST /v1/credentials/{id}/revoke → HTTP ${res.status} (${Buffer.byteLength(await res.text())}-byte body withheld)`);
  return res.status;
}

export interface VerifyOutcome {
  status: number;
  verdict: Verdict;
  credentialIdHeader: string | null;
  receiptHeader: string | null;
}

/**
 * Present a mandate to `POST /v1/verify` with the request shape the gate sends on every
 * gated request — the mandate's identity fields plus the capability the charge requires
 * (for this example's $25 charge, the mandate's `small` tier) — keeping the response
 * headers. The gate sends this on the discovery request too (the unit test asserts the
 * capability there); within a request, the payment `verify` hook consumes the decision
 * the preflight stashed rather than asking the verifier again.
 */
export async function verify(v: HostedVerifier, mandate: IssuedMandate): Promise<VerifyOutcome> {
  const request: VerifierRequest = {
    version: 1,
    bundle: mandate.presentation,
    request: {
      agent_name: mandate.agentName,
      project_key: mandate.audience,
      program: mandate.program,
      model: mandate.model,
      granted_capabilities: [tierCapability(mandate.tier)],
    },
    now_unix: Math.floor(Date.now() / 1000),
  };
  const evidence = await callUrlVerifierWithEvidence({ url: `${v.url}/v1/verify`, token: v.verifierToken }, request);
  // The SDK fails closed: an unreachable verifier, a timeout, or a body that is not a
  // verdict comes back as `deny internal_error` rather than a throw. With no status, no
  // HTTP response was received; its verdict message is the SDK's, so only our words print.
  if (evidence.status === undefined) {
    throw new DiagnosticError('POST /v1/verify → no HTTP response (unreachable, timed out, or an invalid URL; the call failed closed, details withheld)');
  }
  // 200 is a decision and 500 may carry `deny internal_error`; any other status (a wrong
  // verifier token's 401, a proxy's 404) is a misconfiguration, not a verdict worth a row.
  if (evidence.status !== 200 && evidence.status !== 500) {
    throw new DiagnosticError(`POST /v1/verify → HTTP ${evidence.status} (body withheld)`);
  }
  return {
    status: evidence.status,
    verdict: evidence.verdict,
    credentialIdHeader: evidence.credentialId ?? null,
    receiptHeader: evidence.receipt ?? null,
  };
}

/**
 * Decode the base64url receipt header into the SignedReceipt JSON the CLI reads and run
 * `bolyra receipt verify` on it, accepting the Worker's published signer set. Returns the
 * CLI's stdout (starts with `PASS:`); throws with its stderr on any failure.
 */
export function verifyReceiptWithCli(v: HostedVerifier, receiptHeader: string): string {
  const json = Buffer.from(receiptHeader, 'base64url').toString('utf8');
  const dir = mkdtempSync(path.join(tmpdir(), 'managed-revocation-'));
  const file = path.join(dir, 'receipt.json');
  try {
    writeFileSync(file, json);
    const cliDir = path.dirname(createRequire(import.meta.url).resolve('@bolyra/cli/package.json'));
    const cli = path.join(cliDir, 'dist', 'main.js');
    return execFileSync(
      process.execPath,
      [cli, 'receipt', 'verify', file, '--signer-from', `${v.url}/.well-known/bolyra-signers.json`],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ).trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
