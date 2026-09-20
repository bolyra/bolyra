/**
 * Direct calls to the hosted verifier — the evidence the gate cannot surface. The gate's
 * `callUrlVerifier` discards response headers, and its Problem Details body carries the
 * verdict message rather than `detail`; so the `x-bolyra-credential-id` header, the signed
 * receipt header, and a deny's structured `detail` are read here, from the verifier itself.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseBundle, tierCapability, type IssuedMandate } from '@bolyra/mpp';

export interface HostedVerifier {
  url: string;
  adminToken: string;
  verifierToken: string;
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
  if (res.status !== 200) throw new Error(`GET /health → HTTP ${res.status} (${bytes}-byte body withheld)`);
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
      throw new Error(`POST /v1/credentials → HTTP ${res.status} without a credential_id`);
    }
    return { status: res.status, credential_id: body.credential_id };
  }
  if (res.status === 409) return { status: 409, error: typeof body.error === 'string' ? body.error : undefined };
  throw new Error(`POST /v1/credentials → HTTP ${res.status} (${bytes}-byte body withheld)`);
}

export async function revoke(v: HostedVerifier, credentialId: string): Promise<number> {
  const res = await fetch(`${v.url}/v1/credentials/${credentialId}/revoke`, {
    method: 'POST',
    headers: { authorization: `Bearer ${v.adminToken}` },
  });
  if (res.status !== 204) throw new Error(`POST /v1/credentials/{id}/revoke → HTTP ${res.status} (${Buffer.byteLength(await res.text())}-byte body withheld)`);
  return res.status;
}

export interface VerifyOutcome {
  status: number;
  verdict: Record<string, unknown>;
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
  const body = {
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
  const res = await fetch(`${v.url}/v1/verify`, {
    method: 'POST',
    headers: { authorization: `Bearer ${v.verifierToken}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const { bytes, body: verdict } = await jsonOf(res);
  if (Object.keys(verdict).length === 0) throw new Error(`POST /v1/verify → HTTP ${res.status} with a non-JSON body (${bytes} bytes withheld)`);
  return {
    status: res.status,
    verdict,
    credentialIdHeader: res.headers.get('x-bolyra-credential-id'),
    receiptHeader: res.headers.get('x-bolyra-receipt'),
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
