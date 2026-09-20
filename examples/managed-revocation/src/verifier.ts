/**
 * Direct calls to the hosted verifier — the evidence the gate cannot surface. The gate's
 * `callUrlVerifier` discards response headers, and its Problem Details body carries the
 * verdict message rather than `detail`; so the `x-bolyra-credential-id` header, the signed
 * receipt header, and a deny's structured `detail` are read here, from the verifier itself.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseBundle, type IssuedMandate } from '@bolyra/mpp';

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

export async function health(v: HostedVerifier): Promise<Health> {
  const res = await fetch(`${v.url}/health`);
  if (res.status !== 200) throw new Error(`GET /health → HTTP ${res.status}`);
  return (await res.json()) as Health;
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
  const body = (await res.json()) as { credential_id?: unknown; error?: unknown };
  if (res.status === 201 || res.status === 200) {
    if (typeof body.credential_id !== 'string' || !/^[0-9a-f]{64}$/.test(body.credential_id)) {
      throw new Error(`POST /v1/credentials → HTTP ${res.status} without a credential_id`);
    }
    return { status: res.status, credential_id: body.credential_id };
  }
  if (res.status === 409) return { status: 409, error: typeof body.error === 'string' ? body.error : undefined };
  throw new Error(`POST /v1/credentials → HTTP ${res.status}: ${JSON.stringify(body)}`);
}

export async function revoke(v: HostedVerifier, credentialId: string): Promise<number> {
  const res = await fetch(`${v.url}/v1/credentials/${credentialId}/revoke`, {
    method: 'POST',
    headers: { authorization: `Bearer ${v.adminToken}` },
  });
  if (res.status !== 204) throw new Error(`POST /v1/credentials/{id}/revoke → HTTP ${res.status}: ${await res.text()}`);
  return res.status;
}

export interface VerifyOutcome {
  status: number;
  verdict: Record<string, unknown>;
  credentialIdHeader: string | null;
  receiptHeader: string | null;
}

/** Present a mandate to `POST /v1/verify` with the request shape the gate sends, keeping the response headers. */
export async function verify(v: HostedVerifier, mandate: IssuedMandate): Promise<VerifyOutcome> {
  const body = {
    version: 1,
    bundle: mandate.presentation,
    request: {
      agent_name: mandate.agentName,
      project_key: mandate.audience,
      program: mandate.program,
      model: mandate.model,
      granted_capabilities: [`mpp:financial:${mandate.tier}`],
    },
    now_unix: Math.floor(Date.now() / 1000),
  };
  const res = await fetch(`${v.url}/v1/verify`, {
    method: 'POST',
    headers: { authorization: `Bearer ${v.verifierToken}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return {
    status: res.status,
    verdict: (await res.json()) as Record<string, unknown>,
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
    const cli = fileURLToPath(new URL('../node_modules/@bolyra/cli/dist/main.js', import.meta.url));
    return execFileSync(
      process.execPath,
      [cli, 'receipt', 'verify', file, '--signer-from', `${v.url}/.well-known/bolyra-signers.json`],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ).trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
