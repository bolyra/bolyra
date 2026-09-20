import { SELF } from 'cloudflare:test';
import type { SignedReceipt } from '@bolyra/receipts';
import { TOKENS } from './tenants-fixture';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';

export { ORGS, TOKENS, ORG_B_OPERATOR_KEY, buildTestTenants } from './tenants-fixture';

export const BASE = 'https://hosted-verify.test';

/** The conformance fixture's operator key, canonical `x:y`. */
export const FIXTURE_OPERATOR_KEY = (() => {
  const { operator_pubkey } = (JSON.parse(allowAgentOnly.bundle) as {
    agent: { credential: { operator_pubkey: { x: string; y: string } } };
  }).agent.credential;
  return `${operator_pubkey.x}:${operator_pubkey.y}`;
})();

/**
 * POST a body to /v1/verify as org-a's VERIFIER (the default caller). Objects
 * are JSON-encoded; strings sent raw. `token: null` sends no Authorization.
 */
export async function postVerify(
  body: unknown,
  opts: { token?: string | null } = {},
): Promise<Response> {
  const token = opts.token === undefined ? TOKENS.A.verifier : opts.token;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token !== null) headers['authorization'] = `Bearer ${token}`;
  return SELF.fetch(`${BASE}/v1/verify`, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

/** Decode the base64url `x-bolyra-receipt` header into the signed receipt it carries. */
export function decodeReceipt(header: string): SignedReceipt {
  const b64 = header.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as SignedReceipt;
}

/** Deep-clone a fixture request and re-materialize its bundle as an object. */
export function cloneWithBundle(fixture: { bundle: string } & Record<string, unknown>): {
  request: Record<string, unknown>;
  bundle: Record<string, unknown>;
  commit: () => Record<string, unknown>;
} {
  const request = structuredClone(fixture) as Record<string, unknown>;
  const bundle = JSON.parse(fixture.bundle) as Record<string, unknown>;
  return {
    request,
    bundle,
    commit() {
      request.bundle = JSON.stringify(bundle);
      return request;
    },
  };
}

/** Registry routes, as a tenant ADMIN (org-a by default). */
export const CREDENTIALS = `${BASE}/v1/credentials`;

function adminHeaders(token: string | null): Record<string, string> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token !== null) headers['authorization'] = `Bearer ${token}`;
  return headers;
}

export async function postRegister(body: unknown, opts: { token?: string | null; headers?: Record<string, string> } = {}): Promise<Response> {
  const token = opts.token === undefined ? TOKENS.A.admin : opts.token;
  return SELF.fetch(CREDENTIALS, {
    method: 'POST',
    headers: { ...adminHeaders(token), ...(opts.headers ?? {}) },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

export async function getCredential(id: string, opts: { token?: string | null } = {}): Promise<Response> {
  const token = opts.token === undefined ? TOKENS.A.admin : opts.token;
  return SELF.fetch(`${CREDENTIALS}/${id}`, { method: 'GET', headers: adminHeaders(token) });
}

export async function postRevoke(id: string, opts: { token?: string | null; headers?: Record<string, string> } = {}): Promise<Response> {
  const token = opts.token === undefined ? TOKENS.A.admin : opts.token;
  return SELF.fetch(`${CREDENTIALS}/${id}/revoke`, {
    method: 'POST',
    headers: { ...adminHeaders(token), ...(opts.headers ?? {}) },
  });
}

/** The registration body `registerFixture` posts to `/v1/credentials`. */
export interface FixtureRegistration {
  version: number;
  binding: unknown;
  signature: { R8: { x: string; y: string }; S: string };
  operator_pubkey: { x: string; y: string };
}

/**
 * Register a signed binding for `org` (admin token) so that org's verifier
 * gets an allow for presentations of it. Storage isolation is per test FILE:
 * call this in a `beforeAll` of every spec whose allow assertions depend on
 * it. Returns the credential id.
 */
export async function registerFixture(
  registration: FixtureRegistration,
  org: keyof typeof TOKENS = 'A',
): Promise<string> {
  const res = await postRegister(registration, { token: TOKENS[org].admin });
  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`registerFixture(${org}) → ${res.status}: ${await res.text()}`);
  }
  const { credential_id: id } = (await res.json()) as { credential_id?: unknown };
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error(`registerFixture(${org}) → ${res.status} without a credential_id`);
  }
  return id;
}

/** Builds the registration body for any conformance request fixture presenting a signed binding (generic over `{ bundle: string }`), for `registerFixture`. */
export function fixtureRegistration(fixture: { bundle: string }): FixtureRegistration {
  const b = JSON.parse(fixture.bundle) as {
    binding: unknown;
    sig: { R8: { x: string; y: string }; S: string };
    agent: { credential: { operator_pubkey: { x: string; y: string } } };
  };
  return {
    version: 1,
    binding: b.binding,
    signature: { R8: { x: b.sig.R8.x, y: b.sig.R8.y }, S: b.sig.S },
    operator_pubkey: { x: b.agent.credential.operator_pubkey.x, y: b.agent.credential.operator_pubkey.y },
  };
}
