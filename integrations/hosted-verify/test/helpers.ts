import { SELF } from 'cloudflare:test';
import { TOKENS } from './tenants-fixture';

export { ORGS, TOKENS, ORG_B_OPERATOR_KEY, buildTestTenants } from './tenants-fixture';

export const BASE = 'https://hosted-verify.test';

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
