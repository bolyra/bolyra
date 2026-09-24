/**
 * Observability tests: per-tenant tokens (TENANTS) and the Workers Analytics
 * Engine usage data point.
 *
 * Invariants under test:
 *   - TENANTS authenticates with constant-time comparison per token; the usage
 *     label is `<org_id>:<role>` (or `unauthenticated`).
 *   - Exactly ONE data point per request, with the documented shape:
 *       blobs   = [route, label, verdict, code, proof_kind, request_id, cf_ray]
 *       doubles = [latency_ms, http_status]
 *       indexes = [label]
 *   - The point NEVER contains bodies, proofs, credentials, tokens, or IPs.
 *   - An Analytics Engine outage never affects the verdict (fail-tolerant).
 */

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';

import worker, { type Env } from '../src/index';
import { postVerify, BASE, TOKENS, ORGS, registerFixture, fixtureRegistration, getCredential } from './helpers';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import registrations from './fixtures/registrations.json';

beforeAll(async () => {
  await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
  await registerFixture(fixtureRegistration(allowAgentOnly), 'C');
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RAY = '0123456789abcdef-SJC';
const HOSTILE_RAY = `"); DROP TABLE history; --`;

interface DataPoint {
  blobs?: string[];
  doubles?: number[];
  indexes?: string[];
}

/** Env with a capturing mock USAGE binding. */
function usageEnv(overrides: Partial<Env> = {}): { env: Env; points: DataPoint[] } {
  const points: DataPoint[] = [];
  const usage = {
    writeDataPoint(point: DataPoint) {
      points.push(point);
    },
  } as AnalyticsEngineDataset;
  return { env: { ...(env as Env), USAGE: usage, ...overrides }, points };
}

function verifyRequest(token: string | null, body: unknown = allowAgentOnly): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token !== null) headers['authorization'] = `Bearer ${token}`;
  return new Request(`${BASE}/v1/verify`, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

describe('per-tenant tokens (TENANTS)', () => {
  it('each tenant verifier token authenticates and is judged against ITS trusted operators', async () => {
    for (const [token, expected] of [
      [TOKENS.A.verifier, 'allow'],
      [TOKENS.C.verifier, 'allow'],
      [TOKENS.B.verifier, 'deny'], // org-b does not trust the fixture operator
    ] as const) {
      const res = await postVerify(allowAgentOnly, { token });
      expect(res.status).toBe(200);
      expect(((await res.json()) as Record<string, unknown>).verdict).toBe(expected);
    }
  });

  it('labels the data point `<org_id>:<role>`', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), e);
    expect(res.status).toBe(200);
    expect(points[0]!.blobs![1]).toBe(`${ORGS.A}:verifier`);
    expect(points[0]!.indexes).toEqual([`${ORGS.A}:verifier`]);
  });

  it('an admin token is attributed to ITS tenant but recorded as a forbidden error', async () => {
    for (const [token, org] of [
      [TOKENS.A.admin, ORGS.A],
      [TOKENS.B.admin, ORGS.B],
    ] as const) {
      const { env: e, points } = usageEnv();
      const res = await worker.fetch(verifyRequest(token), e);
      expect(res.status).toBe(403);
      expect(points[0]!.blobs!.slice(0, 5)).toEqual(['/v1/verify', `${org}:admin`, 'error', 'forbidden', '']);
      expect(points[0]!.indexes).toEqual([`${org}:admin`]);
    }
  });

  it('rejects a wrong token', async () => {
    expect((await postVerify(allowAgentOnly, { token: 'not-a-real-token' })).status).toBe(401);
  });

  it('rejects a token that is a prefix of a real token', async () => {
    expect((await postVerify(allowAgentOnly, { token: TOKENS.A.verifier.slice(0, -1) })).status).toBe(401);
  });

  it('malformed TENANTS → 500 verdict recorded as unauthenticated / deny / internal_error', async () => {
    const { env: e, points } = usageEnv({ TENANTS: '{not json' });
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), e);
    expect(res.status).toBe(500);
    expect(points[0]!.blobs!.slice(0, 5)).toEqual(['/v1/verify', 'unauthenticated', 'deny', 'internal_error', 'classical']);
    expect(points[0]!.doubles![1]).toBe(500);
  });

  it('unset TENANTS → 500 verdict (never "all tenants trusted")', async () => {
    const { env: e } = usageEnv({ TENANTS: '' });
    expect((await worker.fetch(verifyRequest('anything'), e)).status).toBe(500);
  });
});

describe('Analytics Engine usage data point', () => {
  it('allow → one point with the documented shape', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), e);
    expect(res.status).toBe(200);

    expect(points).toHaveLength(1);
    const p = points[0]!;
    expect(p.blobs).toHaveLength(7);
    expect(p.blobs!.slice(0, 5)).toEqual(['/v1/verify', `${ORGS.A}:verifier`, 'allow', '', 'classical']);
    expect(p.blobs![5]).toMatch(UUID); // server-generated request id
    expect(p.blobs![6]).toBe(''); // no cf-ray on this request
    expect(p.doubles).toHaveLength(2);
    expect(p.doubles![0]).toBeGreaterThanOrEqual(0); // latency_ms
    expect(p.doubles![1]).toBe(200); // http status
    expect(p.indexes).toEqual([`${ORGS.A}:verifier`]);
  });

  it('deny → point carries verdict "deny" and the deny code', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier, { ...allowAgentOnly, version: 2 }), e);
    expect(res.status).toBe(200);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 5)).toEqual([
      '/v1/verify',
      `${ORGS.A}:verifier`,
      'deny',
      'unsupported_version',
      'classical',
    ]);
    expect(points[0]!.doubles![1]).toBe(200);
  });

  it('internal_error deny → verdict "deny", code "internal_error", status 500', async () => {
    const { env: e, points } = usageEnv({ CAPABILITY_MAP: '{not json' });
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), e);
    expect(res.status).toBe(500);
    expect(points[0]!.blobs!.slice(2, 4)).toEqual(['deny', 'internal_error']);
    expect(points[0]!.doubles![1]).toBe(500);
  });

  it('auth failure → label "unauthenticated", verdict "error", code "unauthorized"', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest('wrong-token'), e);
    expect(res.status).toBe(401);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 5)).toEqual([
      '/v1/verify',
      'unauthenticated',
      'error',
      'unauthorized',
      '',
    ]);
    expect(points[0]!.doubles![1]).toBe(401);
    expect(points[0]!.indexes).toEqual(['unauthenticated']);
  });

  it('health and unknown routes are recorded without tenant attribution', async () => {
    const { env: e, points } = usageEnv();
    await worker.fetch(new Request(`${BASE}/health`), e);
    await worker.fetch(new Request(`${BASE}/does/not/exist`), e);
    expect(points).toHaveLength(2);
    expect(points[0]!.blobs!.slice(0, 4)).toEqual(['/health', 'unauthenticated', 'ok', '']); // a resource route, not a verdict
    // Unknown paths are normalized to "other" — never store attacker-chosen URLs.
    expect(points[1]!.blobs!.slice(0, 4)).toEqual(['other', 'unauthenticated', 'error', 'not_found']);
    expect(points[1]!.doubles![1]).toBe(404);
  });

  it('a degraded /health (503) is recorded as an error with code "degraded", not an allow', async () => {
    const { env: e, points } = usageEnv({ TENANTS: '{not json' });
    const res = await worker.fetch(new Request(`${BASE}/health`), e);
    expect(res.status).toBe(503);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 4)).toEqual(['/health', 'unauthenticated', 'error', 'degraded']);
    expect(points[0]!.doubles![1]).toBe(503);
  });

  it('never stores tokens, bodies, proofs, or credentials', async () => {
    const { env: e, points } = usageEnv();
    await worker.fetch(verifyRequest(TOKENS.A.verifier), e);
    const flat = JSON.stringify(points[0]);
    expect(flat).not.toContain(TOKENS.A.verifier);
    expect(flat).not.toContain(allowAgentOnly.request.agent_name);
    expect(flat).not.toContain('publicSignals');
    expect(flat).not.toContain(allowAgentOnly.bundle.slice(0, 32));
  });

  it('writes via ctx.waitUntil when an ExecutionContext is provided', async () => {
    const { env: e, points } = usageEnv();
    const ctx = createExecutionContext();
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), e, ctx);
    expect(res.status).toBe(200);
    await waitOnExecutionContext(ctx);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs![2]).toBe('allow');
  });

  it('an Analytics Engine outage never affects the verdict', async () => {
    const broken = {
      writeDataPoint() {
        throw new Error('AE is down');
      },
    } as AnalyticsEngineDataset;
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), {
      ...(env as Env),
      USAGE: broken,
    });
    expect(res.status).toBe(200);
    const v = (await res.json()) as Record<string, unknown>;
    expect(v.verdict).toBe('allow');
  });

  it('a missing USAGE binding never affects the verdict', async () => {
    const e = { ...(env as Env) };
    delete e.USAGE;
    const res = await worker.fetch(verifyRequest(TOKENS.A.verifier), e);
    expect(res.status).toBe(200);
  });

  it('registry routes are recorded as /v1/credentials with the admin label; ids never reach the route blob', async () => {
    const { env: e, points } = usageEnv();
    const valid = (registrations as { valid: { body: unknown; credential_id: string } }).valid;
    const res = await worker.fetch(
      new Request(`${BASE}/v1/credentials`, {
        method: 'POST',
        headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' },
        body: JSON.stringify(valid.body),
      }),
      e,
    );
    expect(res.status).toBe(201);
    expect(points[0]!.blobs!.slice(0, 5)).toEqual(['/v1/credentials', `${ORGS.A}:admin`, 'ok', '', '']);
    const get = await worker.fetch(
      new Request(`${BASE}/v1/credentials/${valid.credential_id}`, { headers: { authorization: `Bearer ${TOKENS.A.admin}` } }),
      e,
    );
    expect(get.status).toBe(200);
    expect(points[1]!.blobs![0]).toBe('/v1/credentials');
    expect(JSON.stringify(points[1])).not.toContain(valid.credential_id);
  });
});

describe('one structured log line per /v1/verify decision', () => {
  it('carries request_id, org_id, role, route, verdict, code, credential_id (on allow) and latency_ms — and never a token or body', async () => {
    const lines: unknown[] = [];
    const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => { lines.push(args); });
    try {
      const res = await postVerify(allowAgentOnly);
      expect(res.status).toBe(200);
      const decision = lines.find((l) => Array.isArray(l) && l[0] === 'hosted-verify decision') as [string, Record<string, unknown>] | undefined;
      expect(decision).toBeDefined();
      const line = decision![1];
      expect(Object.keys(line).sort()).toEqual(['code', 'credential_id', 'latency_ms', 'org_id', 'request_id', 'role', 'route', 'verdict']);
      expect(line.org_id).toBe(ORGS.A);
      expect(line.role).toBe('verifier');
      expect(line.route).toBe('/v1/verify');
      expect(line.verdict).toBe('allow');
      expect(line.code).toBe('');
      expect(line.credential_id).toMatch(/^[0-9a-f]{64}$/);
      expect(typeof line.latency_ms).toBe('number');
      const flat = JSON.stringify(line);
      expect(flat).not.toContain(TOKENS.A.verifier);
      expect(flat).not.toContain(allowAgentOnly.bundle.slice(0, 32));
      expect(flat).not.toContain('publicSignals');
    } finally {
      spy.mockRestore();
    }
  });

  it('a registry request logs the same shape; register names the id it minted, get names the path id', async () => {
    const lines: unknown[] = [];
    const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => { lines.push(args); });
    let id: string;
    try {
      id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
      await getCredential(id);
    } finally {
      spy.mockRestore();
    }
    const reg = lines.filter((l) => Array.isArray(l) && l[0] === 'hosted-verify registry request') as [string, Record<string, unknown>][];
    expect(reg).toHaveLength(2);
    expect(reg[0]![1].credential_id).toBe(id);
    expect(reg[1]![1].credential_id).toBe(id);
    expect(reg[1]![1].route).toBe('/v1/credentials');
    expect(reg[1]![1].role).toBe('admin');
    expect(Object.keys(reg[0]![1]).sort()).toEqual(['code', 'credential_id', 'latency_ms', 'org_id', 'request_id', 'role', 'route', 'verdict']);
    expect(JSON.stringify(reg)).not.toContain(TOKENS.A.admin);
  });

  it('a deny before the registry read logs no credential_id', async () => {
    const lines: unknown[] = [];
    const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => { lines.push(args); });
    try {
      await postVerify({ ...allowAgentOnly, version: 2 });
      const decision = lines.find((l) => Array.isArray(l) && l[0] === 'hosted-verify decision') as [string, Record<string, unknown>];
      expect(decision[1].verdict).toBe('deny');
      expect(decision[1].code).toBe('unsupported_version');
      expect(decision[1]).not.toHaveProperty('credential_id');
    } finally {
      spy.mockRestore();
    }
  });
});

/** Spy on console.info for one call; returns the captured lines by message. */
async function captureInfo<T>(fn: () => Promise<T>): Promise<{ result: T; lines: Array<[string, Record<string, unknown>]> }> {
  const lines: Array<[string, Record<string, unknown>]> = [];
  const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => {
    lines.push(args as [string, Record<string, unknown>]);
  });
  try {
    return { result: await fn(), lines };
  } finally {
    spy.mockRestore();
  }
}

function withRay(req: Request, ray: string | null): Request {
  const headers = new Headers(req.headers);
  if (ray !== null) headers.set('cf-ray', ray);
  return new Request(req, { headers });
}

describe('request id vs cf-ray correlation (E17)', () => {
  it.each([
    ['a valid cf-ray', RAY, RAY],
    ['a valid cf-ray without a colo suffix', '0123456789abcdef', '0123456789abcdef'],
    ['no cf-ray', null, ''],
    ['a hostile cf-ray', HOSTILE_RAY, ''],
  ])('analytics: request_id is a server UUID; cf_ray is its own trailing blob (%s)', async (_n, ray, blob) => {
    const { env: e, points } = usageEnv();
    await worker.fetch(withRay(verifyRequest(TOKENS.A.verifier), ray), e);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs).toHaveLength(7);
    expect(points[0]!.blobs![5]).toMatch(UUID);
    expect(points[0]!.blobs![6]).toBe(blob);
  });

  it('the decision and registry log lines carry cf_ray only when it is valid; request_id is always a UUID', async () => {
    const valid = (registrations as { valid: { body: unknown } }).valid;
    const register = (ray: string | null) =>
      withRay(
        new Request(`${BASE}/v1/credentials`, {
          method: 'POST',
          headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' },
          body: JSON.stringify(valid.body),
        }),
        ray,
      );
    for (const [ray, expected] of [[RAY, RAY], [null, undefined], [HOSTILE_RAY, undefined]] as const) {
      const { lines } = await captureInfo(async () => {
        await worker.fetch(withRay(verifyRequest(TOKENS.A.verifier), ray), env as Env);
        await worker.fetch(register(ray), env as Env);
      });
      const decision = lines.find((l) => l[0] === 'hosted-verify decision')![1];
      const registry = lines.find((l) => l[0] === 'hosted-verify registry request')![1];
      for (const line of [decision, registry]) {
        expect(line.request_id).toMatch(UUID);
        if (expected === undefined) expect(line).not.toHaveProperty('cf_ray');
        else expect(line.cf_ray).toBe(expected);
      }
      expect(JSON.stringify(lines)).not.toContain('DROP TABLE');
    }
  });
});

describe('x-bolyra-request-id response header (T6)', () => {
  const header = (res: Response) => res.headers.get('x-bolyra-request-id');

  it.each([
    ['200 verify', () => verifyRequest(TOKENS.A.verifier), {}, 200],
    ['401 no token', () => verifyRequest(null), {}, 401],
    ['403 wrong role', () => verifyRequest(TOKENS.A.admin), {}, 403],
    ['404 unknown route', () => new Request(`${BASE}/does/not/exist`), {}, 404],
    ['405 wrong method', () => new Request(`${BASE}/v1/verify`), {}, 405],
    ['503 degraded health', () => new Request(`${BASE}/health`), { TENANTS: '{not json' }, 503],
    ['500 config-error verdict', () => verifyRequest(TOKENS.A.verifier), { CAPABILITY_MAP: '{not json' }, 500],
  ] as const)('%s carries a UUID request id, distinct per request', async (_n, make, overrides, status) => {
    const e = { ...(env as Env), ...overrides };
    const a = await worker.fetch(make(), e);
    const b = await worker.fetch(make(), e);
    expect(a.status).toBe(status);
    expect(header(a)).toMatch(UUID);
    expect(header(b)).toMatch(UUID);
    expect(header(a)).not.toBe(header(b));
    // The header is ADDED, never a replacement: the preview headers survive.
    expect(a.headers.get('x-bolyra-preview')).toBe('design-partner-preview');
  });

  it('a valid cf-ray never becomes the request id header', async () => {
    const res = await worker.fetch(withRay(verifyRequest(TOKENS.A.verifier), RAY), env as Env);
    expect(header(res)).toMatch(UUID);
  });

  it('204 revoke: header present, body still empty; register and revoke headers equal their log lines\' request_id', async () => {
    const valid = (registrations as { valid: { body: unknown; credential_id: string } }).valid;
    const { result, lines } = await captureInfo(async () => {
      const reg = await worker.fetch(
        new Request(`${BASE}/v1/credentials`, {
          method: 'POST',
          headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' },
          body: JSON.stringify(valid.body),
        }),
        env as Env,
      );
      const rev = await worker.fetch(
        new Request(`${BASE}/v1/credentials/${valid.credential_id}/revoke`, {
          method: 'POST',
          headers: { authorization: `Bearer ${TOKENS.A.admin}` },
        }),
        env as Env,
      );
      return { reg, rev };
    });
    expect([200, 201]).toContain(result.reg.status);
    expect(result.rev.status).toBe(204);
    expect(await result.rev.text()).toBe('');
    expect(result.rev.body).toBeNull();
    expect(result.rev.headers.get('cache-control')).toBe('no-store');
    const registry = lines.filter((l) => l[0] === 'hosted-verify registry request').map((l) => l[1].request_id);
    expect(registry).toEqual([header(result.reg), header(result.rev)]);
  });

  it('a verify decision line and its response header share the request id', async () => {
    const { result, lines } = await captureInfo(() => worker.fetch(verifyRequest(TOKENS.A.verifier), env as Env));
    const decision = lines.find((l) => l[0] === 'hosted-verify decision')![1];
    expect(decision.request_id).toBe(header(result));
  });
});
