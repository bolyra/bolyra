/**
 * Observability tests: per-tenant tokens (TENANTS) and the Workers Analytics
 * Engine usage data point.
 *
 * Invariants under test:
 *   - TENANTS authenticates with constant-time comparison per token; the usage
 *     label is `<org_id>:<role>` (or `unauthenticated`).
 *   - Exactly ONE data point per request, with the documented shape:
 *       blobs   = [route, label, verdict, code, proof_kind, request_id]
 *       doubles = [latency_ms, http_status]
 *       indexes = [label]
 *   - The point NEVER contains bodies, proofs, credentials, tokens, or IPs.
 *   - An Analytics Engine outage never affects the verdict (fail-tolerant).
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';

import worker, { type Env } from '../src/index';
import { postVerify, BASE, TOKENS, ORGS, registerFixture, fixtureRegistration } from './helpers';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import registrations from './fixtures/registrations.json';

beforeAll(async () => {
  await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
  await registerFixture(fixtureRegistration(allowAgentOnly), 'C');
});

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
    expect(p.blobs).toHaveLength(6);
    expect(p.blobs!.slice(0, 5)).toEqual(['/v1/verify', `${ORGS.A}:verifier`, 'allow', '', 'classical']);
    expect(p.blobs![5]).toMatch(/\S/); // request id present
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
    expect(points[0]!.blobs!.slice(0, 4)).toEqual(['/health', 'unauthenticated', 'allow', '']);
    // Unknown paths are normalized to "other" — never store attacker-chosen URLs.
    expect(points[1]!.blobs!.slice(0, 4)).toEqual(['other', 'unauthenticated', 'error', 'not_found']);
    expect(points[1]!.doubles![1]).toBe(404);
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
