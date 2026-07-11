/**
 * Observability tests: labeled partner tokens (PARTNER_TOKENS) and the
 * Workers Analytics Engine usage data point.
 *
 * Invariants under test:
 *   - PARTNER_TOKENS (JSON label → token) authenticates with constant-time
 *     comparison per token; legacy PREVIEW_TOKEN keeps working as "preview".
 *   - Exactly ONE data point per request, with the documented shape:
 *       blobs   = [route, partner_label, verdict, code, proof_kind, request_id]
 *       doubles = [latency_ms, http_status]
 *       indexes = [partner_label]
 *   - The point NEVER contains bodies, proofs, credentials, tokens, or IPs.
 *   - An Analytics Engine outage never affects the verdict (fail-tolerant).
 */

import { describe, expect, it } from 'vitest';
import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';

import worker, { type Env } from '../src/index';
import { postVerify, BASE, TOKEN } from './helpers';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';

// Labeled tokens injected by vitest.config.mts (test-only values).
const THESEUS_TOKEN = 'theseus-test-token';
const INTERNAL_TOKEN = 'internal-test-token';

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

describe('labeled partner tokens (PARTNER_TOKENS)', () => {
  it('accepts each configured partner token', async () => {
    for (const token of [THESEUS_TOKEN, INTERNAL_TOKEN]) {
      const res = await postVerify(allowAgentOnly, { token });
      expect(res.status).toBe(200);
      const v = (await res.json()) as Record<string, unknown>;
      expect(v.verdict).toBe('allow');
    }
  });

  it('legacy PREVIEW_TOKEN keeps working (label "preview")', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest(TOKEN), e);
    expect(res.status).toBe(200);
    expect(points[0]!.blobs![1]).toBe('preview');
    expect(points[0]!.indexes).toEqual(['preview']);
  });

  it('rejects a wrong token even with partners configured', async () => {
    const res = await postVerify(allowAgentOnly, { token: 'not-a-real-token' });
    expect(res.status).toBe(401);
  });

  it('rejects a token that is a prefix of a partner token', async () => {
    const res = await postVerify(allowAgentOnly, { token: THESEUS_TOKEN.slice(0, -1) });
    expect(res.status).toBe(401);
  });

  it('fails closed on malformed PARTNER_TOKENS JSON (PREVIEW_TOKEN unaffected)', async () => {
    const { env: e } = usageEnv({ PARTNER_TOKENS: '{not json' });
    expect((await worker.fetch(verifyRequest(THESEUS_TOKEN), e)).status).toBe(401);
    expect((await worker.fetch(verifyRequest(TOKEN), e)).status).toBe(200);
  });

  it('ignores non-string, empty, and reserved-label entries', async () => {
    const { env: e } = usageEnv({
      PARTNER_TOKENS: JSON.stringify({
        bad: 42,
        empty: '',
        unauthenticated: 'reserved-label-token',
        good: 'good-token',
      }),
    });
    expect((await worker.fetch(verifyRequest('reserved-label-token'), e)).status).toBe(401);
    expect((await worker.fetch(verifyRequest(''), e)).status).toBe(401);
    const { env: e2, points } = usageEnv({
      PARTNER_TOKENS: JSON.stringify({ good: 'good-token' }),
    });
    const res = await worker.fetch(verifyRequest('good-token'), e2);
    expect(res.status).toBe(200);
    expect(points[0]!.blobs![1]).toBe('good');
  });

  it('fails closed when neither PARTNER_TOKENS nor PREVIEW_TOKEN is set', async () => {
    const { env: e } = usageEnv({ PARTNER_TOKENS: '', PREVIEW_TOKEN: '' });
    expect((await worker.fetch(verifyRequest('anything'), e)).status).toBe(401);
  });
});

describe('Analytics Engine usage data point', () => {
  it('allow → one point with the documented shape', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest(THESEUS_TOKEN), e);
    expect(res.status).toBe(200);

    expect(points).toHaveLength(1);
    const p = points[0]!;
    expect(p.blobs).toHaveLength(6);
    expect(p.blobs!.slice(0, 5)).toEqual(['/v1/verify', 'theseus', 'allow', '', 'classical']);
    expect(p.blobs![5]).toMatch(/\S/); // request id present
    expect(p.doubles).toHaveLength(2);
    expect(p.doubles![0]).toBeGreaterThanOrEqual(0); // latency_ms
    expect(p.doubles![1]).toBe(200); // http status
    expect(p.indexes).toEqual(['theseus']);
  });

  it('deny → point carries verdict "deny" and the deny code', async () => {
    const { env: e, points } = usageEnv();
    const res = await worker.fetch(verifyRequest(THESEUS_TOKEN, { ...allowAgentOnly, version: 2 }), e);
    expect(res.status).toBe(200);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 5)).toEqual([
      '/v1/verify',
      'theseus',
      'deny',
      'unsupported_version',
      'classical',
    ]);
    expect(points[0]!.doubles![1]).toBe(200);
  });

  it('internal_error deny → verdict "deny", code "internal_error", status 500', async () => {
    const { env: e, points } = usageEnv({ TRUSTED_OPERATORS: '' });
    const res = await worker.fetch(verifyRequest(THESEUS_TOKEN), e);
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

  it('health and unknown routes are recorded without partner attribution', async () => {
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
    await worker.fetch(verifyRequest(THESEUS_TOKEN), e);
    const flat = JSON.stringify(points[0]);
    expect(flat).not.toContain(THESEUS_TOKEN);
    expect(flat).not.toContain(allowAgentOnly.request.agent_name);
    expect(flat).not.toContain('publicSignals');
    expect(flat).not.toContain(allowAgentOnly.bundle.slice(0, 32));
  });

  it('writes via ctx.waitUntil when an ExecutionContext is provided', async () => {
    const { env: e, points } = usageEnv();
    const ctx = createExecutionContext();
    const res = await worker.fetch(verifyRequest(THESEUS_TOKEN), e, ctx);
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
    const res = await worker.fetch(verifyRequest(THESEUS_TOKEN), {
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
    const res = await worker.fetch(verifyRequest(THESEUS_TOKEN), e);
    expect(res.status).toBe(200);
  });
});
