/**
 * HTTP-surface + classical-pipeline tests for the hosted verify preview:
 * auth, routing, body bounds, fail-closed denials, zk rejection, receipts,
 * and env fail-closed behavior.
 */

import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { SELF, env, createExecutionContext } from 'cloudflare:test';
import { verifyReceipt } from '@bolyra/receipts';

import worker, { type Env } from '../src/index';
import { BODY_READ_DEADLINE_MS, REGISTRY_DEADLINE_MS } from '../src/deadlines';
import { cachedProbeRegistry, resetHealthProbeCache } from '../src/health-probe';
import { ORG_ID_PATTERN } from '../src/tenants';
import { bindingDigest } from '../src/verify/binding';
import type { Binding } from '../src/verify/bundle';
import { requiredBits, DEFAULT_CAPABILITY_MAP } from '../src/verify/capabilities';
import { verifyClassical, MAX_NONCE_RETENTION_SECONDS } from '../src/verify/core';
import { VerifyDenial } from '../src/verify/verdict';
import {
  postVerify,
  cloneWithBundle,
  BASE,
  TOKENS,
  ORGS,
  buildTestTenants,
  registerFixture,
  fixtureRegistration,
  FIXTURE_OPERATOR_KEY,
  decodeReceipt,
} from './helpers';
import { validateVerdictSchema } from './verdict-schema';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import allowHuman from '../../cli/test/fixtures/verify/allow-human/request.json';
import allowDelegation from '../../cli/test/fixtures/verify/allow-delegation-1hop/request.json';

const LEGACY_NAMES = /TRUSTED_OPERATORS|PARTNER_TOKENS|PREVIEW_TOKEN/;

// Every allow in this file presents the conformance fixture: register it for
// the tenants that trust its operator (org-a and org-c). Per-file isolation.
beforeAll(async () => {
  await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
  await registerFixture(fixtureRegistration(allowAgentOnly), 'C');
});

async function verdictOf(res: Response): Promise<Record<string, unknown>> {
  const v = (await res.json()) as Record<string, unknown>;
  expect(validateVerdictSchema(v)).toEqual({ ok: true });
  expect(v.kind).toBe('classical');
  return v;
}

function verifyReq(token: string, body: unknown = allowAgentOnly): Request {
  return new Request(`${BASE}/v1/verify`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('binding v2 digest conformance', () => {
  // CROSS-IMPLEMENTATION CONFORMANCE VECTOR (binding v2). The SAME fixed binding
  // and expected digest are pinned in @bolyra/mpp (classical.test.ts) and
  // `bolyra verify` (cli binding.test.ts). If any of the three bindingDigest
  // implementations drifts, exactly its own pinned test breaks — the three
  // cannot silently diverge and produce mutually unverifiable bundles.
  it('matches the shared v2 binding-digest conformance vector', () => {
    const vector: Binding = {
      agent_name: 'conformance-agent',
      project_key: 'api.merchant.example',
      program: 'mpp',
      model: 'opus-4.1',
      capabilities: ['mpp:financial:small', 'mpp:financial:medium'],
      expiry: 1893456000,
    };
    expect(bindingDigest(vector).toString()).toBe(
      '6852214223979096266887740803477328516969972228468997483569432332607241636802',
    );
  });
});

describe('routing + auth', () => {
  it('GET /health is public and prominently labeled as a preview', async () => {
    const res = await SELF.fetch(`${BASE}/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get('x-bolyra-preview')).toBe('design-partner-preview');
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(String(body.phase)).toContain('DESIGN PARTNER PREVIEW');
    expect(body.verifier_kind).toBe('classical');
    expect(body.nonce_mode).toBe('host');
    expect(body.tenants).toBe('ok');
    expect(body.registry).toBe('ok');
    expect(body.registry_kind).toBe('durable-object');
    expect(body.capability_map).toBe('ok');
    expect(body.registry_enforced).toBe(true);
    expect(String(body.trust_policy)).toContain('ACTIVE');
    expect(String(body.trust_model)).toContain('registry');
    expect((body.checks_authenticated as string[]).join(' ')).toContain('trusted-operator');
    expect((body.checks_consistency_only as string[]).length).toBeGreaterThan(3);
    expect((body.checks_not_performed as string[]).join(' ')).toContain('Groth16');
    expect(String(body.trust_model)).toContain('proof itself is NOT verified');
    // The legacy configuration names must not survive on any public surface.
    expect(JSON.stringify(body)).not.toMatch(LEGACY_NAMES);
  });

  // Deliberately changed from 200 (E5): a degraded service answers 503 so a probe
  // cannot mistake it for healthy. Still reported, never thrown.
  it('GET /health reports tenants:"invalid" as 503 degraded when TENANTS is malformed', async () => {
    const res = await worker.fetch(new Request(`${BASE}/health`), { ...env, TENANTS: '{not json' });
    expect(res.status).toBe(503);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('degraded');
    expect(body.tenants).toBe('invalid');
    expect(body.registry_enforced).toBe(true);
    // The components are independent: a bad TENANTS does not mark the others down.
    expect(body.capability_map).toBe('ok');
    expect(body.registry).toBe('ok');
  });

  it('unknown route → 404; wrong methods → 405', async () => {
    expect((await SELF.fetch(`${BASE}/`)).status).toBe(404);
    expect((await SELF.fetch(`${BASE}/health`, { method: 'POST' })).status).toBe(405);
    expect((await SELF.fetch(`${BASE}/v1/verify`, { method: 'GET' })).status).toBe(405);
  });

  it('POST /v1/verify without a token → 401 with the unchanged error body', async () => {
    const res = await postVerify(allowAgentOnly, { token: null });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized', hint: 'Authorization: Bearer <token>' });
  });

  it('POST /v1/verify with a wrong token → 401', async () => {
    const res = await postVerify(allowAgentOnly, { token: 'wrong-token' });
    expect(res.status).toBe(401);
  });

  it('an ADMIN token on /v1/verify → 403 with exactly { error: "forbidden" }', async () => {
    const res = await postVerify(allowAgentOnly, { token: TOKENS.A.admin });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'forbidden' });
  });

  it("another tenant's verifier (org-b does not trust the fixture operator) → deny untrusted_root", async () => {
    const res = await postVerify(allowAgentOnly, { token: TOKENS.B.verifier });
    expect(res.status).toBe(200);
    expect((await verdictOf(res)).code).toBe('untrusted_root');
  });

  it('a second tenant trusting the same operator (org-c) → allow', async () => {
    const res = await postVerify(allowAgentOnly, { token: TOKENS.C.verifier });
    expect((await verdictOf(res)).verdict).toBe('allow');
  });

  it('a disabled tenant → 500 deny internal_error; other tenants unaffected', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const disabled = await worker.fetch(verifyReq(TOKENS.A.verifier), e);
    expect(disabled.status).toBe(500);
    expect((await verdictOf(disabled)).code).toBe('internal_error');
    const other = await worker.fetch(verifyReq(TOKENS.C.verifier), e);
    expect(other.status).toBe(200);
    expect((await verdictOf(other)).verdict).toBe('allow');
    createExecutionContext(); // keep the import exercised under the workers pool
  });

  it("a disabled tenant's ADMIN token on /v1/verify → the quarantine 500, not a 403 (no route serves it)", async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(verifyReq(TOKENS.A.admin), e);
    expect(res.status).toBe(500);
    expect((await verdictOf(res)).code).toBe('internal_error');
  });

  it('GET /health reports tenants:"ok" for a parseable map even when a tenant is disabled (parseability, not availability)', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(new Request(`${BASE}/health`), e);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { tenants: string }).tenants).toBe('ok');
  });

  it('GET /health reports tenant_count for a normal map (the fixture has org-a/b/c)', async () => {
    const res = await worker.fetch(new Request(`${BASE}/health`), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { tenant_count: unknown }).tenant_count).toBe(3);
  });
});

// E13: `{}` is the deliberately EMPTY map the last tenant's removal leaves behind. It is valid
// configuration, not a defect: every authenticated route denies (401 — there is no tenant for
// any bearer to resolve to), and /health stays 200 with tenants ok and a count of 0.
describe('an empty TENANTS map ({}) — the last tenant was removed (E13)', () => {
  const empty = () => ({ ...env, TENANTS: '{}' });

  it('POST /v1/verify with a formerly valid verifier token → 401 (no tenant to resolve to)', async () => {
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), empty());
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized', hint: 'Authorization: Bearer <token>' });
  });

  it('POST /v1/verify with any other bearer → 401', async () => {
    expect((await worker.fetch(verifyReq('x'.repeat(40)), empty())).status).toBe(401);
  });

  it('POST /v1/credentials with a formerly valid admin token → 401', async () => {
    const req = new Request(`${BASE}/v1/credentials`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' },
      body: '{}',
    });
    const res = await worker.fetch(req, empty());
    expect(res.status).toBe(401);
  });

  it("GET /health → 200 ok, tenants 'ok', tenant_count 0", async () => {
    const res = await worker.fetch(new Request(`${BASE}/health`), empty());
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(body.tenants).toBe('ok');
    expect(body.tenant_count).toBe(0);
  });

  it('a MALFORMED map is still a defect: /health 503 tenants invalid, tenant_count null', async () => {
    const res = await worker.fetch(new Request(`${BASE}/health`), { ...env, TENANTS: '{not json' });
    expect(res.status).toBe(503);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.tenants).toBe('invalid');
    expect(body.tenant_count).toBeNull();
  });
});

// The registry probe is cached per isolate (src/health-probe.ts); each test starts cold.
beforeEach(() => {
  resetHealthProbeCache();
});

describe('/health probes the registry and the capability map (E5)', () => {
  type Probe = { names: string[]; ids: string[] };
  /** A fake TENANT namespace recording what the probe asked for; `status` is the behavior under test. */
  function fakeTenant(status: (id: string) => unknown): { ns: typeof env.TENANT; probe: Probe } {
    const probe: Probe = { names: [], ids: [] };
    const ns = {
      idFromName: (n: string) => {
        probe.names.push(n);
        return env.TENANT.idFromName(n);
      },
      get: () => ({
        status: (id: string) => {
          probe.ids.push(id);
          return status(id);
        },
      }),
    } as unknown as typeof env.TENANT;
    return { ns, probe };
  }
  const health = (e: Env) => worker.fetch(new Request(`${BASE}/health`), e);
  const bodyOf = async (res: Response) => (await res.json()) as Record<string, unknown>;

  it('healthy → 200 with every component ok and the build marker intact', async () => {
    const res = await health(env);
    expect(res.status).toBe(200);
    const body = await bodyOf(res);
    expect(body).toMatchObject({
      status: 'ok',
      tenants: 'ok',
      capability_map: 'ok',
      registry: 'ok',
      registry_kind: 'durable-object',
      registry_enforced: true,
    });
  });

  it('the probe names only the constant __health__ object and the all-zero credential id', async () => {
    const { ns, probe } = fakeTenant(async () => 'ABSENT');
    const res = await health({ ...env, TENANT: ns });
    expect(res.status).toBe(200);
    expect((await bodyOf(res)).registry).toBe('ok');
    expect(probe.names).toEqual(['__health__']);
    expect(probe.ids).toEqual(['0'.repeat(64)]);
  });

  it('__health__ can never be a tenant org id (ORG_ID_PATTERN forbids "_")', () => {
    expect(ORG_ID_PATTERN.test('__health__')).toBe(false);
  });

  it('a registry RPC that throws → 503 degraded, registry "unavailable"', async () => {
    const { ns } = fakeTenant(async () => {
      throw new Error('Network connection lost.');
    });
    const res = await health({ ...env, TENANT: ns });
    expect(res.status).toBe(503);
    const body = await bodyOf(res);
    expect(body.status).toBe('degraded');
    expect(body.registry).toBe('unavailable');
    expect(body.registry_kind).toBe('durable-object');
    expect(body.registry_enforced).toBe(true);
  });

  it.each(['storage_error', 'invalid_input', 'something_new'])('a registry answering %s → 503 registry "unavailable"', async (answer) => {
    const { ns } = fakeTenant(async () => answer);
    const res = await health({ ...env, TENANT: ns });
    expect(res.status).toBe(503);
    const body = await bodyOf(res);
    expect(body.status).toBe('degraded');
    expect(body.registry).toBe('unavailable');
  });

  it.each(['ABSENT', 'ACTIVE', 'REVOKED'])('a registry answering %s → registry "ok"', async (answer) => {
    const { ns } = fakeTenant(async () => answer);
    const res = await health({ ...env, TENANT: ns });
    expect(res.status).toBe(200);
    expect((await bodyOf(res)).registry).toBe('ok');
  });

  it(`a registry read that never resolves → 503 registry "timeout" at the ${REGISTRY_DEADLINE_MS} ms deadline`, async () => {
    vi.useFakeTimers();
    try {
      const { ns } = fakeTenant(() => new Promise<never>(() => {}));
      const pending = health({ ...env, TENANT: ns });
      await vi.advanceTimersByTimeAsync(REGISTRY_DEADLINE_MS + 1);
      const res = await pending;
      expect(res.status).toBe(503);
      const body = await bodyOf(res);
      expect(body.status).toBe('degraded');
      expect(body.registry).toBe('timeout');
    } finally {
      vi.useRealTimers();
    }
  });

  it('a malformed CAPABILITY_MAP → 503 degraded, capability_map "invalid"', async () => {
    const res = await health({ ...env, CAPABILITY_MAP: '{bad' });
    expect(res.status).toBe(503);
    const body = await bodyOf(res);
    expect(body.status).toBe('degraded');
    expect(body.capability_map).toBe('invalid');
    expect(body.tenants).toBe('ok');
    expect(body.registry).toBe('ok');
  });

  it('a registry stub whose status() throws SYNCHRONOUSLY → 503 registry "unavailable"', async () => {
    const { ns } = fakeTenant(() => {
      throw new Error('boom');
    });
    const res = await health({ ...env, TENANT: ns });
    expect(res.status).toBe(503);
    expect((await bodyOf(res)).registry).toBe('unavailable');
  });

  it('a fast probe leaves no deadline timer behind', async () => {
    vi.useFakeTimers();
    try {
      const { ns, probe } = fakeTenant(async () => 'ABSENT');
      const res = await health({ ...env, TENANT: ns });
      expect(res.status).toBe(200);
      expect(probe.ids).toHaveLength(1);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  describe('probe cache: single-flight, 10 s TTL, failures not cached', () => {
    it('two concurrent /health calls → exactly one status() RPC', async () => {
      const { ns, probe } = fakeTenant(async () => 'ABSENT');
      const e = { ...env, TENANT: ns };
      const [a, b] = await Promise.all([health(e), health(e)]);
      expect([a.status, b.status]).toEqual([200, 200]);
      expect(probe.ids).toHaveLength(1);
    });

    it('a healthy result is served from cache within 10 s and re-probed after it', async () => {
      vi.useFakeTimers();
      try {
        const { ns, probe } = fakeTenant(async () => 'ABSENT');
        const e = { ...env, TENANT: ns };
        await health(e);
        await vi.advanceTimersByTimeAsync(9_000);
        await health(e);
        expect(probe.ids).toHaveLength(1);
        await vi.advanceTimersByTimeAsync(1_001);
        const res = await health(e);
        expect(res.status).toBe(200);
        expect(probe.ids).toHaveLength(2);
      } finally {
        vi.useRealTimers();
      }
    });

    it('a failed probe is not served from cache: the next call re-probes', async () => {
      let answer = 'storage_error';
      const { ns, probe } = fakeTenant(async () => answer);
      const e = { ...env, TENANT: ns };
      expect((await health(e)).status).toBe(503);
      answer = 'ABSENT';
      const res = await health(e);
      expect(res.status).toBe(200);
      expect((await bodyOf(res)).registry).toBe('ok');
      expect(probe.ids).toHaveLength(2);
    });

    it('a probe that REJECTS is evicted, not cached for the isolate lifetime', async () => {
      // probeRegistry catches everything today; the injected probe stands in for a future one that does not.
      const { ns } = fakeTenant(async () => 'ABSENT');
      const failing = cachedProbeRegistry(ns, () => Promise.reject(new Error('probe bug')));
      await expect(failing).rejects.toThrow('probe bug');
      let calls = 0;
      const next = await cachedProbeRegistry(ns, async () => {
        calls++;
        return 'ok';
      });
      expect(next).toBe('ok');
      expect(calls).toBe(1);
    });

    it('a timed-out probe is not served from cache either', async () => {
      vi.useFakeTimers();
      try {
        let hang = true;
        const { ns, probe } = fakeTenant(() => (hang ? new Promise<never>(() => {}) : Promise.resolve('ABSENT')));
        const e = { ...env, TENANT: ns };
        const pending = health(e);
        await vi.advanceTimersByTimeAsync(REGISTRY_DEADLINE_MS + 1);
        expect((await pending).status).toBe(503);
        hang = false;
        expect((await health(e)).status).toBe(200);
        expect(probe.ids).toHaveLength(2);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});

describe('/health reports the deployed version (E14)', () => {
  const healthBody = async (e: Env) =>
    (await (await worker.fetch(new Request(`${BASE}/health`), e)).json()) as Record<string, unknown>;

  it('echoes the version_metadata binding as { id, tag, timestamp }', async () => {
    const body = await healthBody({ ...env, CF_VERSION_METADATA: { id: 'test-version', tag: 'v-tag', timestamp: '2026-09-24T00:00:00Z' } });
    expect(body.version).toEqual({ id: 'test-version', tag: 'v-tag', timestamp: '2026-09-24T00:00:00Z' });
  });

  it('omits an absent timestamp rather than inventing one', async () => {
    const body = await healthBody({ ...env, CF_VERSION_METADATA: { id: 'test-version', tag: '' } });
    expect(body.version).toEqual({ id: 'test-version', tag: '' });
  });

  it('reports version: null when the binding is absent (some local runs)', async () => {
    const { CF_VERSION_METADATA: _bound, ...unbound } = env;
    const body = await healthBody(unbound);
    expect(body.version).toBeNull();
    expect(body.status).toBe('ok'); // a missing version is informational, never a degradation
  });

  it('the wrangler.jsonc binding reaches the Worker (the pool provides it)', async () => {
    const body = (await (await SELF.fetch(`${BASE}/health`)).json()) as { version: { id: unknown } | null };
    expect(body.version).not.toBeNull();
    expect(typeof body.version!.id).toBe('string');
  });
});

describe('fail-closed input handling', () => {
  it('truncated JSON body → deny malformed_input (spec §13.5)', async () => {
    const res = await postVerify('{"version":1,"bun');
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('malformed_input');
  });

  it('non-object JSON body → deny malformed_input', async () => {
    const v = await verdictOf(await postVerify('42'));
    expect(v.code).toBe('malformed_input');
  });

  it('oversized body (> 1 MiB) → deny malformed_input (spec §6 bound)', async () => {
    const huge = { ...allowAgentOnly, padding: 'x'.repeat(1_100_000) };
    const v = await verdictOf(await postVerify(huge));
    expect(v.code).toBe('malformed_input');
  });

  it('request version 2 → deny unsupported_version', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, version: 2 }));
    expect(v.code).toBe('unsupported_version');
  });

  it('undecodable bundle → deny invalid_bundle', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, bundle: '!!not-base64url!!' }));
    expect(v.code).toBe('invalid_bundle');
  });

  it('bvp version 2 → deny unsupported_version', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    bundle.bvp = 2;
    const v = await verdictOf(await postVerify(commit()));
    expect(v.code).toBe('unsupported_version');
  });
});

/** A POST /v1/verify whose body is the given stream (no content-length: the reader loop decides). */
function streamingVerify(body: ReadableStream<Uint8Array>): Request {
  return new Request(`${BASE}/v1/verify`, {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' },
    body,
    duplex: 'half',
  } as RequestInit);
}

/** Env with a capturing USAGE binding, plus the decision log lines. */
function observed(): { env: Env; points: Array<{ blobs?: string[]; doubles?: number[] }> } {
  const points: Array<{ blobs?: string[]; doubles?: number[] }> = [];
  const usage = { writeDataPoint: (p: { blobs?: string[]; doubles?: number[] }) => { points.push(p); } } as unknown as AnalyticsEngineDataset;
  return { env: { ...(env as Env), USAGE: usage }, points };
}

describe('body-stream failures stay inside the verdict boundary (E7)', () => {
  it('a body stream that errors → 200 deny malformed_input, with its analytics point and decision line', async () => {
    const { env: e, points } = observed();
    const lines: unknown[][] = [];
    const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => { lines.push(args); });
    let res: Response;
    try {
      res = await worker.fetch(streamingVerify(new ReadableStream({ pull: () => Promise.reject(new Error('connection reset')) })), e);
    } finally {
      spy.mockRestore();
    }
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('malformed_input');
    expect(v.message).toBe('request body could not be read');
    expect(JSON.stringify(v)).not.toContain('connection reset');
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 5)).toEqual(['/v1/verify', `${ORGS.A}:verifier`, 'deny', 'malformed_input', 'classical']);
    expect(points[0]!.doubles![1]).toBe(200);
    const decision = lines.find((l) => l[0] === 'hosted-verify decision') as [string, Record<string, unknown>] | undefined;
    expect(decision?.[1].code).toBe('malformed_input');
  });

  it('a streamed body over the cap (no content-length) → deny malformed_input "exceeds", stream cancelled', async () => {
    let cancelled = false;
    const chunk = new Uint8Array(256 * 1024);
    const { env: e, points } = observed();
    const res = await worker.fetch(
      streamingVerify(new ReadableStream({ pull: (c) => c.enqueue(chunk), cancel: () => { cancelled = true; } })),
      e,
    );
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.code).toBe('malformed_input');
    expect(v.message).toContain('exceeds');
    expect(cancelled).toBe(true);
    expect(points[0]!.blobs!.slice(2, 4)).toEqual(['deny', 'malformed_input']);
  });

  it('a cancel() that rejects on overflow is best-effort: still deny malformed_input', async () => {
    const chunk = new Uint8Array(512 * 1024);
    const res = await worker.fetch(
      streamingVerify(new ReadableStream({ pull: (c) => c.enqueue(chunk), cancel: () => Promise.reject(new Error('cancel failed')) })),
      env as Env,
    );
    expect(res.status).toBe(200);
    expect((await verdictOf(res)).code).toBe('malformed_input');
  });

  it(`a body that never arrives → 500 deny internal_error "request body stalled" at ${BODY_READ_DEADLINE_MS} ms; no timer left`, async () => {
    vi.useFakeTimers();
    try {
      const { env: e, points } = observed();
      const pending = worker.fetch(streamingVerify(new ReadableStream({ pull: () => new Promise<void>(() => {}) })), e);
      await vi.advanceTimersByTimeAsync(BODY_READ_DEADLINE_MS + 1);
      const res = await pending;
      expect(res.status).toBe(500);
      const v = await verdictOf(res);
      expect(v.code).toBe('internal_error');
      expect(v.message).toBe('request body stalled');
      expect(points).toHaveLength(1);
      expect(points[0]!.blobs!.slice(2, 4)).toEqual(['deny', 'internal_error']);
      expect(points[0]!.doubles![1]).toBe(500);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('a normal request leaves no body-read timer behind', async () => {
    vi.useFakeTimers();
    try {
      const res = await worker.fetch(verifyReq(TOKENS.A.verifier), env as Env);
      expect(res.status).toBe(200);
      expect((await verdictOf(res)).verdict).toBe('allow');
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('classical-only scope', () => {
  it('explicit request kind "zk" → clear deny', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, kind: 'zk' }));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_proof');
    expect(String(v.message)).toContain('classical');
    expect(String(v.message)).toContain('zk');
  });

  it('explicit request kind "classical" is accepted', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, kind: 'classical' }));
    expect(v.verdict).toBe('allow');
  });

  it('human-backed bundle → deny (zk-only slot)', async () => {
    const v = await verdictOf(await postVerify(allowHuman));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_proof');
    expect((v.detail as Record<string, unknown>).slots).toEqual(['human']);
  });

  it('delegation-bearing bundle → deny (zk-only slot)', async () => {
    const v = await verdictOf(await postVerify(allowDelegation));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_proof');
    expect((v.detail as Record<string, unknown>).slots).toEqual(['delegation']);
  });
});

describe('classical pipeline', () => {
  it('valid agent-only bundle → allow with host-mode consume_nonces', async () => {
    const res = await postVerify(allowAgentOnly);
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('allow');

    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      agent: {
        envelope: { publicSignals: string[] };
        credential: { operator_pubkey: { x: string; y: string }; expiry: number };
      };
    };
    const nonces = v.consume_nonces as Array<Record<string, unknown>>;
    expect(nonces).toHaveLength(1);
    expect(nonces[0]!.nonce).toBe(bundle.agent.envelope.publicSignals[1]);
    expect(nonces[0]!.issuer_key).toBe(
      `${bundle.agent.credential.operator_pubkey.x}:${bundle.agent.credential.operator_pubkey.y}`,
    );
    // `retain_until` is CLAMPED, not the raw credential expiry. This fixture
    // expires in 2100, and asking a host to retain a nonce for ~75 years makes
    // its replay store unbounded. The verifier states a bounded retention
    // instead — EVC constrains what a host must retain, never what a verifier
    // may ask for.
    const clamped = allowAgentOnly.now_unix + MAX_NONCE_RETENTION_SECONDS;
    expect(nonces[0]!.retain_until).toBe(clamped);
    expect(nonces[0]!.retain_until).toBeLessThan(bundle.agent.credential.expiry);
  });

  it('retain_until is the credential expiry when that is inside the window', async () => {
    // The clamp is a ceiling, not a floor. Move the caller's clock to just
    // inside the fixture's expiry — no re-signing needed, since the binding
    // signs the expiry, not the clock — and the credential's own expiry
    // becomes the smaller of the two. Nothing is ever retained past the life
    // of the credential it protects.
    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      agent: { credential: { expiry: number } };
    };
    const expiry = bundle.agent.credential.expiry;
    const res = await postVerify({ ...allowAgentOnly, now_unix: expiry - 600 });
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('allow');
    const nonces = v.consume_nonces as Array<Record<string, unknown>>;
    expect(nonces[0]!.retain_until).toBe(expiry);
  });

  it('inflated permission bitmask → deny invalid_proof (scope anchor, F2)', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    (bundle.agent as { credential: { permission_bitmask: string } }).credential.permission_bitmask =
      '255';
    const v = await verdictOf(await postVerify(commit()));
    expect(v.code).toBe('invalid_proof');
  });

  it('binding v2: signed binding.expiry ≠ credential.expiry → deny invalid_bundle', async () => {
    // The signed binding.expiry is unchanged (signature still verifies) but the
    // credential.expiry the strict-expiry check would consume is re-anchored
    // forward — the §5b equality catches the divergence.
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    (bundle.agent as { credential: { expiry: number } }).credential.expiry = 4200000000;
    const v = await verdictOf(await postVerify(commit()));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_bundle');
  });

  it('binding v2: an obsolete v1 binding (no expiry) → deny unsupported_version', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    delete (bundle.binding as Record<string, unknown>).expiry;
    const v = await verdictOf(await postVerify(commit()));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('unsupported_version');
  });

  it("operator key not in the tenant's trusted_operators → deny untrusted_root", async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    // A different (untrusted) operator key. The signature will not verify
    // either, but the trust-anchor gate fires first.
    (bundle.agent as { credential: { operator_pubkey: { x: string; y: string } } }).credential
      .operator_pubkey = { x: '12345', y: '67890' };
    const v = await verdictOf(await postVerify(commit()));
    expect(v.code).toBe('untrusted_root');
  });

  // Regression for the Codex P1: WITHOUT proof verification, an attacker who
  // generates their own operator key, copies a trusted root into the public
  // signals, recomputes the scopeCommitment, and self-signs the binding must
  // STILL be denied — the trust anchor is the operator key set, not the
  // (unverified) Merkle root.
  it('forged bundle signed by an attacker-generated key → deny (not allow)', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    const agent = bundle.agent as {
      envelope: { publicSignals: string[] };
      credential: { operator_pubkey: { x: string; y: string }; permission_bitmask: string };
    };
    // Attacker-chosen operator key + a fresh (non-trusted) signature would be
    // needed; even copying the trusted root into signals[0] must not help.
    agent.envelope.publicSignals[0] =
      '18320371612677943971623074242238461500910720206465255065323445886458846517670';
    agent.credential.operator_pubkey = { x: '99999999', y: '88888888' };
    const v = await verdictOf(await postVerify(commit()));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('untrusted_root');
  });

  it('tampered binding → deny invalid_signature', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    (bundle.binding as { program: string }).program = 'other-program';
    const req = commit();
    (req.request as { program: string }).program = 'other-program';
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('invalid_signature');
  });

  it('request not matching the signed binding → deny request_mismatch', async () => {
    const req = structuredClone(allowAgentOnly) as typeof allowAgentOnly;
    req.request.agent_name = 'someone-else';
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('request_mismatch');
  });

  it('granted capability outside the signed set → deny request_mismatch', async () => {
    const req = structuredClone(allowAgentOnly) as typeof allowAgentOnly;
    req.request.granted_capabilities = ['fetch_inbox', 'broadcast'];
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('request_mismatch');
  });

  it('now_unix == expiry → deny expired (STRICT boundary)', async () => {
    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      agent: { credential: { expiry: number } };
    };
    const req = { ...allowAgentOnly, now_unix: bundle.agent.credential.expiry };
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('expired');
  });

  it('unmapped capability fails closed with unknown_capability (unit)', () => {
    expect(() => requiredBits(DEFAULT_CAPABILITY_MAP, ['no_such_capability'])).toThrowError(
      expect.objectContaining({ code: 'unknown_capability' }) as Error,
    );
    expect(new VerifyDenial('unknown_capability', 'x').toVerdict().kind).toBe('classical');
  });

  it('verifyClassical exposes the verified binding and operator on allow, and nothing on deny (unit)', () => {
    const trusted = new Set([FIXTURE_OPERATOR_KEY]);
    const ok = verifyClassical(allowAgentOnly, trusted, DEFAULT_CAPABILITY_MAP);
    expect(ok.verdict.verdict).toBe('allow');
    const verified = ok.verified;
    expect(verified).toBeDefined();
    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      binding: Record<string, unknown>;
      agent: { credential: { operator_pubkey: { x: string; y: string } } };
    };
    expect(verified?.binding).toEqual(bundle.binding);
    expect(verified?.operator).toEqual({
      x: BigInt(bundle.agent.credential.operator_pubkey.x),
      y: BigInt(bundle.agent.credential.operator_pubkey.y),
    });

    const denied = verifyClassical({ ...allowAgentOnly, version: 2 }, trusted, DEFAULT_CAPABILITY_MAP);
    expect(denied.verdict.verdict).toBe('deny');
    expect(denied.verified).toBeUndefined();
  });

  it('a request denied AFTER the operator was checked still exposes nothing (unit)', () => {
    const req = structuredClone(allowAgentOnly) as typeof allowAgentOnly;
    req.request.granted_capabilities = ['fetch_inbox', 'broadcast'];
    const denied = verifyClassical(req, new Set([FIXTURE_OPERATOR_KEY]), DEFAULT_CAPABILITY_MAP);
    expect(denied.verdict.verdict).toBe('deny');
    expect((denied.verdict as { code: string }).code).toBe('request_mismatch');
    expect(denied.verified).toBeUndefined();

    // The operator gate really did run first: the same request against an
    // untrusted set stops earlier, at untrusted_root.
    expect(
      (verifyClassical(req, new Set<string>(), DEFAULT_CAPABILITY_MAP).verdict as { code: string }).code,
    ).toBe('untrusted_root');
  });
});

describe('fail-closed configuration (config errors are a 500 VERDICT, never a bare error body)', () => {
  it.each([
    ['TENANTS unset', { TENANTS: '' }],
    ['TENANTS malformed', { TENANTS: '{not json' }],
    ['TENANTS with an empty trusted_operators list', {
      TENANTS: JSON.stringify({
        [ORGS.A]: { admin_token: TOKENS.A.admin, verifier_token: TOKENS.A.verifier, trusted_operators: [] },
      }),
    }],
    ['TENANTS with a malformed operator entry', {
      TENANTS: JSON.stringify({
        [ORGS.A]: { admin_token: TOKENS.A.admin, verifier_token: TOKENS.A.verifier, trusted_operators: ['nope'] },
      }),
    }],
    ['TENANTS with one token value used by two tenants', {
      TENANTS: JSON.stringify({
        [ORGS.A]: { admin_token: TOKENS.A.admin, verifier_token: TOKENS.A.verifier, trusted_operators: ['1:2'] },
        [ORGS.B]: { admin_token: TOKENS.B.admin, verifier_token: TOKENS.A.verifier, trusted_operators: ['1:2'] },
      }),
    }],
    ['CAPABILITY_MAP malformed', { CAPABILITY_MAP: '{not json' }],
    ['CAPABILITY_MAP naming an unknown permission', {
      CAPABILITY_MAP: JSON.stringify({ send_message: ['NO_SUCH_PERMISSION'] }),
    }],
  ])('%s → HTTP 500 deny internal_error', async (_name, overrides) => {
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), { ...env, ...overrides });
    expect(res.status).toBe(500);
    const v = await verdictOf(res);
    expect(v.code).toBe('internal_error');
    expect(v.message).toBe('missing or invalid trust configuration');
    expect(v).not.toHaveProperty('detail'); // config internals never reach the wire
    expect(JSON.stringify(v)).not.toMatch(LEGACY_NAMES);
  });

  it('a configuration defect is the 500 verdict for EVERY caller — no token, wrong token, admin token', async () => {
    const e = { ...env, CAPABILITY_MAP: '{not json' };
    for (const token of [null, 'not-a-real-token-0000000000000000000', TOKENS.A.admin]) {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (token !== null) headers['authorization'] = `Bearer ${token}`;
      const res = await worker.fetch(
        new Request(`${BASE}/v1/verify`, { method: 'POST', headers, body: JSON.stringify(allowAgentOnly) }),
        e,
      );
      expect(res.status).toBe(500);
      expect((await verdictOf(res)).code).toBe('internal_error');
    }
  });

  it('a duplicate JSON member in TENANTS is a defect (the last value must never silently win)', async () => {
    const raw = `{"${ORGS.A}":{"admin_token":"${TOKENS.A.admin}","verifier_token":"${TOKENS.A.verifier}","trusted_operators":["${FIXTURE_OPERATOR_KEY}"],"disabled":true,"disabled":false}}`;
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), { ...env, TENANTS: raw });
    expect(res.status).toBe(500);
    expect((await verdictOf(res)).code).toBe('internal_error');
  });
});

describe('signed receipts (X-Bolyra-Receipt)', () => {
  it('allow responses carry a verifiable ES256K receipt', async () => {
    const res = await postVerify(allowAgentOnly);
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    const receipt = decodeReceipt(header!);
    expect(verifyReceipt(receipt)).toBe(true);
    expect(receipt.payload.decision.allowed).toBe(true);
    expect(receipt.payload.decision.reasonCode).toBe('allow');
    expect(receipt.payload.issuer).toBe('bolyra-hosted-verify-preview');
  });

  it('deny responses carry a receipt with the deny code as reason', async () => {
    const res = await postVerify({ ...allowAgentOnly, version: 2 });
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    const receipt = decodeReceipt(header!);
    expect(verifyReceipt(receipt)).toBe(true);
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toBe('unsupported_version');
  });

  it('receipts are omitted when RECEIPT_SIGNER_KEY is unset', async () => {
    const req = verifyReq(TOKENS.A.verifier);
    const res = await worker.fetch(req, { ...env, RECEIPT_SIGNER_KEY: '' });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-bolyra-receipt')).toBeNull();
  });

  it('401 and 403 carry no receipt (they are not verdicts)', async () => {
    expect((await postVerify(allowAgentOnly, { token: null })).headers.get('x-bolyra-receipt')).toBeNull();
    expect((await postVerify(allowAgentOnly, { token: TOKENS.A.admin })).headers.get('x-bolyra-receipt')).toBeNull();
  });

  it('the disabled-tenant 500 receipt is anonymous and names no tenant or token', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), e);
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    const receipt = decodeReceipt(header!);
    expect(receipt.payload.subject.rootDid).toBe('did:bolyra:preview:anonymous');
    expect(JSON.stringify(receipt)).not.toContain(ORGS.A);
    expect(JSON.stringify(receipt)).not.toContain(TOKENS.A.verifier);
  });
});

describe('entry module', () => {
  it('exports only what the Workers runtime accepts: handlers, classes, and functions', async () => {
    // workerd refuses to start a Worker whose entry module has any other named export
    // ("not of type 'function or ExportedHandler'"); the vitest pool does not enforce
    // this, so a plain constant exported here breaks `wrangler dev` and is rejected
    // when the runtime instantiates a deploy while the suite stays green.
    const entry = (await import('../src/index')) as Record<string, unknown>;
    // The default export must be a real ExportedHandler, not merely an object: workerd
    // instantiates `export default {}` and then 500s every request with "Handler does not
    // export a fetch() function". This also keeps the loop below from passing vacuously.
    expect(typeof (entry.default as { fetch?: unknown } | undefined)?.fetch).toBe('function');
    for (const [name, value] of Object.entries(entry)) {
      const accepted = typeof value === 'function' || (name === 'default' && typeof value === 'object' && value !== null);
      expect(accepted, `export "${name}" is a ${typeof value}`).toBe(true);
    }
  });
});
