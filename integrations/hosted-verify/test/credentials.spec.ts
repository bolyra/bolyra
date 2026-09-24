/**
 * `/v1/credentials*` end to end through the Worker: admin auth, registration
 * (trust membership → signature → expiry → lifecycle), read, revoke, error
 * bodies, id handling, cross-tenant isolation, quarantine, configuration
 * defects. Storage isolation is per file, so every test starts with reset().
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SELF, env, reset, runInDurableObject } from 'cloudflare:test';

import { canonicalize } from '@bolyra/receipts';
import { BODY_READ_DEADLINE_MS } from '../src/deadlines';
import worker from '../src/index';
import {
  BASE,
  CREDENTIALS,
  ORGS,
  TOKENS,
  buildTestTenants,
  fixtureRegistration,
  getCredential,
  postRegister,
  postRepairHistory,
  postRevoke,
  postVerify,
  registerFixture,
} from './helpers';
import registrations from './fixtures/registrations.json';
import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';

type Fixture = { body: Record<string, unknown>; credential_id: string; binding_digest_hex: string };
const F = registrations as Record<'valid' | 'valid2' | 'expired' | 'untrusted' | 'orgB' | 'injection' | 'badSig', Fixture>;

const FIXTURE_OPERATOR_KEY = (() => {
  const { operator_pubkey } = (JSON.parse(allowAgentOnly.bundle) as {
    agent: { credential: { operator_pubkey: { x: string; y: string } } };
  }).agent.credential;
  return `${operator_pubkey.x}:${operator_pubkey.y}`;
})();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

async function body(res: Response): Promise<Record<string, unknown>> {
  return (await res.json()) as Record<string, unknown>;
}

beforeEach(async () => {
  await reset();
});

describe('lifecycle over HTTP', () => {
  it('register → 201 with the expected id; again → 200 with the original registered_at; get → full record', async () => {
    const before = Math.floor(Date.now() / 1000);
    const created = await postRegister(F.valid.body);
    expect(created.status).toBe(201);
    const c = await body(created);
    expect(c.credential_id).toBe(F.valid.credential_id);
    expect(c.status).toBe('ACTIVE');
    expect(c.registered_at as number).toBeGreaterThanOrEqual(before);

    const again = await postRegister(F.valid.body);
    expect(again.status).toBe(200);
    expect(await body(again)).toEqual({ credential_id: F.valid.credential_id, status: 'ACTIVE', registered_at: c.registered_at });

    const got = await getCredential(F.valid.credential_id);
    expect(got.status).toBe(200);
    const g = await body(got);
    expect(g.credential_id).toBe(F.valid.credential_id);
    expect(g.status).toBe('ACTIVE');
    expect(g.operator_key).toBe(FIXTURE_OPERATOR_KEY);
    expect(g.binding).toEqual(F.valid.body.binding);
    expect(g.registered_at).toBe(c.registered_at);
    expect(g.revoked_at).toBeNull();
    expect((g.history as Array<{ event: string }>).map((h) => h.event)).toEqual(['registered']);
  });

  it('revoke → 204 (empty), again → 204, get shows REVOKED with two events, re-register → 409', async () => {
    await postRegister(F.valid.body);
    const rev = await postRevoke(F.valid.credential_id);
    expect(rev.status).toBe(204);
    expect(await rev.text()).toBe('');
    expect((await postRevoke(F.valid.credential_id)).status).toBe(204);
    const g = await body(await getCredential(F.valid.credential_id));
    expect(g.status).toBe('REVOKED');
    expect(typeof g.revoked_at).toBe('number');
    expect((g.history as Array<{ event: string }>).map((h) => h.event)).toEqual(['registered', 'revoked']);
    const re = await postRegister(F.valid.body);
    expect(re.status).toBe(409);
    expect((await body(re)).error).toBe('credential_revoked');
  });

  it('absent id: get → 404, revoke → 404', async () => {
    expect((await getCredential(F.valid2.credential_id)).status).toBe(404);
    expect((await body(await postRevoke(F.valid2.credential_id))).error).toBe('not_found');
  });

  it('two different bindings from one operator are two credentials', async () => {
    const a = await body(await postRegister(F.valid.body));
    const b = await body(await postRegister(F.valid2.body));
    expect(a.credential_id).not.toBe(b.credential_id);
    expect(b.credential_id).toBe(F.valid2.credential_id);
  });

  it('a registry storage failure surfaces as 500 internal_error, nothing stored', async () => {
    await runInDurableObject(env.TENANT.get(env.TENANT.idFromName(ORGS.A)), (_i, state) => {
      state.storage.sql.exec(
        'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
        F.valid.credential_id,
        'registered',
        1,
        'seed',
      );
    });
    const res = await postRegister(F.valid.body);
    expect(res.status).toBe(500);
    expect(await body(res)).toEqual({ error: 'internal_error', message: 'registry storage failure' });
    expect((await getCredential(F.valid.credential_id)).status).toBe(404);
  });

  it('the request id in history is always a server-generated UUID, even when a valid cf-ray is present', async () => {
    await postRegister(F.valid.body, { headers: { 'cf-ray': '0123456789abcdef-SJC' } });
    await postRevoke(F.valid.credential_id, { headers: { 'cf-ray': `"); DROP TABLE history; --` } });
    const g = await body(await getCredential(F.valid.credential_id));
    const history = g.history as Array<{ event: string; request_id: string }>;
    expect(history.map((h) => h.event)).toEqual(['registered', 'revoked']);
    for (const h of history) expect(h.request_id).toMatch(UUID);
    expect(history[0]!.request_id).not.toBe(history[1]!.request_id);
  });
});

describe('durable revocation over HTTP: an audit-row failure never un-revokes', () => {
  const tenantA = () => env.TENANT.get(env.TENANT.idFromName(ORGS.A));

  async function seedRevokedEvent(id: string, ts: number, request_id: string): Promise<void> {
    await runInDurableObject(tenantA(), (_i, state) => {
      state.storage.sql.exec("INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, 'revoked', ?, ?)", id, ts, request_id);
    });
  }

  it('a normal revoke is exactly 204 with no audit header; repair-history on it → 200 clean', async () => {
    await postRegister(F.valid.body);
    const rev = await postRevoke(F.valid.credential_id);
    expect(rev.status).toBe(204);
    expect(rev.headers.get('x-bolyra-audit')).toBeNull();
    expect(rev.headers.get('cache-control')).toBe('no-store');
    const rep = await postRepairHistory(F.valid.credential_id);
    expect(rep.status).toBe(200);
    expect(await body(rep)).toEqual({ credential_id: F.valid.credential_id, audit: 'clean' });
  });

  it('history write fails → 204 + x-bolyra-audit history_write_failed, then history_conflict on every retry; the credential denies, repair-history → 409 history_conflict', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    expect((await body(await postVerify(allowAgentOnly))).verdict).toBe('allow');
    await seedRevokedEvent(id, 1, 'seed');
    for (let i = 0; i < 3; i++) {
      const rev = await postRevoke(id);
      expect(rev.status).toBe(204);
      expect(await rev.text()).toBe('');
      // The first attempt failed its write; every retry found the conflicting row.
      expect(rev.headers.get('x-bolyra-audit')).toBe(i === 0 ? 'history_write_failed' : 'history_conflict');
      expect(rev.headers.get('cache-control')).toBe('no-store');
      expect(rev.headers.get('x-bolyra-preview')).toBe('design-partner-preview');
    }
    const v = await body(await postVerify(allowAgentOnly));
    expect(v.verdict).toBe('deny');
    expect((v.detail as { reason: string }).reason).toBe('credential_not_active');
    const g = await body(await getCredential(id));
    expect(g.status).toBe('REVOKED');
    expect(g.pending_history).toBe(true);
    const rep = await postRepairHistory(id);
    expect(rep.status).toBe(409);
    expect((await body(rep)).error).toBe('history_conflict');
  });

  it('once the foreign row is gone, repair-history → 200 repaired and the audit row carries the first revocation', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    await seedRevokedEvent(id, 1, 'seed');
    const rev = await postRevoke(id, { headers: { 'cf-ray': '0123456789abcdef-SJC' } });
    expect(rev.headers.get('x-bolyra-audit')).toBe('history_write_failed');
    const revokeRequestId = rev.headers.get('x-bolyra-request-id');
    expect(revokeRequestId).toMatch(UUID);
    await runInDurableObject(tenantA(), (_i, state) => {
      state.storage.sql.exec("DELETE FROM history WHERE credential_id = ? AND event = 'revoked'", id);
    });
    const rep = await postRepairHistory(id);
    expect(rep.status).toBe(200);
    expect(await body(rep)).toEqual({ credential_id: id, audit: 'repaired' });
    const g = await body(await getCredential(id));
    expect(g.pending_history).toBe(false);
    const history = g.history as Array<{ event: string; request_id: string }>;
    expect(history.map((h) => [h.event, h.request_id])).toEqual([
      ['registered', expect.any(String)],
      ['revoked', revokeRequestId], // the owed row carries the FIRST revocation's server request id
    ]);
    expect((await postRevoke(id)).headers.get('x-bolyra-audit')).toBeNull();
  });

  it('the failure is visible in the request log and the analytics code, never as a non-204', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    await seedRevokedEvent(id, 1, 'seed');
    const points: Array<{ blobs?: string[] }> = [];
    const usage = { writeDataPoint: (p: { blobs?: string[] }) => { points.push(p); } } as unknown as AnalyticsEngineDataset;
    const lines: unknown[][] = [];
    const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => { lines.push(args); });
    let res: Response;
    try {
      res = await worker.fetch(
        new Request(`${CREDENTIALS}/${id}/revoke`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.admin}` } }),
        { ...env, USAGE: usage },
      );
    } finally {
      spy.mockRestore();
    }
    expect(res.status).toBe(204);
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 4)).toEqual(['/v1/credentials', `${ORGS.A}:admin`, 'ok', 'revoke_history_failed']);
    const logged = lines.find((l) => l[0] === 'hosted-verify registry request')?.[1] as Record<string, unknown> | undefined;
    expect(logged?.code).toBe('revoke_history_failed');
    expect(logged?.credential_id).toBe(id);

    // A retry meets the same foreign row: a conflict, still 204, its own code.
    const retry = await worker.fetch(
      new Request(`${CREDENTIALS}/${id}/revoke`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.admin}` } }),
      { ...env, USAGE: usage },
    );
    expect(retry.status).toBe(204);
    expect(retry.headers.get('x-bolyra-audit')).toBe('history_conflict');
    expect(points).toHaveLength(2);
    expect(points[1]!.blobs!.slice(0, 4)).toEqual(['/v1/credentials', `${ORGS.A}:admin`, 'ok', 'revoke_history_conflict']);
  });

  it('repair-history: unknown id → 404; no token → 401; verifier → 403', async () => {
    const unknown = await postRepairHistory(F.valid2.credential_id);
    expect(unknown.status).toBe(404);
    expect((await body(unknown)).error).toBe('not_found');
    const anon = await postRepairHistory(F.valid.credential_id, { token: null });
    expect(anon.status).toBe(401);
    const verifier = await postRepairHistory(F.valid.credential_id, { token: TOKENS.A.verifier });
    expect(verifier.status).toBe(403);
    expect(await body(verifier)).toEqual({ error: 'forbidden' });
  });
});

describe('registration checks, in order', () => {
  it('valid signature from an operator this tenant does not trust → 403 untrusted_operator', async () => {
    const res = await postRegister(F.untrusted.body);
    expect(res.status).toBe(403);
    expect(await body(res)).toEqual({ error: 'untrusted_operator', message: "operator key is not in this tenant's trusted operators" });
  });

  it("a valid signature over a DIFFERENT binding → 400 binding_signature_invalid; nothing stored under either id", async () => {
    const res = await postRegister(F.badSig.body);
    expect(res.status).toBe(400);
    expect((await body(res)).error).toBe('binding_signature_invalid');
    expect((await getCredential(F.valid2.credential_id)).status).toBe(404);
  });

  it('a non-canonical spelling of the operator key is the SAME credential (idempotent 200), never a second id', async () => {
    const first = await body(await postRegister(F.valid.body));
    const spelled = structuredClone(F.valid.body) as { operator_pubkey: { x: string; y: string } };
    spelled.operator_pubkey.x = `000${spelled.operator_pubkey.x}`;
    const again = await postRegister(spelled);
    expect(again.status).toBe(200);
    expect((await body(again)).credential_id).toBe(first.credential_id);
  });

  it('tampered binding → 400 binding_signature_invalid', async () => {
    const tampered = structuredClone(F.valid.body) as { binding: { agent_name: string } };
    tampered.binding.agent_name = 'someone-else';
    const res = await postRegister(tampered);
    expect(res.status).toBe(400);
    expect((await body(res)).error).toBe('binding_signature_invalid');
    expect((await getCredential(F.valid.credential_id)).status).toBe(404);
  });

  it('expired binding → 400 binding_expired, nothing stored', async () => {
    const res = await postRegister(F.expired.body);
    expect(res.status).toBe(400);
    expect((await body(res)).error).toBe('binding_expired');
    expect((await getCredential(F.expired.credential_id)).status).toBe(404);
  });

  it.each([
    ['invalid JSON', '{not json'],
    ['a non-object', '42'],
    ['version 2', { ...F.valid.body, version: 2 }],
    ['a missing signature', { ...F.valid.body, signature: undefined }],
    ['an extra field', { ...F.valid.body, extra: 1 }],
    ['a five-field v1 binding', { ...F.valid.body, binding: { ...(F.valid.body.binding as object), expiry: undefined } }],
    ['a non-decimal operator_pubkey', { ...F.valid.body, operator_pubkey: { x: '12abc', y: '1' } }],
  ])('malformed: %s → 400 malformed_input', async (_name, payload) => {
    const res = await postRegister(payload);
    expect(res.status).toBe(400);
    const b = await body(res);
    expect(b.error).toBe('malformed_input');
    expect(typeof b.message).toBe('string');
  });

  it.each([
    ['operator_pubkey', { ...F.valid.body, operator_pubkey: { ...(F.valid.body.operator_pubkey as object), extra: 1 } }],
    ['signature', { ...F.valid.body, signature: { ...(F.valid.body.signature as object), extra: 1 } }],
    ['signature.R8', { ...F.valid.body, signature: { ...(F.valid.body.signature as { R8: object; S: string }), R8: { ...(F.valid.body.signature as { R8: object }).R8, extra: 1 } } }],
  ])('an unknown nested field in %s → 400 malformed_input', async (_name, payload) => {
    const res = await postRegister(payload);
    expect(res.status).toBe(400);
    expect((await body(res)).error).toBe('malformed_input');
    expect((await getCredential(F.valid.credential_id)).status).toBe(404);
  });

  it('a body over 64 KiB → 400 malformed_input', async () => {
    const res = await postRegister({ ...F.valid.body, binding: { ...(F.valid.body.binding as object), agent_name: 'x'.repeat(70_000) } });
    expect(res.status).toBe(400);
    expect((await body(res)).error).toBe('malformed_input');
  });

  it("hostile text in the signed binding's agent_name registers and reads back byte-exact", async () => {
    const res = await postRegister(F.injection.body);
    expect(res.status).toBe(201);
    const g = await body(await getCredential(F.injection.credential_id));
    expect((g.binding as { agent_name: string }).agent_name).toBe("'); DROP TABLE credentials;--");
    // The tables survived: a second registration still works.
    expect((await postRegister(F.valid.body)).status).toBe(201);
  });
});

describe('ids and methods', () => {
  it.each([
    ['uppercase hex', F.valid.credential_id.toUpperCase()],
    ['63 characters', F.valid.credential_id.slice(0, 63)],
    ['65 characters', `${F.valid.credential_id}0`],
    ['non-hex', 'z'.repeat(64)],
  ])('%s id → 404 not_found (never 400)', async (_name, id) => {
    await postRegister(F.valid.body);
    expect((await getCredential(id)).status).toBe(404);
    expect((await postRevoke(id)).status).toBe(404);
  });

  it('a malformed id is 404 for EVERY caller and method — before auth, role, quarantine or method are considered', async () => {
    const bad = `${CREDENTIALS}/not-a-credential-id`;
    for (const [headers, method] of [
      [{}, 'GET'],
      [{ authorization: 'Bearer wrong-token-000000000000000000000000' }, 'GET'],
      [{ authorization: `Bearer ${TOKENS.A.verifier}` }, 'GET'],
      [{ authorization: `Bearer ${TOKENS.A.admin}` }, 'POST'],
      [{ authorization: `Bearer ${TOKENS.A.admin}` }, 'DELETE'],
    ] as const) {
      const res = await SELF.fetch(bad, { method, headers });
      expect(res.status).toBe(404);
      expect(await body(res)).toEqual({ error: 'not_found', message: 'no such credential' });
    }
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const quarantined = await worker.fetch(new Request(bad, { headers: { authorization: `Bearer ${TOKENS.A.admin}` } }), e);
    expect(quarantined.status).toBe(404);
  });

  it('unknown sub-path → 404 with the route list; wrong methods → 405 with allow', async () => {
    const h = { authorization: `Bearer ${TOKENS.A.admin}` };
    expect((await SELF.fetch(`${CREDENTIALS}/${F.valid.credential_id}/other`, { headers: h })).status).toBe(404);
    const m1 = await SELF.fetch(CREDENTIALS, { method: 'GET', headers: h });
    expect(m1.status).toBe(405);
    expect(m1.headers.get('allow')).toBe('POST');
    const m2 = await SELF.fetch(`${CREDENTIALS}/${F.valid.credential_id}`, { method: 'POST', headers: h });
    expect(m2.status).toBe(405);
    expect(m2.headers.get('allow')).toBe('GET');
    const m3 = await SELF.fetch(`${CREDENTIALS}/${F.valid.credential_id}/revoke`, { method: 'GET', headers: h });
    expect(m3.status).toBe(405);
    expect(m3.headers.get('allow')).toBe('POST');
    const m4 = await SELF.fetch(`${CREDENTIALS}/${F.valid.credential_id}/repair-history`, { method: 'GET', headers: h });
    expect(m4.status).toBe(405);
    expect(m4.headers.get('allow')).toBe('POST');
    const unknown = await body(await SELF.fetch(`${BASE}/nope`, { headers: h }));
    expect(unknown.routes).toContain('POST /v1/credentials/{id}/repair-history');
  });
});

describe('auth, roles, tenants', () => {
  it('no token → 401 { error, message }', async () => {
    const res = await postRegister(F.valid.body, { token: null });
    expect(res.status).toBe(401);
    expect(await body(res)).toEqual({ error: 'unauthorized', message: 'Authorization: Bearer <admin token>' });
  });

  it('a VERIFIER token on every registry route → 403 exactly { error: "forbidden" }', async () => {
    for (const res of [
      await postRegister(F.valid.body, { token: TOKENS.A.verifier }),
      await getCredential(F.valid.credential_id, { token: TOKENS.A.verifier }),
      await postRevoke(F.valid.credential_id, { token: TOKENS.A.verifier }),
      await postRepairHistory(F.valid.credential_id, { token: TOKENS.A.verifier }),
    ]) {
      expect(res.status).toBe(403);
      expect(await body(res)).toEqual({ error: 'forbidden' });
    }
  });

  it('a disabled tenant → 503 tenant_disabled on the admin routes; other tenants unaffected', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(
      new Request(CREDENTIALS, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' }, body: JSON.stringify(F.valid.body) }),
      e,
    );
    expect(res.status).toBe(503);
    expect(await body(res)).toEqual({ error: 'tenant_disabled', message: 'this tenant is disabled' });
    const other = await worker.fetch(
      new Request(CREDENTIALS, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.C.admin}`, 'content-type': 'application/json' }, body: JSON.stringify(F.valid.body) }),
      e,
    );
    expect(other.status).toBe(201);
  });

  it('a configuration defect → 500 { error: "internal_error" } (an error body, not a verdict) for every caller', async () => {
    for (const token of [null, TOKENS.A.admin, TOKENS.A.verifier]) {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (token !== null) headers['authorization'] = `Bearer ${token}`;
      const res = await worker.fetch(new Request(CREDENTIALS, { method: 'POST', headers, body: JSON.stringify(F.valid.body) }), { ...env, TENANTS: '{not json' });
      expect(res.status).toBe(500);
      expect(await body(res)).toEqual({ error: 'internal_error', message: 'missing or invalid trust configuration' });
    }
  });

  it("cross-tenant: org-b does not trust the fixture operator; org-b's own registration is invisible to org-a", async () => {
    const denied = await postRegister(F.valid.body, { token: TOKENS.B.admin });
    expect(denied.status).toBe(403);
    expect((await body(denied)).error).toBe('untrusted_operator');

    const bOwn = await postRegister(F.orgB.body, { token: TOKENS.B.admin });
    expect(bOwn.status).toBe(201);
    expect((await body(bOwn)).credential_id).toBe(F.orgB.credential_id);
    expect((await getCredential(F.orgB.credential_id, { token: TOKENS.A.admin })).status).toBe(404);
    expect((await postRevoke(F.orgB.credential_id, { token: TOKENS.A.admin })).status).toBe(404);
    expect((await getCredential(F.orgB.credential_id, { token: TOKENS.B.admin })).status).toBe(200);
  });

  it("probing another tenant's registry with a derivable id is 404, never 403 (existence is not confirmed)", async () => {
    await postRegister(F.valid.body, { token: TOKENS.A.admin });
    expect((await getCredential(F.valid.credential_id, { token: TOKENS.C.admin })).status).toBe(404);
    expect((await postRevoke(F.valid.credential_id, { token: TOKENS.C.admin })).status).toBe(404);
  });

  it('two tenants trusting the same operator hold the SAME id independently: revoking in org-a leaves org-c ACTIVE', async () => {
    const a = await body(await postRegister(F.valid.body, { token: TOKENS.A.admin }));
    const c = await body(await postRegister(F.valid.body, { token: TOKENS.C.admin }));
    expect(a.credential_id).toBe(c.credential_id);
    expect((await postRevoke(F.valid.credential_id, { token: TOKENS.A.admin })).status).toBe(204);
    expect((await body(await getCredential(F.valid.credential_id, { token: TOKENS.A.admin }))).status).toBe('REVOKED');
    expect((await body(await getCredential(F.valid.credential_id, { token: TOKENS.C.admin }))).status).toBe('ACTIVE');
  });
});

describe('failures behind the registry call are the documented 500 with an analytics point', () => {
  const throwing = {
    get: () => ({
      register: async () => { throw new Error('Durable Object reset because its code was updated'); },
      get: async () => { throw new Error('Network connection lost.'); },
      revoke: async () => { throw new Error('Network connection lost.'); },
      repairHistory: async () => { throw new Error('Network connection lost.'); },
      status: async () => { throw new Error('Network connection lost.'); },
    }),
    idFromName: (name: string) => env.TENANT.idFromName(name),
  } as unknown as typeof env.TENANT;
  const alien = {
    get: () => ({
      register: async () => ({ outcome: 'something_new' }),
      get: async () => ({ outcome: 'found', record: { credential_id: 'x', status: 'ACTIVE', operator_key: '1:2', binding_digest_hex: '0', binding_json: 'NOT JSON', registered_at: 1, revoked_at: null, history: [] } }),
      revoke: async () => 'something_new',
      repairHistory: async () => 'something_new',
      status: async () => 'ACTIVE',
    }),
    idFromName: (name: string) => env.TENANT.idFromName(name),
  } as unknown as typeof env.TENANT;

  it('a missing registry binding is the documented 500 with a data point, not a bare exception', async () => {
    const points: unknown[] = [];
    const usage = { writeDataPoint: (p: unknown) => { points.push(p); } } as unknown as AnalyticsEngineDataset;
    const e = { ...env, USAGE: usage } as Record<string, unknown>;
    delete e.TENANT;
    const res = await worker.fetch(
      new Request(CREDENTIALS, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' }, body: JSON.stringify(F.valid.body) }),
      e as unknown as typeof env,
    );
    expect(res.status).toBe(500);
    expect(await body(res)).toEqual({ error: 'internal_error', message: 'registry storage failure' });
    expect(points).toHaveLength(1);
  });

  it.each([
    ['a rejecting RPC on register', throwing, 'POST', ''],
    ['a rejecting RPC on get', throwing, 'GET', `/${'a'.repeat(64)}`],
    ['a rejecting RPC on revoke', throwing, 'POST', `/${'a'.repeat(64)}/revoke`],
    ['an outcome outside the union on register', alien, 'POST', ''],
    ['stored text that is not JSON on get', alien, 'GET', `/${'a'.repeat(64)}`],
    ['an outcome outside the union on revoke', alien, 'POST', `/${'a'.repeat(64)}/revoke`],
    ['a rejecting RPC on repair-history', throwing, 'POST', `/${'a'.repeat(64)}/repair-history`],
    ['an outcome outside the union on repair-history', alien, 'POST', `/${'a'.repeat(64)}/repair-history`],
  ] as const)('%s → 500 internal_error, one data point recorded', async (_name, tenant, method, suffix) => {
    const points: Array<{ blobs?: string[] }> = [];
    const usage = { writeDataPoint: (p: { blobs?: string[] }) => { points.push(p); } } as unknown as AnalyticsEngineDataset;
    const res = await worker.fetch(
      new Request(`${CREDENTIALS}${suffix}`, {
        method,
        headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' },
        ...(method === 'POST' && suffix === '' ? { body: JSON.stringify(F.valid.body) } : {}),
      }),
      { ...env, TENANT: tenant, USAGE: usage },
    );
    expect(res.status).toBe(500);
    expect(await body(res)).toEqual({ error: 'internal_error', message: 'registry storage failure' });
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 4)).toEqual(['/v1/credentials', `${ORGS.A}:admin`, 'error', 'internal_error']);
  });
});

describe('wire grammar and canonical form', () => {
  it('coordinates spelled as hex or with whitespace are 400 malformed_input (decimal digits only)', async () => {
    for (const x of ['0x7b', ' 123', '+123']) {
      const spelled = structuredClone(F.valid.body) as { operator_pubkey: { x: string } };
      spelled.operator_pubkey.x = x;
      const res = await postRegister(spelled);
      expect(res.status).toBe(400);
      expect((await body(res)).error).toBe('malformed_input');
    }
  });

  it('a negative coordinate is 400 malformed_input — the decimal grammar rejects it before trust or id derivation', async () => {
    const neg = structuredClone(F.valid.body) as { operator_pubkey: { x: string } };
    neg.operator_pubkey.x = `-${neg.operator_pubkey.x}`;
    const res = await postRegister(neg);
    expect(res.status).toBe(400);
    expect((await body(res)).error).toBe('malformed_input');
  });

  it('a reordered binding is the SAME credential; the returned binding is the canonical (key-sorted) form', async () => {
    const first = await body(await postRegister(F.valid.body));
    const b = F.valid.body.binding as Record<string, unknown>;
    const reordered = { ...F.valid.body, binding: Object.fromEntries(Object.keys(b).sort().reverse().map((k) => [k, b[k]])) };
    const again = await postRegister(reordered);
    expect(again.status).toBe(200);
    expect((await body(again)).credential_id).toBe(first.credential_id);
    const g = await body(await getCredential(F.valid.credential_id));
    expect(JSON.stringify(g.binding)).toBe(canonicalize(F.valid.body.binding as Record<string, unknown>));
    expect(g.binding_digest_hex).toBe(F.valid.binding_digest_hex);
  });

  it('version must be the number 1', async () => {
    const res = await postRegister({ ...F.valid.body, version: '1' });
    expect(res.status).toBe(400);
    expect((await body(res)).message).toBe('version must be 1');
  });

  it('the body bound is inclusive at 65,536 bytes', async () => {
    const base = JSON.stringify(F.valid.body);
    // Pad inside a string value the parser rejects anyway; only the byte cap is under test here.
    const pad = (n: number) => `${base.slice(0, -1)},"extra":"${'x'.repeat(n)}"}`;
    const overhead = Buffer.byteLength(pad(0), 'utf8');
    const exact = await postRegister(pad(65_536 - overhead));
    expect((await body(exact)).message).toBe('request carries an unexpected field'); // read fully, then rejected by shape
    const over = await postRegister(pad(65_537 - overhead));
    expect((await body(over)).message).toContain('exceeds');
  });
});

describe('registration body-stream failures (E7)', () => {
  function streamingRegister(body: ReadableStream<Uint8Array>): Request {
    return new Request(CREDENTIALS, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKENS.A.admin}`, 'content-type': 'application/json' },
      body,
      duplex: 'half',
    } as RequestInit);
  }
  function usageCapture(): { e: typeof env; points: Array<{ blobs?: string[]; doubles?: number[] }> } {
    const points: Array<{ blobs?: string[]; doubles?: number[] }> = [];
    const usage = { writeDataPoint: (p: { blobs?: string[]; doubles?: number[] }) => { points.push(p); } } as unknown as AnalyticsEngineDataset;
    return { e: { ...env, USAGE: usage }, points };
  }

  it('a body stream that errors → 400 malformed_input with its analytics point and request line', async () => {
    const { e, points } = usageCapture();
    const lines: unknown[][] = [];
    const spy = vi.spyOn(console, 'info').mockImplementation((...args: unknown[]) => { lines.push(args); });
    let res: Response;
    try {
      res = await worker.fetch(streamingRegister(new ReadableStream({ pull: () => Promise.reject(new Error('connection reset')) })), e);
    } finally {
      spy.mockRestore();
    }
    expect(res.status).toBe(400);
    expect(await body(res)).toEqual({ error: 'malformed_input', message: 'request body could not be read' });
    expect(points).toHaveLength(1);
    expect(points[0]!.blobs!.slice(0, 4)).toEqual(['/v1/credentials', `${ORGS.A}:admin`, 'error', 'malformed_input']);
    expect(points[0]!.doubles![1]).toBe(400);
    expect(lines.some((l) => l[0] === 'hosted-verify registry request' && (l[1] as { code: string }).code === 'malformed_input')).toBe(true);
  });

  it(`a body that never arrives → 500 internal_error "request body stalled" at ${BODY_READ_DEADLINE_MS} ms`, async () => {
    vi.useFakeTimers();
    try {
      const { e, points } = usageCapture();
      const pending = worker.fetch(streamingRegister(new ReadableStream({ pull: () => new Promise<void>(() => {}) })), e);
      await vi.advanceTimersByTimeAsync(BODY_READ_DEADLINE_MS + 1);
      const res = await pending;
      expect(res.status).toBe(500);
      expect(await body(res)).toEqual({ error: 'internal_error', message: 'request body stalled' });
      expect(points[0]!.blobs!.slice(2, 4)).toEqual(['error', 'internal_error']);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('/health', () => {
  it('names the credential id version', async () => {
    const h = await body(await SELF.fetch(`${BASE}/health`));
    expect(h.credential_id_version).toBe('v1');
  });
});
