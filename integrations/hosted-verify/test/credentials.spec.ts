/**
 * `/v1/credentials*` end to end through the Worker: admin auth, registration
 * (trust membership → signature → expiry → lifecycle), read, revoke, error
 * bodies, id handling, cross-tenant isolation, quarantine, configuration
 * defects. Storage isolation is per file, so every test starts with reset().
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { SELF, env, reset, runInDurableObject } from 'cloudflare:test';

import worker from '../src/index';
import { BASE, CREDENTIALS, ORGS, TOKENS, buildTestTenants, getCredential, postRegister, postRevoke } from './helpers';
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

  it('the request id in history is the edge-shaped cf-ray when present and a UUID otherwise', async () => {
    await postRegister(F.valid.body, { headers: { 'cf-ray': '0123456789abcdef-SJC' } });
    await postRevoke(F.valid.credential_id, { headers: { 'cf-ray': `"); DROP TABLE history; --` } });
    const g = await body(await getCredential(F.valid.credential_id));
    const history = g.history as Array<{ event: string; request_id: string }>;
    expect(history[0]!.request_id).toBe('0123456789abcdef-SJC');
    expect(history[1]!.request_id).toMatch(/^[0-9a-f-]{36}$/);
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

describe('/health', () => {
  it('names the registry and the id version', async () => {
    const h = await body(await SELF.fetch(`${BASE}/health`));
    expect(h.registry).toBe('durable-object');
    expect(h.credential_id_version).toBe('v1');
  });
});
