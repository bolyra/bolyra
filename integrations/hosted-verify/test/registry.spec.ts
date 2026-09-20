/**
 * The registry Durable Object, driven through its RPC stub exactly as the
 * Worker drives it. Storage isolation in this pool is per test FILE, so every
 * test starts with `reset()`; restart persistence uses `evictDurableObject`
 * (instance reset, data kept). Every mutation is one synchronous transaction,
 * so concurrent RPCs are ORDERING tests, not races.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { env, evictDurableObject, listDurableObjectIds, reset, runInDurableObject } from 'cloudflare:test';
import type { RegisterInput, RegisterResult } from '../src/registry';
import { ORGS } from './tenants-fixture';

const ID_A = 'a'.repeat(64);
const ID_B = 'b'.repeat(64);
const NOW = 1_800_000_000;
const HOSTILE = "'); DROP TABLE credentials;--";

const registry = (org: string) => env.TENANT.get(env.TENANT.idFromName(org));

function input(credential_id: string, overrides: Partial<RegisterInput> = {}): RegisterInput {
  return {
    credential_id,
    operator_key: '1:2',
    binding_digest_hex: '0'.repeat(63) + '1',
    binding_json: JSON.stringify({ agent_name: HOSTILE, capabilities: ['fetch_inbox'], expiry: NOW + 3600 }),
    expiry: NOW + 3600,
    now: NOW,
    request_id: 'req-1',
    ...overrides,
  };
}

beforeEach(async () => {
  await reset();
});

describe('register', () => {
  it('absent → created, ACTIVE, one registered event with the caller request id', async () => {
    const r = registry(ORGS.A);
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'created', registered_at: NOW });
    expect(await r.status(ID_A)).toBe('ACTIVE');
    const got = await r.get(ID_A);
    expect(got.outcome).toBe('found');
    if (got.outcome !== 'found') return;
    expect(got.record).toEqual({
      credential_id: ID_A,
      status: 'ACTIVE',
      operator_key: '1:2',
      binding_digest_hex: '0'.repeat(63) + '1',
      binding_json: input(ID_A).binding_json,
      registered_at: NOW,
      revoked_at: null,
      history: [{ event: 'registered', ts: NOW, request_id: 'req-1' }],
    });
  });

  it('ACTIVE → unchanged, original registered_at preserved, no second history row', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.register(input(ID_A, { now: NOW + 100, request_id: 'req-2' }))).toEqual({
      outcome: 'unchanged',
      registered_at: NOW,
    });
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history).toHaveLength(1);
  });

  it('expired at registration → expired, nothing stored (defense in depth: the object re-checks)', async () => {
    const r = registry(ORGS.A);
    expect(await r.register(input(ID_A, { expiry: NOW }))).toEqual({ outcome: 'expired' });
    expect(await r.register(input(ID_A, { expiry: NOW - 1 }))).toEqual({ outcome: 'expired' });
    expect(await r.status(ID_A)).toBe('ABSENT');
  });

  it('same id with a DIFFERENT key or digest → mismatch; the stored row is untouched', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.register(input(ID_A, { operator_key: '9:9' }))).toEqual({ outcome: 'mismatch' });
    expect(await r.register(input(ID_A, { binding_digest_hex: 'f'.repeat(64) }))).toEqual({ outcome: 'mismatch' });
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.operator_key).toBe('1:2');
    expect(got.outcome === 'found' && got.record.history).toHaveLength(1);
  });

  it.each([
    ['a non-string credential_id', { credential_id: 12345 as unknown as string }],
    ['an object as binding_json', { binding_json: { a: 1 } as unknown as string }],
    ['a NaN now', { now: Number.NaN }],
    ['a fractional now', { now: NOW + 0.5 }],
    ['a negative expiry', { expiry: -1 }],
  ])('%s → invalid_input, nothing stored', async (_name, overrides) => {
    const r = registry(ORGS.A);
    expect(await r.register(input(ID_A, overrides))).toEqual({ outcome: 'invalid_input' });
    expect(await r.status(ID_A)).toBe('ABSENT');
    expect(await r.status(12345 as unknown as string)).toBe('invalid_input');
    expect(await r.revoke(ID_A, Number.NaN, 'r')).toBe('invalid_input');
  });

  it('REVOKED → revoked (terminal), row untouched', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.revoke(ID_A, NOW + 10, 'req-r')).toBe('revoked');
    expect(await r.register(input(ID_A, { now: NOW + 20 }))).toEqual({ outcome: 'revoked' });
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.status).toBe('REVOKED');
    expect(got.outcome === 'found' && got.record.history).toHaveLength(2);
  });
});

describe('revoke / status / get', () => {
  it('ACTIVE → revoked with revoked_at and a revoked event; again → unchanged, no duplicate event', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.revoke(ID_A, NOW + 10, 'req-r1')).toBe('revoked');
    expect(await r.revoke(ID_A, NOW + 20, 'req-r2')).toBe('unchanged');
    expect(await r.status(ID_A)).toBe('REVOKED');
    const got = await r.get(ID_A);
    expect(got.outcome).toBe('found');
    if (got.outcome !== 'found') return;
    expect(got.record.revoked_at).toBe(NOW + 10);
    expect(got.record.history).toEqual([
      { event: 'registered', ts: NOW, request_id: 'req-1' },
      { event: 'revoked', ts: NOW + 10, request_id: 'req-r1' },
    ]);
  });

  it('a revocation clocked BEFORE the registration is recorded at the registration time; history stays in insertion order', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.revoke(ID_A, NOW - 5000, 'req-early')).toBe('revoked');
    const got = await r.get(ID_A);
    expect(got.outcome).toBe('found');
    if (got.outcome !== 'found') return;
    expect(got.record.revoked_at).toBe(NOW);
    expect(got.record.history.map((h) => h.event)).toEqual(['registered', 'revoked']);
    expect(got.record.history[1]!.ts).toBe(NOW);
  });

  it('absent → revoke absent, status ABSENT, get absent (never a tombstone)', async () => {
    const r = registry(ORGS.A);
    expect(await r.revoke(ID_B, NOW, 'req')).toBe('absent');
    expect(await r.status(ID_B)).toBe('ABSENT');
    expect(await r.get(ID_B)).toEqual({ outcome: 'absent' });
  });
});

describe('durability contracts', () => {
  it('a history-row collision rolls the whole registration back; the seeded row survives; the object RETURNS storage_error', async () => {
    const r = registry(ORGS.A);
    await runInDurableObject(r, (_instance, state) => {
      state.storage.sql.exec(
        'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
        ID_A,
        'registered',
        1,
        'seed',
      );
    });
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'storage_error' });
    expect(await r.status(ID_A)).toBe('ABSENT');
    expect(await r.get(ID_A)).toEqual({ outcome: 'absent' });
    const seeded = await runInDurableObject(r, (_instance, state) =>
      state.storage.sql
        .exec<{ request_id: string; ts: number }>('SELECT request_id, ts FROM history WHERE credential_id = ?', ID_A)
        .toArray(),
    );
    expect(seeded).toEqual([{ request_id: 'seed', ts: 1 }]);
  });

  it('register/register issued together: one created, one unchanged, equal registered_at, one history row', async () => {
    const r = registry(ORGS.A);
    const [x, y] = await Promise.all([r.register(input(ID_A)), r.register(input(ID_A, { now: NOW + 1 }))]);
    expect([x.outcome, y.outcome].sort()).toEqual(['created', 'unchanged']);
    const at = (r: RegisterResult): number => (r.outcome === 'created' || r.outcome === 'unchanged' ? r.registered_at : NaN);
    expect(Number.isNaN(at(x))).toBe(false);
    expect(at(x)).toBe(at(y));
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history).toHaveLength(1);
  });

  it('register/revoke issued together: final state is one of the two consistent outcomes', async () => {
    const r = registry(ORGS.A);
    const [reg, rev] = await Promise.all([r.register(input(ID_A)), r.revoke(ID_A, NOW + 1, 'req-r')]);
    const got = await r.get(ID_A);
    expect(got.outcome).toBe('found');
    if (got.outcome !== 'found') return;
    if (rev === 'revoked') {
      expect(reg.outcome).toBe('created');
      expect(got.record.status).toBe('REVOKED');
      expect(got.record.history.map((h) => h.event)).toEqual(['registered', 'revoked']);
    } else {
      expect(rev).toBe('absent');
      expect(reg.outcome).toBe('created');
      expect(got.record.status).toBe('ACTIVE');
      expect(got.record.history.map((h) => h.event)).toEqual(['registered']);
    }
  });

  it('revoke/revoke issued together: one revoked, one unchanged, two history rows in total', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    const results = await Promise.all([r.revoke(ID_A, NOW + 1, 'r1'), r.revoke(ID_A, NOW + 2, 'r2')]);
    expect([...results].sort()).toEqual(['revoked', 'unchanged']);
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history).toHaveLength(2);
  });

  it('state survives an instance reset (eviction): ACTIVE stays ACTIVE, REVOKED stays REVOKED, history intact', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await r.register(input(ID_B, { request_id: 'req-b' }));
    await r.revoke(ID_B, NOW + 5, 'req-rb');
    await evictDurableObject(r);
    const again = registry(ORGS.A);
    expect(await again.status(ID_A)).toBe('ACTIVE');
    expect(await again.status(ID_B)).toBe('REVOKED');
    const got = await again.get(ID_B);
    expect(got.outcome === 'found' && got.record.history.map((h) => h.event)).toEqual(['registered', 'revoked']);
  });

  it('hostile text in binding_json and request_id round-trips byte-exact and the tables survive', async () => {
    const r = registry(ORGS.A);
    const quoted = `"; DROP TABLE history; --`;
    await r.register(input(ID_A, { request_id: quoted }));
    const got = await r.get(ID_A);
    expect(got.outcome).toBe('found');
    if (got.outcome !== 'found') return;
    expect(JSON.parse(got.record.binding_json).agent_name).toBe(HOSTILE);
    expect(got.record.history[0]!.request_id).toBe(quoted);
    expect(await r.register(input(ID_B))).toEqual({ outcome: 'created', registered_at: NOW });
  });

  it('each tenant is its own object; this file touches exactly the three test orgs', async () => {
    await registry(ORGS.A).register(input(ID_A));
    await registry(ORGS.B).register(input(ID_A));
    await registry(ORGS.C).status(ID_A);
    expect(await registry(ORGS.B).status(ID_A)).toBe('ACTIVE');
    expect(await registry(ORGS.C).status(ID_A)).toBe('ABSENT');
    const ids = await listDurableObjectIds(env.TENANT);
    const expected = [ORGS.A, ORGS.B, ORGS.C].map((o) => env.TENANT.idFromName(o).toString()).sort();
    expect(ids.map((i) => i.toString()).sort()).toEqual(expected);
  });
});
