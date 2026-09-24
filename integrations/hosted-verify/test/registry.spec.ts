/**
 * The registry Durable Object, driven through its RPC stub exactly as the
 * Worker drives it. Storage isolation in this pool is per test FILE, so every
 * test starts with `reset()`; restart persistence uses `evictDurableObject`
 * (instance reset, data kept). Every mutation is one synchronous transaction,
 * so concurrent RPCs are ORDERING tests, not races.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { env, evictDurableObject, listDurableObjectIds, reset, runInDurableObject } from 'cloudflare:test';
import { MAX_ACTIVE_CREDENTIALS, MAX_BINDING_JSON_BYTES, type RegisterInput, type RegisterResult } from '../src/registry';
import { seedCredentials } from './helpers';
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
      pending_history: false,
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
    ['a binding_json one byte over the bound', { binding_json: 'x'.repeat(MAX_BINDING_JSON_BYTES + 1) }],
    ['a binding_json under the bound in characters but over it in UTF-8 bytes', { binding_json: '€'.repeat(Math.ceil((MAX_BINDING_JSON_BYTES + 1) / 3)) }],
  ])('%s → invalid_input, nothing stored', async (_name, overrides) => {
    const r = registry(ORGS.A);
    expect(await r.register(input(ID_A, overrides))).toEqual({ outcome: 'invalid_input' });
    expect(await r.status(ID_A)).toBe('ABSENT');
    expect(await r.status(12345 as unknown as string)).toBe('invalid_input');
    expect(await r.revoke(ID_A, Number.NaN, 'r')).toBe('invalid_input');
  });

  it('a binding_json of exactly the byte bound is accepted', async () => {
    const r = registry(ORGS.A);
    expect(await r.register(input(ID_A, { binding_json: 'x'.repeat(MAX_BINDING_JSON_BYTES) }))).toEqual({ outcome: 'created', registered_at: NOW });
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

describe('per-tenant ACTIVE credential cap', () => {
  const ID_C = 'c'.repeat(64);

  it(`at cap-1 one more registers; the next is quota_exceeded and stores nothing`, async () => {
    const r = registry(ORGS.A);
    await seedCredentials(r, MAX_ACTIVE_CREDENTIALS - 1);
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'created', registered_at: NOW });
    expect(await r.register(input(ID_B))).toEqual({ outcome: 'quota_exceeded' });
    expect(await r.status(ID_B)).toBe('ABSENT');
    await runInDurableObject(r, (_i, state) => {
      expect(state.storage.sql.exec('SELECT count(*) AS n FROM history WHERE credential_id = ?', ID_B).one().n).toBe(0);
    });
  });

  it('at cap, re-registering an existing ACTIVE id is still unchanged with its original registered_at', async () => {
    const r = registry(ORGS.A);
    await seedCredentials(r, MAX_ACTIVE_CREDENTIALS - 1);
    await r.register(input(ID_A));
    expect(await r.register(input(ID_A, { now: NOW + 50, request_id: 'req-2' }))).toEqual({ outcome: 'unchanged', registered_at: NOW });
  });

  it('at cap, a REVOKED id still answers revoked and a different key/digest still answers mismatch', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_C));
    expect(await r.revoke(ID_C, NOW + 1, 'req-r')).toBe('revoked');
    await r.register(input(ID_A));
    await seedCredentials(r, MAX_ACTIVE_CREDENTIALS - 1);
    expect(await r.register(input(ID_C))).toEqual({ outcome: 'revoked' });
    expect(await r.register(input(ID_A, { operator_key: '9:9' }))).toEqual({ outcome: 'mismatch' });
  });

  it('revoking one frees a slot', async () => {
    const r = registry(ORGS.A);
    const ids = await seedCredentials(r, MAX_ACTIVE_CREDENTIALS);
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'quota_exceeded' });
    expect(await r.revoke(ids[0]!, NOW + 1, 'req-r')).toBe('revoked');
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'created', registered_at: NOW });
    expect(await r.register(input(ID_B))).toEqual({ outcome: 'quota_exceeded' });
  });

  it('REVOKED rows do not count toward the cap', async () => {
    const r = registry(ORGS.A);
    await seedCredentials(r, 50, { status: 'REVOKED', prefix: 'd' });
    await seedCredentials(r, MAX_ACTIVE_CREDENTIALS - 1);
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'created', registered_at: NOW });
  });

  it('expired-but-ACTIVE rows still count (no reclamation)', async () => {
    const r = registry(ORGS.A);
    // Every seeded row is ACTIVE with a binding whose expiry is in the PAST: still counted until revoked.
    const pastExpiry = NOW - 3600;
    const ids = await seedCredentials(r, MAX_ACTIVE_CREDENTIALS, { now: NOW - 7200, expiry: pastExpiry });
    const seeded = await r.get(ids[0]!);
    expect(seeded.outcome === 'found' && seeded.record.status).toBe('ACTIVE');
    expect(seeded.outcome === 'found' && (JSON.parse(seeded.record.binding_json) as { expiry: number }).expiry).toBe(pastExpiry);
    await runInDurableObject(r, (_i, state) => {
      expect(
        state.storage.sql
          .exec("SELECT count(*) AS n FROM credentials WHERE status = 'ACTIVE' AND json_extract(binding_json, '$.expiry') < ?", NOW)
          .one().n,
      ).toBe(MAX_ACTIVE_CREDENTIALS);
    });
    expect(await r.register(input(ID_A))).toEqual({ outcome: 'quota_exceeded' });
  });

  it('two registers issued together at cap-1: exactly one created, one quota_exceeded', async () => {
    // Guards the observable invariant only: register has no `await`, so the object serializes these RPCs
    // anyway; atomicity rests on header rule 1 (no `await`) plus the single transaction.
    const r = registry(ORGS.A);
    await seedCredentials(r, MAX_ACTIVE_CREDENTIALS - 1);
    const [x, y] = await Promise.all([r.register(input(ID_A)), r.register(input(ID_B))]);
    expect([x.outcome, y.outcome].sort()).toEqual(['created', 'quota_exceeded']);
    await runInDurableObject(r, (_i, state) => {
      expect(state.storage.sql.exec("SELECT count(*) AS n FROM credentials WHERE status = 'ACTIVE'").one().n).toBe(MAX_ACTIVE_CREDENTIALS);
    });
  });

  it('the cap is per tenant: org A at cap does not affect org B', async () => {
    await seedCredentials(registry(ORGS.A), MAX_ACTIVE_CREDENTIALS);
    expect(await registry(ORGS.A).register(input(ID_A))).toEqual({ outcome: 'quota_exceeded' });
    expect(await registry(ORGS.B).register(input(ID_A))).toEqual({ outcome: 'created', registered_at: NOW });
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

type Stub = ReturnType<typeof registry>;
type Pending = { pending_history: number; pending_request_id: string | null; pending_at: number | null };

/** Put a 'revoked' history row in place so the revocation's own insert collides with it. */
async function seedRevokedEvent(r: Stub, id: string, ts: number, request_id: string): Promise<void> {
  await runInDurableObject(r, (_i, state) => {
    state.storage.sql.exec("INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, 'revoked', ?, ?)", id, ts, request_id);
  });
}

async function deleteRevokedEvent(r: Stub, id: string): Promise<void> {
  await runInDurableObject(r, (_i, state) => {
    state.storage.sql.exec("DELETE FROM history WHERE credential_id = ? AND event = 'revoked'", id);
  });
}

async function pendingOf(r: Stub, id: string): Promise<Pending> {
  return runInDurableObject(r, (_i, state) =>
    state.storage.sql
      .exec<Pending>('SELECT pending_history, pending_request_id, pending_at FROM credentials WHERE credential_id = ?', id)
      .one(),
  );
}

const CLEAN: Pending = { pending_history: 0, pending_request_id: null, pending_at: null };

/** Make every history INSERT throw (a storage failure confined to the audit write). */
async function failHistoryInserts(r: Stub, on: boolean): Promise<void> {
  await runInDurableObject(r, (_i, state) => {
    state.storage.sql.exec(
      on
        ? "CREATE TRIGGER test_fail_history_insert BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT, 'injected history failure'); END"
        : 'DROP TRIGGER IF EXISTS test_fail_history_insert',
    );
  });
}

describe('durable revocation and audit repair', () => {
  it('a failed history write leaves the credential REVOKED with pending metadata; a later revoke repairs it from that metadata', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await seedRevokedEvent(r, ID_A, 1, 'seed');
    expect(await r.revoke(ID_A, NOW + 1, 'r1')).toBe('revoked_history_failed');
    expect(await r.status(ID_A)).toBe('REVOKED');
    expect(await pendingOf(r, ID_A)).toEqual({ pending_history: 1, pending_request_id: 'r1', pending_at: NOW + 1 });
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.pending_history).toBe(true);
    expect(got.outcome === 'found' && got.record.revoked_at).toBe(NOW + 1);

    await deleteRevokedEvent(r, ID_A);
    expect(await r.revoke(ID_A, NOW + 2, 'r2')).toBe('unchanged');
    expect(await pendingOf(r, ID_A)).toEqual(CLEAN);
    const after = await r.get(ID_A);
    expect(after.outcome).toBe('found');
    if (after.outcome !== 'found') return;
    expect(after.record.pending_history).toBe(false);
    expect(after.record.revoked_at).toBe(NOW + 1);
    expect(after.record.history).toEqual([
      { event: 'registered', ts: NOW, request_id: 'req-1' },
      { event: 'revoked', ts: NOW + 1, request_id: 'r1' },
    ]);
  });

  it('a retry whose repair THROWS stays revoked_history_failed (the 204 contract), metadata kept; repairHistory still reports storage_error', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await seedRevokedEvent(r, ID_A, 1, 'seed');
    expect(await r.revoke(ID_A, NOW + 1, 'r1')).toBe('revoked_history_failed');
    await deleteRevokedEvent(r, ID_A);
    await failHistoryInserts(r, true);
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(await r.revoke(ID_A, NOW + 2, 'r2')).toBe('revoked_history_failed');
      expect(await r.repairHistory(ID_A)).toBe('storage_error'); // an explicit admin action reports the failure as such
    } finally {
      spy.mockRestore();
      await failHistoryInserts(r, false);
    }
    expect(await r.status(ID_A)).toBe('REVOKED');
    expect(await pendingOf(r, ID_A)).toEqual({ pending_history: 1, pending_request_id: 'r1', pending_at: NOW + 1 });
    expect(await r.repairHistory(ID_A)).toBe('repaired');
    expect(await pendingOf(r, ID_A)).toEqual(CLEAN);
  });

  it('a persistent collision: the first revoke is revoked_history_failed, every retry revoked_history_conflict, repair reports conflict and never clears the metadata', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await seedRevokedEvent(r, ID_A, 1, 'seed');
    const errors: unknown[][] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { errors.push(args); });
    try {
      expect(await r.revoke(ID_A, NOW + 1, 'r1')).toBe('revoked_history_failed');
      expect(await r.revoke(ID_A, NOW + 2, 'r2')).toBe('revoked_history_conflict');
      expect(await r.revoke(ID_A, NOW + 3, 'r3')).toBe('revoked_history_conflict');
      expect(await r.repairHistory(ID_A)).toBe('conflict');
    } finally {
      spy.mockRestore();
    }
    expect(await pendingOf(r, ID_A)).toEqual({ pending_history: 1, pending_request_id: 'r1', pending_at: NOW + 1 });
    expect(await r.status(ID_A)).toBe('REVOKED');
    const conflict = errors.find((e) => e[0] === 'hosted-verify history conflict');
    expect(conflict?.[1]).toEqual({
      credential_id: ID_A,
      pending: { ts: NOW + 1, request_id: 'r1' },
      stored: { ts: 1, request_id: 'seed' },
    });
    // No log line carries the stored binding.
    expect(JSON.stringify(errors)).not.toContain('DROP TABLE');
  });

  it.each([
    ['the same request id at a different ts', 1, 'r1'],
    ['the same ts under a different request id', NOW + 1, 'other'],
  ])('a stored revoked event with %s is a conflict, not our own event', async (_name, ts, request_id) => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await seedRevokedEvent(r, ID_A, ts, request_id);
    expect(await r.revoke(ID_A, NOW + 1, 'r1')).toBe('revoked_history_failed');
    expect(await r.repairHistory(ID_A)).toBe('conflict');
    expect((await pendingOf(r, ID_A)).pending_history).toBe(1);
  });

  it('crash recovery: REVOKED with pending metadata and no event → repairHistory writes the event from the metadata and clears it', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    const T = NOW + 7;
    await runInDurableObject(r, (_i, state) => {
      state.storage.sql.exec(
        "UPDATE credentials SET status = 'REVOKED', revoked_at = ?, pending_history = 1, pending_request_id = 'p', pending_at = ? WHERE credential_id = ?",
        T,
        T,
        ID_A,
      );
    });
    expect(await r.repairHistory(ID_A)).toBe('repaired');
    expect(await pendingOf(r, ID_A)).toEqual(CLEAN);
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history[1]).toEqual({ event: 'revoked', ts: T, request_id: 'p' });
    expect(await r.repairHistory(ID_A)).toBe('clean');
  });

  it('pending metadata that is itself incomplete (null ts / request id) is a conflict: never cleared, logged with stored: null', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await runInDurableObject(r, (_i, state) => {
      state.storage.sql.exec(
        "UPDATE credentials SET status = 'REVOKED', revoked_at = ?, pending_history = 1, pending_request_id = NULL, pending_at = NULL WHERE credential_id = ?",
        NOW + 7,
        ID_A,
      );
    });
    const errors: unknown[][] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { errors.push(args); });
    try {
      expect(await r.repairHistory(ID_A)).toBe('conflict');
    } finally {
      spy.mockRestore();
    }
    expect(await pendingOf(r, ID_A)).toEqual({ pending_history: 1, pending_request_id: null, pending_at: null });
    expect(errors.find((e) => e[0] === 'hosted-verify history conflict')?.[1]).toEqual({
      credential_id: ID_A,
      pending: { ts: null, request_id: null },
      stored: null,
    });
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history.map((h) => h.event)).toEqual(['registered']);
  });

  it('crash recovery through a plain revoke: repairs and answers unchanged', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    const T = NOW + 7;
    await runInDurableObject(r, (_i, state) => {
      state.storage.sql.exec(
        "UPDATE credentials SET status = 'REVOKED', revoked_at = ?, pending_history = 1, pending_request_id = 'p', pending_at = ? WHERE credential_id = ?",
        T,
        T,
        ID_A,
      );
    });
    expect(await r.revoke(ID_A, NOW + 9, 'later')).toBe('unchanged');
    expect(await pendingOf(r, ID_A)).toEqual(CLEAN);
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history.map((h) => [h.event, h.ts, h.request_id])).toEqual([
      ['registered', NOW, 'req-1'],
      ['revoked', T, 'p'],
    ]);
  });

  it('pending metadata that matches the stored event exactly is our own committed event: cleared, repaired', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.revoke(ID_A, NOW + 3, 'r1')).toBe('revoked');
    await runInDurableObject(r, (_i, state) => {
      state.storage.sql.exec(
        "UPDATE credentials SET pending_history = 1, pending_request_id = 'r1', pending_at = ? WHERE credential_id = ?",
        NOW + 3,
        ID_A,
      );
    });
    expect(await r.repairHistory(ID_A)).toBe('repaired');
    expect(await pendingOf(r, ID_A)).toEqual(CLEAN);
    const got = await r.get(ID_A);
    expect(got.outcome === 'found' && got.record.history).toHaveLength(2);
  });

  it('a normal revoke leaves no pending metadata; repairHistory on it → clean; unknown → absent; ill-typed → invalid_input', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    expect(await r.repairHistory(ID_A)).toBe('clean');
    expect(await r.revoke(ID_A, NOW + 1, 'r1')).toBe('revoked');
    expect(await pendingOf(r, ID_A)).toEqual(CLEAN);
    expect(await r.repairHistory(ID_A)).toBe('clean');
    expect(await r.repairHistory(ID_B)).toBe('absent');
    expect(await r.repairHistory(12345 as unknown as string)).toBe('invalid_input');
  });

  it('pending metadata survives an instance reset and is repairable afterwards', async () => {
    const r = registry(ORGS.A);
    await r.register(input(ID_A));
    await seedRevokedEvent(r, ID_A, 1, 'seed');
    expect(await r.revoke(ID_A, NOW + 1, 'r1')).toBe('revoked_history_failed');
    await deleteRevokedEvent(r, ID_A);
    await evictDurableObject(r);
    const again = registry(ORGS.A);
    expect(await again.status(ID_A)).toBe('REVOKED');
    expect(await again.repairHistory(ID_A)).toBe('repaired');
    const got = await again.get(ID_A);
    expect(got.outcome === 'found' && got.record.history[1]).toEqual({ event: 'revoked', ts: NOW + 1, request_id: 'r1' });
  });
});
