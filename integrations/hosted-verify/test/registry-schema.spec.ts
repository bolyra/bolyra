/**
 * Schema versioning for the registry Durable Object: `schema_meta` holds one
 * version row; the constructor creates a fresh database and migrates an older
 * one in ONE transaction, and refuses (every method → storage_error) a database
 * NEWER than this build. Storage isolation is per file; every test resets.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { env, evictDurableObject, reset, runInDurableObject } from 'cloudflare:test';
import type { RegisterInput } from '../src/registry';

const ID_A = 'a'.repeat(64);
const ID_B = 'b'.repeat(64);
const NOW = 1_800_000_000;
const PENDING_COLUMNS = ['pending_history', 'pending_request_id', 'pending_at'];

const registry = (org: string) => env.TENANT.get(env.TENANT.idFromName(org));

function input(credential_id: string, overrides: Partial<RegisterInput> = {}): RegisterInput {
  return {
    credential_id,
    operator_key: '1:2',
    binding_digest_hex: '0'.repeat(63) + '1',
    binding_json: JSON.stringify({ agent_name: 'a', capabilities: ['fetch_inbox'], expiry: NOW + 3600 }),
    expiry: NOW + 3600,
    now: NOW,
    request_id: 'req-1',
    ...overrides,
  };
}

type Stub = ReturnType<typeof registry>;

async function versionOf(r: Stub): Promise<number[]> {
  return runInDurableObject(r, (_i, state) =>
    state.storage.sql.exec<{ version: number }>('SELECT version FROM schema_meta').toArray().map((row) => row.version),
  );
}

async function columnsOf(r: Stub): Promise<string[]> {
  return runInDurableObject(r, (_i, state) =>
    state.storage.sql.exec<{ name: string }>('PRAGMA table_info(credentials)').toArray().map((c) => c.name),
  );
}

/**
 * Rewrite an object's storage into the pre-versioning (v1) layout, with one
 * ACTIVE credential, and evict it. Returns the seeded credentials columns
 * (read here: any later look constructs the object, which migrates it).
 */
async function seedLegacy(r: Stub, extraColumns = ''): Promise<string[]> {
  const columns = await runInDurableObject(r, (_i, state) => {
    const sql = state.storage.sql;
    sql.exec('DROP TABLE schema_meta');
    sql.exec('DROP TABLE credentials');
    sql.exec(`CREATE TABLE credentials (
      credential_id   TEXT PRIMARY KEY,
      operator_key    TEXT NOT NULL,
      binding_digest  TEXT NOT NULL,
      binding_json    TEXT NOT NULL,
      status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
      registered_at   INTEGER NOT NULL,
      revoked_at      INTEGER${extraColumns}
    )`);
    sql.exec(
      "INSERT INTO credentials (credential_id, operator_key, binding_digest, binding_json, status, registered_at, revoked_at) VALUES (?, '1:2', ?, '{}', 'ACTIVE', ?, NULL)",
      ID_A,
      '0'.repeat(63) + '1',
      NOW,
    );
    sql.exec("INSERT INTO history VALUES (?, 'registered', ?, 'legacy-req')", ID_A, NOW);
    return sql.exec<{ name: string }>('PRAGMA table_info(credentials)').toArray().map((c) => c.name);
  });
  await evictDurableObject(r);
  return columns;
}

beforeEach(async () => {
  await reset();
});

describe('schema versioning', () => {
  it('a fresh object is created at version 2 with the pending-history columns', async () => {
    const r = registry('schema-fresh');
    expect(await r.status(ID_A)).toBe('ABSENT');
    expect(await versionOf(r)).toEqual([2]);
    expect(await columnsOf(r)).toEqual(expect.arrayContaining(PENDING_COLUMNS));
  });

  it('schema_meta can never hold a second row', async () => {
    const r = registry('schema-fresh');
    await r.status(ID_A);
    const threw = await runInDurableObject(r, (_i, state) => {
      try {
        state.storage.sql.exec('INSERT INTO schema_meta (version) VALUES (2)');
        return false;
      } catch {
        return true;
      }
    });
    expect(threw).toBe(true);
    expect(await versionOf(r)).toEqual([2]);
  });

  it('a legacy (v1) object migrates to v2 on construction; its credential stays readable and revocable', async () => {
    const r = registry('schema-legacy');
    await r.status(ID_A);
    const seeded = await seedLegacy(r);
    for (const c of PENDING_COLUMNS) expect(seeded).not.toContain(c);

    const again = registry('schema-legacy');
    const got = await again.get(ID_A);
    expect(got.outcome).toBe('found');
    if (got.outcome !== 'found') return;
    expect(got.record.status).toBe('ACTIVE');
    expect(got.record.history).toEqual([{ event: 'registered', ts: NOW, request_id: 'legacy-req' }]);
    expect(await versionOf(again)).toEqual([2]);
    expect(await columnsOf(again)).toEqual(expect.arrayContaining(PENDING_COLUMNS));

    expect(await again.revoke(ID_A, NOW + 10, 'req-r')).toBe('revoked');
    expect(await again.status(ID_A)).toBe('REVOKED');
    expect(await again.register(input(ID_B))).toEqual({ outcome: 'created', registered_at: NOW });
  });

  it('a partially applied migration (one column already added, still v1) completes on the next construction', async () => {
    const r = registry('schema-partial');
    await r.status(ID_A);
    const seeded = await seedLegacy(r, ',\n      pending_history INTEGER NOT NULL DEFAULT 0');
    expect(seeded).toContain('pending_history');
    expect(seeded).not.toContain('pending_at');

    const again = registry('schema-partial');
    expect(await again.status(ID_A)).toBe('ACTIVE');
    expect(await versionOf(again)).toEqual([2]);
    const cols = await columnsOf(again);
    for (const c of PENDING_COLUMNS) expect(cols.filter((x) => x === c)).toHaveLength(1);
  });

  it('a database NEWER than this build → every method returns storage_error, nothing is changed', async () => {
    const r = registry('schema-newer');
    await r.register(input(ID_A));
    await runInDurableObject(r, (_i, state) => {
      state.storage.sql.exec('UPDATE schema_meta SET version = 99');
    });
    await evictDurableObject(r);
    const again = registry('schema-newer');
    expect(await again.status(ID_A)).toBe('storage_error');
    expect(await again.revoke(ID_A, NOW + 1, 'r')).toBe('storage_error');
    expect(await again.get(ID_A)).toEqual({ outcome: 'storage_error' });
    expect(await again.register(input(ID_B))).toEqual({ outcome: 'storage_error' });
    expect(await again.repairHistory(ID_A)).toBe('storage_error');
    expect(await versionOf(again)).toEqual([99]);
  });

  it('a restart at the current version is a no-op: version, columns and credentials unchanged', async () => {
    const r = registry('schema-restart');
    await r.register(input(ID_A));
    await r.revoke(ID_A, NOW + 5, 'req-r');
    const colsBefore = await columnsOf(r);
    await evictDurableObject(r);
    const again = registry('schema-restart');
    expect(await again.status(ID_A)).toBe('REVOKED');
    expect(await versionOf(again)).toEqual([2]);
    expect(await columnsOf(again)).toEqual(colsBefore);
    const got = await again.get(ID_A);
    expect(got.outcome === 'found' && got.record.history.map((h) => h.event)).toEqual(['registered', 'revoked']);
  });
});
