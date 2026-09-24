/**
 * `TenantRegistry` — one SQLite-backed Durable Object per tenant, named by the
 * tenant's org_id. It holds the tenant's managed credentials and an append-only
 * event history.
 *
 *   credentials(credential_id PK, operator_key, binding_digest, binding_json,
 *               status ∈ {ACTIVE, REVOKED}, registered_at, revoked_at)
 *   history(credential_id, event ∈ {registered, revoked}, ts, request_id)
 *               PRIMARY KEY (credential_id, event)   -- at most one of each
 *   schema_meta(version)  -- exactly one row; see SCHEMA_VERSION and MIGRATIONS
 *
 * The constructor creates a fresh database and migrates an older one in ONE
 * transaction; a database NEWER than this build (a rolled-back Worker) is
 * refused: every method returns `storage_error` rather than touch a layout
 * this code does not know.
 *
 * Lifecycle (the caller has already authenticated the tenant, checked trust
 * membership and the signature, and computed the id):
 *
 *   register:  expired  ─► { expired }          (re-checked here with the caller's `now`)
 *              absent   ─► { created }  + history 'registered'
 *              ACTIVE, same key + digest ─► { unchanged } (original registered_at; no new row)
 *              ACTIVE/REVOKED, DIFFERENT key or digest ─► { mismatch }  (an id-derivation
 *                          defect or a collision; never silently kept, never overwritten)
 *              REVOKED  ─► { revoked }   (terminal; nothing is replaced)
 *   revoke:    absent ─► 'absent'   ACTIVE ─► 'revoked' + history   REVOKED ─► 'unchanged'
 *
 * A credential row and its 'registered' event are created in the same
 * transaction, so a history row without a credential row cannot exist.
 *
 * Rules this class lives by:
 *   1. Every mutation is ONE `transactionSync` with no `await` inside. The
 *      object's input gate only covers storage operations, so a method that
 *      awaited between a read and a write would interleave with other calls;
 *      synchronous methods run to completion one after another.
 *   2. Nothing is thrown across the RPC boundary — a throw inside the object is
 *      reported as an unhandled rejection by the runtime even when the caller
 *      handles it. Storage failures are RETURNED (`storage_error`), a schema
 *      failure at construction is remembered and returned by every method, and
 *      ill-typed inputs are RETURNED (`invalid_input`): TypeScript types do not
 *      survive the RPC boundary, so the object validates for itself.
 *   3. Every SQL statement binds its parameters with `?`; no value is ever
 *      interpolated into SQL text. History is ordered by insertion (`rowid`),
 *      never by the caller-supplied timestamp.
 */

import { DurableObject } from 'cloudflare:workers';
import type { Env } from './index';

export type Status = 'ACTIVE' | 'REVOKED' | 'ABSENT';

export interface RegisterInput {
  credential_id: string;
  operator_key: string;
  binding_digest_hex: string;
  binding_json: string;
  expiry: number;
  now: number;
  request_id: string;
}

export type RegisterResult =
  | { outcome: 'created' | 'unchanged'; registered_at: number }
  | { outcome: 'revoked' }
  | { outcome: 'expired' }
  | { outcome: 'mismatch' }
  | { outcome: 'invalid_input' }
  | { outcome: 'storage_error' };

export type RevokeResult = 'revoked' | 'unchanged' | 'absent' | 'invalid_input' | 'storage_error';

export type StatusResult = Status | 'invalid_input' | 'storage_error';

// `type` aliases, not interfaces: `sql.exec<T>` requires an implicit index
// signature, which TypeScript gives to aliases and mapped types only.
export type HistoryEvent = {
  event: 'registered' | 'revoked';
  ts: number;
  request_id: string;
};

export interface CredentialRecord {
  credential_id: string;
  status: Exclude<Status, 'ABSENT'>;
  operator_key: string;
  binding_digest_hex: string;
  binding_json: string;
  registered_at: number;
  revoked_at: number | null;
  history: HistoryEvent[];
}

export type GetResult =
  | { outcome: 'found'; record: CredentialRecord }
  | { outcome: 'absent' }
  | { outcome: 'invalid_input' }
  | { outcome: 'storage_error' };

const SCHEMA = `
CREATE TABLE IF NOT EXISTS credentials (
  credential_id   TEXT PRIMARY KEY,
  operator_key    TEXT NOT NULL,
  binding_digest  TEXT NOT NULL,
  binding_json    TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  registered_at   INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE TABLE IF NOT EXISTS history (
  credential_id   TEXT NOT NULL,
  event           TEXT NOT NULL CHECK (event IN ('registered','revoked')),
  ts              INTEGER NOT NULL,
  request_id      TEXT NOT NULL,
  PRIMARY KEY (credential_id, event)
);
`;

/**
 * The layout version this build reads and writes. `schema_meta` holds exactly
 * one row (the CHECK pins its rowid). Version 1 is the pre-versioning layout
 * above — every object created before versioning, and the starting point of a
 * brand-new object; migrations then bring it to `SCHEMA_VERSION`.
 */
export const SCHEMA_VERSION = 2;

const SCHEMA_META = `
CREATE TABLE IF NOT EXISTS schema_meta (
  version INTEGER NOT NULL,
  CHECK (rowid = 1)
);
`;

/**
 * Migration N → N+1 is `MIGRATIONS[N - 1]`. Each one is idempotent on its own
 * (a partially applied migration can be re-run), and runs inside the
 * constructor's single transaction together with the version bump.
 */
const MIGRATIONS: ReadonlyArray<(sql: SqlStorage) => void> = [
  // 1 → 2: recovery metadata for a revocation whose history row is not yet written.
  (sql) => {
    const columns = new Set(
      sql
        .exec<{ name: string }>('PRAGMA table_info(credentials)')
        .toArray()
        .map((c) => c.name),
    );
    const add: Array<[string, string]> = [
      ['pending_history', 'pending_history INTEGER NOT NULL DEFAULT 0'],
      ['pending_request_id', 'pending_request_id TEXT'],
      ['pending_at', 'pending_at INTEGER'],
    ];
    for (const [name, definition] of add) {
      if (!columns.has(name)) sql.exec(`ALTER TABLE credentials ADD COLUMN ${definition}`);
    }
  },
];

type CredentialRow = {
  credential_id: string;
  status: 'ACTIVE' | 'REVOKED';
  operator_key: string;
  binding_digest: string;
  binding_json: string;
  registered_at: number;
  revoked_at: number | null;
};

const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isUnixSeconds = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

function validRegisterInput(input: unknown): input is RegisterInput {
  if (typeof input !== 'object' || input === null) return false;
  const i = input as Record<string, unknown>;
  return (
    isNonEmptyString(i.credential_id) &&
    isNonEmptyString(i.operator_key) &&
    isNonEmptyString(i.binding_digest_hex) &&
    typeof i.binding_json === 'string' &&
    isUnixSeconds(i.expiry) &&
    isUnixSeconds(i.now) &&
    typeof i.request_id === 'string'
  );
}

/** SQLite messages name tables, columns and constraints — never bound values (verified). */
function logStorageError(operation: string, requestId: string | undefined, e: unknown): void {
  console.error(
    `hosted-verify registry storage error (${operation}):`,
    e instanceof Error ? (e.stack ?? e.message) : String(e),
    { request_id: requestId ?? '' },
  );
}

export class TenantRegistry extends DurableObject<Env> {
  /** Set when the schema could not be created; every method then returns `storage_error`. */
  #schemaError: unknown = undefined;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Synchronous and idempotent: the schema exists, at this build's version,
    // before any request runs. Creation and migration are ONE transaction, so a
    // failure leaves the database exactly as it was.
    try {
      this.#schemaError = this.ctx.storage.transactionSync(() => this.#migrate());
      if (this.#schemaError !== undefined) logStorageError('schema', undefined, this.#schemaError);
    } catch (e) {
      this.#schemaError = e;
      logStorageError('schema', undefined, e);
    }
  }

  /** Returns an Error (not thrown: nothing to roll back) when the database is newer than this build. */
  #migrate(): Error | undefined {
    const sql = this.ctx.storage.sql;
    sql.exec(SCHEMA);
    sql.exec(SCHEMA_META);
    if (sql.exec('SELECT 1 FROM schema_meta').toArray().length === 0) {
      sql.exec('INSERT INTO schema_meta (rowid, version) VALUES (1, 1)');
    }
    const version = sql.exec<{ version: number }>('SELECT version FROM schema_meta').one().version;
    if (version > SCHEMA_VERSION) {
      // A rolled-back Worker meeting a database a newer build migrated: refuse
      // rather than read or write a layout this code does not know.
      return new Error(`schema version ${version} is newer than this build supports (${SCHEMA_VERSION})`);
    }
    for (let v = version; v < SCHEMA_VERSION; v++) MIGRATIONS[v - 1]!(sql);
    if (version < SCHEMA_VERSION) sql.exec('UPDATE schema_meta SET version = ?', SCHEMA_VERSION);
    return undefined;
  }

  register(input: RegisterInput): RegisterResult {
    if (this.#schemaError !== undefined) return { outcome: 'storage_error' };
    if (!validRegisterInput(input)) return { outcome: 'invalid_input' };
    if (input.expiry <= input.now) return { outcome: 'expired' };
    try {
      return this.ctx.storage.transactionSync((): RegisterResult => {
        const existing = this.ctx.storage.sql
          .exec<Pick<CredentialRow, 'status' | 'registered_at' | 'operator_key' | 'binding_digest'>>(
            'SELECT status, registered_at, operator_key, binding_digest FROM credentials WHERE credential_id = ?',
            input.credential_id,
          )
          .toArray()[0];
        if (existing !== undefined) {
          if (existing.operator_key !== input.operator_key || existing.binding_digest !== input.binding_digest_hex) {
            return { outcome: 'mismatch' };
          }
          return existing.status === 'REVOKED'
            ? { outcome: 'revoked' }
            : { outcome: 'unchanged', registered_at: existing.registered_at };
        }
        this.ctx.storage.sql.exec(
          'INSERT INTO credentials (credential_id, operator_key, binding_digest, binding_json, status, registered_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)',
          input.credential_id,
          input.operator_key,
          input.binding_digest_hex,
          input.binding_json,
          'ACTIVE',
          input.now,
        );
        this.ctx.storage.sql.exec(
          'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
          input.credential_id,
          'registered',
          input.now,
          input.request_id,
        );
        return { outcome: 'created', registered_at: input.now };
      });
    } catch (e) {
      logStorageError('register', input.request_id, e);
      return { outcome: 'storage_error' };
    }
  }

  status(credential_id: string): StatusResult {
    if (this.#schemaError !== undefined) return 'storage_error';
    if (!isNonEmptyString(credential_id)) return 'invalid_input';
    try {
      const row = this.ctx.storage.sql
        .exec<Pick<CredentialRow, 'status'>>('SELECT status FROM credentials WHERE credential_id = ?', credential_id)
        .toArray()[0];
      return row === undefined ? 'ABSENT' : row.status;
    } catch (e) {
      logStorageError('status', undefined, e);
      return 'storage_error';
    }
  }

  revoke(credential_id: string, now: number, request_id: string): RevokeResult {
    if (this.#schemaError !== undefined) return 'storage_error';
    if (!isNonEmptyString(credential_id) || !isUnixSeconds(now) || typeof request_id !== 'string') {
      return 'invalid_input';
    }
    try {
      return this.ctx.storage.transactionSync((): RevokeResult => {
        const row = this.ctx.storage.sql
          .exec<Pick<CredentialRow, 'status' | 'registered_at'>>(
            'SELECT status, registered_at FROM credentials WHERE credential_id = ?',
            credential_id,
          )
          .toArray()[0];
        if (row === undefined) return 'absent';
        if (row.status === 'REVOKED') return 'unchanged';
        // Clocks differ between the colo that registered and the one revoking:
        // never record a revocation earlier than the registration it ends.
        const revokedAt = Math.max(now, row.registered_at);
        this.ctx.storage.sql.exec(
          'UPDATE credentials SET status = ?, revoked_at = ? WHERE credential_id = ?',
          'REVOKED',
          revokedAt,
          credential_id,
        );
        this.ctx.storage.sql.exec(
          'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
          credential_id,
          'revoked',
          revokedAt,
          request_id,
        );
        return 'revoked';
      });
    } catch (e) {
      logStorageError('revoke', request_id, e);
      return 'storage_error';
    }
  }

  get(credential_id: string): GetResult {
    if (this.#schemaError !== undefined) return { outcome: 'storage_error' };
    if (!isNonEmptyString(credential_id)) return { outcome: 'invalid_input' };
    try {
      const row = this.ctx.storage.sql
        .exec<CredentialRow>(
          'SELECT credential_id, status, operator_key, binding_digest, binding_json, registered_at, revoked_at FROM credentials WHERE credential_id = ?',
          credential_id,
        )
        .toArray()[0];
      if (row === undefined) return { outcome: 'absent' };
      const history = this.ctx.storage.sql
        .exec<HistoryEvent>(
          'SELECT event, ts, request_id FROM history WHERE credential_id = ? ORDER BY rowid ASC',
          credential_id,
        )
        .toArray()
        .map((h) => ({ event: h.event, ts: h.ts, request_id: h.request_id }));
      const { binding_digest, ...rest } = row;
      return { outcome: 'found', record: { ...rest, binding_digest_hex: binding_digest, history } };
    } catch (e) {
      logStorageError('get', undefined, e);
      return { outcome: 'storage_error' };
    }
  }
}
