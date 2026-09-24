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
 *              absent, tenant already holds MAX_ACTIVE_CREDENTIALS ACTIVE rows
 *                       ─► { quota_exceeded }  (nothing stored; checked AFTER the
 *                          existing-record arms, so the three above never hit the cap)
 *   revoke:    absent ─► 'absent'   ACTIVE ─► 'revoked' + history   REVOKED ─► 'unchanged' (pending ─► repair first)
 *              ACTIVE, history write fails ─► 'revoked_history_failed' (still REVOKED; see below)
 *              REVOKED, pending, repair finds a conflict ─► 'revoked_history_conflict'
 *              REVOKED, pending, repair throws ─► 'revoked_history_failed' (metadata kept)
 *
 * Revocation is durable even when its audit row cannot be written. It is two
 * transactions, run back to back with no `await` between them:
 *   1. status → REVOKED, and the event it owes the history (pending_history = 1,
 *      pending_request_id, pending_at) recorded ON the credential row;
 *   2. the 'revoked' history row inserted from that metadata AND the metadata
 *      cleared, together.
 * If (2) fails the revocation stands and the metadata stays: `repairHistory`
 * (and any later `revoke` of the same id) retries (2) idempotently. A stored
 * 'revoked' row that does not match the metadata exactly (ts AND request_id)
 * is a conflict: reported, never cleared — the credential is revoked either way.
 *
 * A credential row and its 'registered' event are created in the same
 * transaction, so a history row without a credential row cannot exist.
 *
 * Rules this class lives by:
 *   1. Every mutation is synchronous, with no `await` anywhere in it, so a
 *      method runs to completion before the object can deliver another event:
 *      revoke's two transactions cannot interleave with another call. (The
 *      input gate only matters across an `await`, and there are none.)
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

/**
 * Per-tenant cap on ACTIVE credentials. Only revocation frees a slot: a row
 * whose binding has expired but was never revoked is still ACTIVE and still
 * counts (no reclamation). REVOKED rows never count. The count and the insert
 * are one transaction, so two registrations at cap-1 cannot both succeed.
 */
export const MAX_ACTIVE_CREDENTIALS = 1000;

/**
 * Bound on a stored binding: the UTF-8 byte length of the canonical binding
 * JSON (bytes, never string length — a 3-byte character is 3 bytes).
 */
export const MAX_BINDING_JSON_BYTES = 16_384;

const utf8 = new TextEncoder();

/** UTF-8 byte length of `s`. */
export function utf8ByteLength(s: string): number {
  return utf8.encode(s).byteLength;
}

export type RegisterResult =
  | { outcome: 'created' | 'unchanged'; registered_at: number }
  | { outcome: 'revoked' }
  | { outcome: 'quota_exceeded' }
  | { outcome: 'expired' }
  | { outcome: 'mismatch' }
  | { outcome: 'invalid_input' }
  | { outcome: 'storage_error' };

export type RevokeResult =
  | 'revoked'
  | 'unchanged'
  /** The credential IS revoked; its audit row is owed (pending metadata kept for repair). */
  | 'revoked_history_failed'
  /** A retry of an owed audit row found a conflicting row (or unusable metadata): a human looks. Still REVOKED. */
  | 'revoked_history_conflict'
  | 'absent'
  | 'invalid_input'
  | 'storage_error';

export type RepairResult = 'repaired' | 'clean' | 'conflict' | 'absent' | 'invalid_input' | 'storage_error';

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
  /** True while the revocation's history row is owed (see `repairHistory`). */
  pending_history: boolean;
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
  pending_history: number;
  pending_request_id: string | null;
  pending_at: number | null;
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
    // Belt and braces: the route answers an oversized binding 413 before it
    // ever calls the object, so this `invalid_input` (which the route maps to
    // 500) is unreachable over HTTP. It guards the object against any other caller.
    utf8ByteLength(i.binding_json) <= MAX_BINDING_JSON_BYTES &&
    isUnixSeconds(i.expiry) &&
    isUnixSeconds(i.now) &&
    typeof i.request_id === 'string'
  );
}

/** SQLite messages name tables, columns and constraints — never bound values (verified). */
function logStorageError(operation: string, requestId: string | undefined, e: unknown, credentialId?: string): void {
  console.error(
    `hosted-verify registry storage error (${operation}):`,
    e instanceof Error ? (e.stack ?? e.message) : String(e),
    { request_id: requestId ?? '', ...(credentialId !== undefined ? { credential_id: credentialId } : {}) },
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
      this.ctx.storage.transactionSync(() => this.#migrate());
    } catch (e) {
      this.#schemaError = e;
      logStorageError('schema', undefined, e);
    }
  }

  /**
   * Create, then migrate, inside the constructor's transaction. Refusing a
   * layout THROWS, so everything this ran (the base schema included) rolls back
   * and the constructor latches the error.
   */
  #migrate(): void {
    const sql = this.ctx.storage.sql;
    sql.exec(SCHEMA);
    sql.exec(SCHEMA_META);
    if (sql.exec('SELECT 1 FROM schema_meta').toArray().length === 0) {
      sql.exec('INSERT INTO schema_meta (rowid, version) VALUES (1, 1)');
    }
    const version = sql.exec<{ version: number }>('SELECT version FROM schema_meta').one().version;
    if (!Number.isSafeInteger(version) || version < 1) {
      throw new Error(`schema version ${version} is not a known layout`);
    }
    if (version > SCHEMA_VERSION) {
      // A rolled-back Worker meeting a database a newer build migrated: refuse
      // rather than read or write a layout this code does not know.
      throw new Error(`schema version ${version} is newer than this build supports (${SCHEMA_VERSION})`);
    }
    for (let v = version; v < SCHEMA_VERSION; v++) MIGRATIONS[v - 1]!(sql);
    if (version < SCHEMA_VERSION) sql.exec('UPDATE schema_meta SET version = ?', SCHEMA_VERSION);
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
        const active = this.ctx.storage.sql
          .exec<{ n: number }>("SELECT count(*) AS n FROM credentials WHERE status = 'ACTIVE'")
          .one().n;
        if (active >= MAX_ACTIVE_CREDENTIALS) return { outcome: 'quota_exceeded' };
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
    // Transaction 1: the revocation itself, with the audit event it owes.
    let step: RevokeResult | 'repair' | { revokedAt: number };
    try {
      step = this.ctx.storage.transactionSync((): RevokeResult | 'repair' | { revokedAt: number } => {
        const row = this.ctx.storage.sql
          .exec<Pick<CredentialRow, 'status' | 'registered_at' | 'pending_history'>>(
            'SELECT status, registered_at, pending_history FROM credentials WHERE credential_id = ?',
            credential_id,
          )
          .toArray()[0];
        if (row === undefined) return 'absent';
        if (row.status === 'REVOKED') return row.pending_history === 1 ? 'repair' : 'unchanged';
        // Clocks differ between the colo that registered and the one revoking:
        // never record a revocation earlier than the registration it ends.
        const revokedAt = Math.max(now, row.registered_at);
        this.ctx.storage.sql.exec(
          'UPDATE credentials SET status = ?, revoked_at = ?, pending_history = 1, pending_request_id = ?, pending_at = ? WHERE credential_id = ?',
          'REVOKED',
          revokedAt,
          request_id,
          revokedAt,
          credential_id,
        );
        return { revokedAt };
      });
    } catch (e) {
      logStorageError('revoke', request_id, e, credential_id);
      return 'storage_error';
    }
    if (step === 'repair') {
      // Already revoked, audit row still owed: this call is a retry of it.
      const repaired = this.#repair(credential_id);
      switch (repaired) {
        case 'repaired':
        case 'clean':
          return 'unchanged';
        case 'conflict':
          return 'revoked_history_conflict';
        case 'storage_error':
          // The credential is revoked (transaction 1 of an earlier call committed) and only
          // the audit row is still owed: the same 204 + history_write_failed as the first
          // attempt, never a 500. The metadata stays (the repair rolled back).
          return 'revoked_history_failed';
        default:
          return 'storage_error';
      }
    }
    if (typeof step === 'string') return step;
    const { revokedAt } = step;
    // Transaction 2: the audit row and the clearing of its metadata, together.
    // Synchronous and right after (1), so no other call runs in between.
    try {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(
          'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
          credential_id,
          'revoked',
          revokedAt,
          request_id,
        );
        this.ctx.storage.sql.exec(
          'UPDATE credentials SET pending_history = 0, pending_request_id = NULL, pending_at = NULL WHERE credential_id = ?',
          credential_id,
        );
      });
    } catch (e) {
      // The revocation stands (transaction 1 committed); the metadata stays for repair.
      logStorageError('revoke_history_failed', request_id, e, credential_id);
      return 'revoked_history_failed';
    }
    return 'revoked';
  }

  /**
   * Write a revocation's owed audit row from its pending metadata. Idempotent:
   *   no pending metadata            ─► 'clean'
   *   no 'revoked' row               ─► insert it from the metadata, clear ─► 'repaired'
   *   a 'revoked' row with the SAME ts and request_id (our own event) ─► clear ─► 'repaired'
   *   a 'revoked' row that differs in either ─► 'conflict', metadata KEPT, logged
   */
  repairHistory(credential_id: string): RepairResult {
    if (this.#schemaError !== undefined) return 'storage_error';
    if (!isNonEmptyString(credential_id)) return 'invalid_input';
    return this.#repair(credential_id);
  }

  #repair(credential_id: string): RepairResult {
    try {
      return this.ctx.storage.transactionSync((): RepairResult => {
        const sql = this.ctx.storage.sql;
        const row = sql
          .exec<Pick<CredentialRow, 'pending_history' | 'pending_request_id' | 'pending_at'>>(
            'SELECT pending_history, pending_request_id, pending_at FROM credentials WHERE credential_id = ?',
            credential_id,
          )
          .toArray()[0];
        if (row === undefined) return 'absent';
        if (row.pending_history !== 1) return 'clean';
        const pending = { ts: row.pending_at, request_id: row.pending_request_id };
        const stored = sql
          .exec<Pick<HistoryEvent, 'ts' | 'request_id'>>(
            "SELECT ts, request_id FROM history WHERE credential_id = ? AND event = 'revoked'",
            credential_id,
          )
          .toArray()[0];
        const unusable = pending.ts === null || pending.request_id === null;
        const foreign = stored !== undefined && (stored.ts !== pending.ts || stored.request_id !== pending.request_id);
        if (unusable || foreign) {
          // Never cleared silently: a human decides which record is right.
          console.error('hosted-verify history conflict', {
            credential_id,
            pending,
            stored: stored === undefined ? null : { ts: stored.ts, request_id: stored.request_id },
          });
          return 'conflict';
        }
        if (stored === undefined) {
          sql.exec(
            'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
            credential_id,
            'revoked',
            pending.ts,
            pending.request_id,
          );
        }
        sql.exec(
          'UPDATE credentials SET pending_history = 0, pending_request_id = NULL, pending_at = NULL WHERE credential_id = ?',
          credential_id,
        );
        return 'repaired';
      });
    } catch (e) {
      logStorageError('repair_history', undefined, e, credential_id);
      return 'storage_error';
    }
  }

  get(credential_id: string): GetResult {
    if (this.#schemaError !== undefined) return { outcome: 'storage_error' };
    if (!isNonEmptyString(credential_id)) return { outcome: 'invalid_input' };
    try {
      const row = this.ctx.storage.sql
        .exec<Omit<CredentialRow, 'pending_request_id' | 'pending_at'>>(
          'SELECT credential_id, status, operator_key, binding_digest, binding_json, registered_at, revoked_at, pending_history FROM credentials WHERE credential_id = ?',
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
      const { binding_digest, pending_history, ...rest } = row;
      return {
        outcome: 'found',
        record: { ...rest, binding_digest_hex: binding_digest, pending_history: pending_history === 1, history },
      };
    } catch (e) {
      logStorageError('get', undefined, e);
      return { outcome: 'storage_error' };
    }
  }
}
