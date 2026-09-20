/**
 * `TenantRegistry` — one SQLite-backed Durable Object per tenant, named by the
 * tenant's org_id. It holds the tenant's managed credentials and an append-only
 * event history.
 *
 *   credentials(credential_id PK, operator_key, binding_digest, binding_json,
 *               status ∈ {ACTIVE, REVOKED}, registered_at, revoked_at)
 *   history(credential_id, event ∈ {registered, revoked}, ts, request_id)
 *               PRIMARY KEY (credential_id, event)   -- at most one of each
 *
 * Lifecycle (the caller has already authenticated the tenant, checked trust
 * membership and the signature, and computed the id):
 *
 *   register:  expired ─► { expired }           (re-checked here with the caller's `now`)
 *              absent  ─► { created }  + history 'registered'
 *              ACTIVE  ─► { unchanged } (original registered_at; no new row)
 *              REVOKED ─► { revoked }   (terminal; nothing is replaced)
 *   revoke:    absent ─► 'absent'   ACTIVE ─► 'revoked' + history   REVOKED ─► 'unchanged'
 *
 * Two rules this class lives by:
 *   1. Every mutation is ONE `transactionSync` with no `await` inside. The
 *      object's input gate only covers storage operations, so a method that
 *      awaited between a read and a write would interleave with other calls;
 *      synchronous methods run to completion one after another.
 *   2. Storage failures are RETURNED (`storage_error`), never thrown across the
 *      RPC boundary: a throw inside the object is reported as an unhandled
 *      rejection by the runtime even when the caller handles it. The caller
 *      maps `storage_error` to a fail-closed 500.
 *
 * Every SQL statement binds its parameters with `?`; no value is ever
 * interpolated into SQL text.
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
  | { outcome: 'storage_error' };

export type RevokeResult = 'revoked' | 'unchanged' | 'absent' | 'storage_error';

export type StatusResult = Status | 'storage_error';

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
  binding_json: string;
  registered_at: number;
  revoked_at: number | null;
  history: HistoryEvent[];
}

export type GetResult =
  | { outcome: 'found'; record: CredentialRecord }
  | { outcome: 'absent' }
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

type CredentialRow = {
  credential_id: string;
  status: 'ACTIVE' | 'REVOKED';
  operator_key: string;
  binding_json: string;
  registered_at: number;
  revoked_at: number | null;
};

function logStorageError(operation: string, e: unknown): void {
  // SQLite messages name tables/columns, never row values.
  console.error(`registry storage error (${operation}):`, e instanceof Error ? e.message : String(e));
}

export class TenantRegistry extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Synchronous and idempotent: the schema exists before any request runs.
    this.ctx.storage.sql.exec(SCHEMA);
  }

  register(input: RegisterInput): RegisterResult {
    try {
      return this.ctx.storage.transactionSync((): RegisterResult => {
        if (input.expiry <= input.now) return { outcome: 'expired' };
        const existing = this.ctx.storage.sql
          .exec<Pick<CredentialRow, 'status' | 'registered_at'>>(
            'SELECT status, registered_at FROM credentials WHERE credential_id = ?',
            input.credential_id,
          )
          .toArray()[0];
        if (existing !== undefined) {
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
      logStorageError('register', e);
      return { outcome: 'storage_error' };
    }
  }

  status(credential_id: string): StatusResult {
    try {
      const row = this.ctx.storage.sql
        .exec<Pick<CredentialRow, 'status'>>('SELECT status FROM credentials WHERE credential_id = ?', credential_id)
        .toArray()[0];
      return row === undefined ? 'ABSENT' : row.status;
    } catch (e) {
      logStorageError('status', e);
      return 'storage_error';
    }
  }

  revoke(credential_id: string, now: number, request_id: string): RevokeResult {
    try {
      return this.ctx.storage.transactionSync((): RevokeResult => {
        const row = this.ctx.storage.sql
          .exec<Pick<CredentialRow, 'status'>>('SELECT status FROM credentials WHERE credential_id = ?', credential_id)
          .toArray()[0];
        if (row === undefined) return 'absent';
        if (row.status === 'REVOKED') return 'unchanged';
        this.ctx.storage.sql.exec(
          'UPDATE credentials SET status = ?, revoked_at = ? WHERE credential_id = ?',
          'REVOKED',
          now,
          credential_id,
        );
        this.ctx.storage.sql.exec(
          'INSERT INTO history (credential_id, event, ts, request_id) VALUES (?, ?, ?, ?)',
          credential_id,
          'revoked',
          now,
          request_id,
        );
        return 'revoked';
      });
    } catch (e) {
      logStorageError('revoke', e);
      return 'storage_error';
    }
  }

  get(credential_id: string): GetResult {
    try {
      const row = this.ctx.storage.sql
        .exec<CredentialRow>(
          'SELECT credential_id, status, operator_key, binding_json, registered_at, revoked_at FROM credentials WHERE credential_id = ?',
          credential_id,
        )
        .toArray()[0];
      if (row === undefined) return { outcome: 'absent' };
      const history = this.ctx.storage.sql
        .exec<HistoryEvent>(
          'SELECT event, ts, request_id FROM history WHERE credential_id = ? ORDER BY ts ASC, event ASC',
          credential_id,
        )
        .toArray()
        .map((h) => ({ event: h.event, ts: h.ts, request_id: h.request_id }));
      return { outcome: 'found', record: { ...row, history } };
    } catch (e) {
      logStorageError('get', e);
      return { outcome: 'storage_error' };
    }
  }
}
