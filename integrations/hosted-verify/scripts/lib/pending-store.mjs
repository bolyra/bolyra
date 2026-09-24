/**
 * The canary pending store: a directory (default ~/.bolyra/canary-pending-<env>/) holding
 * one file per unresolved canary, `<credential_id>.pending`, whose content is the line
 * `<iso-time> <env> <org> <credential_id> pending`.
 *
 * A record is created with one exclusive create (`wx`: an existing id is refused, never
 * overwritten) and removed with one unlink. Nothing ever reads and rewrites shared state, so
 * concurrent verify-deploy runs cannot overwrite or lose each other's entries, and an
 * interrupted run leaves at most its own record behind. Manual cleanup: `ls` the directory,
 * resolve each id (pilot/RUNBOOK.md §7), delete its file.
 */
import { mkdirSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const ID = /^[0-9a-f]{64}$/;

function fileFor(dir, id) {
  if (typeof id !== 'string' || !ID.test(id)) throw new TypeError('pending store: credential id must be 64 lowercase hex');
  return path.join(dir, `${id}.pending`);
}

/** @param {string} dir */
export function pendingStore(dir) {
  return {
    /** Atomically create the record; throws EEXIST if the id already has one. */
    append(id, line) {
      const file = fileFor(dir, id);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(file, `${line}\n`, { flag: 'wx', mode: 0o600 });
    },
    /** Remove the record; a missing record (or directory) is a no-op. */
    remove(id) {
      const file = fileFor(dir, id);
      try {
        unlinkSync(file);
      } catch (e) {
        if (e?.code !== 'ENOENT') throw e;
      }
    },
  };
}
