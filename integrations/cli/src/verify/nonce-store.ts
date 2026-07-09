/**
 * Replay protection for `bolyra verify` (spec §5.2, F3/F7).
 *
 * Two modes:
 *
 *   - **local** — {@link FileNonceStore}: a durable, file-backed replay store.
 *     Each seen nonce becomes a per-key file recording an expiry timestamp.
 *     Survives process restarts (unlike the in-memory reference store) so a
 *     proof cannot be replayed across CLI invocations within its TTL.
 *
 *   - **host** — {@link buildConsumeNonce}: the CLI does not persist anything
 *     itself; instead it emits a `consume_nonce` instruction telling the calling
 *     host to burn the one-time nonce in its own store.
 *
 * The store implements the `@bolyra/mcp` {@link NonceStore} contract
 * (`markIfFresh(key, ttlSeconds)`), so it is a drop-in replacement for the
 * in-memory `MemoryNonceStore` when a verifier wants durability.
 */

import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createHash, randomBytes } from 'crypto';

import type { NonceStore } from '@bolyra/mcp';

import type { ConsumeNonce } from './verdict';

/** Default base directory for the durable nonce store. */
const DEFAULT_BASE_DIR = path.join(os.homedir(), '.bolyra', 'nonces');

/** Extract a POSIX-style error code from an unknown thrown value, if any. */
function errorCode(err: unknown): string | undefined {
  if (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    typeof (err as { code: unknown }).code === 'string'
  ) {
    return (err as { code: string }).code;
  }
  return undefined;
}

/**
 * Durable, file-backed replay store for the local nonce mode.
 *
 * Each nonce key maps to a file named after its SHA-256 (filesystem-safe) whose
 * sole content is the entry's expiry as Unix milliseconds. Freshness is decided
 * by an *atomic* create:
 *
 *   1. Fully write the candidate expiry to a per-call temp file, then
 *      {@link fs.link} it into place. `link` is atomic and fails with `EEXIST`
 *      if the key file already exists — so the entry only ever becomes visible
 *      already carrying its full content (no empty-file window for a racing
 *      reader to misread as expired).
 *   2. If the key file already exists and is still live → replay → `false`.
 *   3. If it exists but is expired → reclaim it under an exclusive `.lock`
 *      (created with the `wx` flag) and atomically `rename` the fresh temp over
 *      it → `true`. Concurrent reclaimers lose the lock race and return `false`.
 *
 * Net effect: many simultaneous marks of the same fresh key yield exactly one
 * `true`.
 */
export class FileNonceStore implements NonceStore {
  private readonly baseDir: string;
  private dirReady = false;

  constructor(baseDir?: string) {
    this.baseDir = baseDir ?? DEFAULT_BASE_DIR;
  }

  async markIfFresh(key: string, ttlSeconds: number): Promise<boolean> {
    await this.ensureDir();
    await this.pruneExpired();

    const file = this.pathFor(key);
    const expiryMs = Date.now() + ttlSeconds * 1000;
    const tmp = `${file}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;

    // Fully materialize the entry in a temp file first, so it can appear
    // atomically (with content) via link/rename.
    await fs.writeFile(tmp, String(expiryMs), { flag: 'w' });

    try {
      // Atomic exclusive-create: succeeds only if the key was never seen.
      await fs.link(tmp, file);
      return true;
    } catch (err) {
      if (errorCode(err) !== 'EEXIST') {
        await this.safeRm(tmp);
        throw err;
      }
    }

    // Key file exists. If it is still live, this is a replay.
    const existing = await this.readExpiry(file);
    if (existing !== null && existing > Date.now()) {
      await this.safeRm(tmp);
      return false;
    }

    // Expired (or unreadable) — reclaim atomically under an exclusive lock so
    // exactly one concurrent reclaimer wins.
    const lock = `${file}.lock`;
    let lockAcquired = false;
    try {
      const lockFh = await fs.open(lock, 'wx');
      lockAcquired = true;
      await lockFh.close();
    } catch (err) {
      await this.safeRm(tmp);
      if (errorCode(err) === 'EEXIST') {
        // Another caller is reclaiming this key right now; they will win.
        return false;
      }
      throw err;
    }

    try {
      // Re-check under the lock in case a racer refreshed the entry.
      const recheck = await this.readExpiry(file);
      if (recheck !== null && recheck > Date.now()) {
        await this.safeRm(tmp);
        return false;
      }
      // Atomic replace — readers see either the old or the new content, never
      // a partial or absent file.
      await fs.rename(tmp, file);
      return true;
    } finally {
      if (lockAcquired) {
        await fs.rm(lock, { force: true });
      }
    }
  }

  /** Filesystem-safe per-key path derived from the key's SHA-256 digest. */
  private pathFor(key: string): string {
    const digest = createHash('sha256').update(key).digest('hex');
    return path.join(this.baseDir, digest);
  }

  private async ensureDir(): Promise<void> {
    if (this.dirReady) return;
    await fs.mkdir(this.baseDir, { recursive: true });
    this.dirReady = true;
  }

  /** Read an entry's expiry (Unix ms). Returns null if missing or unreadable. */
  private async readExpiry(file: string): Promise<number | null> {
    try {
      const raw = await fs.readFile(file, 'utf8');
      const value = Number(raw.trim());
      return Number.isFinite(value) ? value : null;
    } catch {
      return null;
    }
  }

  /** Unlink a path, swallowing "already gone" and other best-effort errors. */
  private async safeRm(target: string): Promise<void> {
    await fs.rm(target, { force: true }).catch(() => undefined);
  }

  /**
   * Best-effort prune of obviously-expired entries. Skips temp/lock scratch
   * files and any key currently being reclaimed (its `.lock` sibling exists),
   * and swallows all errors — pruning is an optimization, not a correctness
   * requirement (the reclaim path handles expired entries per-key anyway).
   */
  private async pruneExpired(): Promise<void> {
    let entries: string[];
    try {
      entries = await fs.readdir(this.baseDir);
    } catch {
      return;
    }
    const now = Date.now();
    const locked = new Set(
      entries
        .filter((name) => name.endsWith('.lock'))
        .map((name) => name.slice(0, -'.lock'.length)),
    );
    await Promise.all(
      entries.map(async (name) => {
        if (name.endsWith('.tmp') || name.endsWith('.lock')) return;
        if (locked.has(name)) return;
        const file = path.join(this.baseDir, name);
        const expiry = await this.readExpiry(file);
        if (expiry !== null && expiry <= now) {
          await this.safeRm(file);
        }
      }),
    );
  }
}

/**
 * Build a `consume_nonce` instruction for the host nonce mode (spec §5.2, F7).
 *
 * The verifier keys replay protection on the proof's `nullifierHash`; the host
 * is told to retain that burned nonce (scoped to `issuerKey`) until
 * `retainUntil` so the same proof cannot be replayed before then.
 */
export function buildConsumeNonce(
  nullifierHash: string,
  issuerKey: string,
  retainUntil: number,
): ConsumeNonce {
  return {
    issuer_key: issuerKey,
    nonce: nullifierHash,
    retain_until: retainUntil,
  };
}
