/**
 * NonceStore: replay protection, bounded retention, bounded memory.
 *
 * The retention and capacity behaviour here is the fix for the reviewed defect
 * where `evict()` walked the entire retained map on every `reserve()` while
 * `retain_until` was the credential expiry (every shipped fixture used
 * 2100-01-01), so nothing was ever evicted and reservation cost grew with the
 * store. The sustained-arrival test below is the one that fails on the old
 * implementation; consecutive-handshake tests never did.
 */

import {
  NonceStore,
  NonceStoreCapacityError,
  NonceRetentionTooLongError,
  MAX_NONCE_RETENTION_SECONDS,
  DEFAULT_MAX_ENTRIES,
} from '../src/nonces';
import type { ConsumeNonce } from '../src/types';

const NOW = 1_700_000_000;
const YEAR_2100 = 4_102_444_800;

function entry(nonce: string, retainUntil = NOW + 3600): ConsumeNonce {
  return { issuer_key: 'iss', nonce, retain_until: retainUntil };
}

describe('NonceStore — replay protection', () => {
  test('a fresh entry reserves, the same entry replays', () => {
    const store = new NonceStore();
    expect(store.reserve([entry('a')], NOW)).toBe(true);
    expect(store.reserve([entry('a')], NOW)).toBe(false);
  });

  test('reservation is atomic: a conflict records nothing new', () => {
    const store = new NonceStore();
    expect(store.reserve([entry('a')], NOW)).toBe(true);
    expect(store.reserve([entry('a'), entry('b')], NOW)).toBe(false);
    // 'b' must NOT have been recorded by the failed batch.
    expect(store.reserve([entry('b')], NOW)).toBe(true);
  });

  test('entries are namespaced by issuer key', () => {
    const store = new NonceStore();
    expect(store.reserve([{ issuer_key: 'x', nonce: 'n', retain_until: NOW + 60 }], NOW)).toBe(true);
    expect(store.reserve([{ issuer_key: 'y', nonce: 'n', retain_until: NOW + 60 }], NOW)).toBe(true);
  });

  // Regression: the key separator must not be a printable character. With a
  // space, ("a", "b c") and ("a b", "c") collide onto one key, so a fresh
  // presentation reports as replayed (or a replay reports as fresh). Both
  // halves are attacker-influenced, so this is a real collision vector.
  test('distinct (issuer, nonce) pairs that would collide on a space stay distinct', () => {
    const store = new NonceStore();
    expect(store.reserve([{ issuer_key: 'a', nonce: 'b c', retain_until: NOW + 60 }], NOW)).toBe(
      true,
    );
    expect(store.reserve([{ issuer_key: 'a b', nonce: 'c', retain_until: NOW + 60 }], NOW)).toBe(
      true,
    );
    expect(store.size).toBe(2);
  });

  test('a reservation whose retention has elapsed no longer blocks', () => {
    const store = new NonceStore();
    expect(store.reserve([entry('a', NOW + 10)], NOW)).toBe(true);
    expect(store.reserve([entry('a', NOW + 10)], NOW + 5)).toBe(false);
    expect(store.reserve([entry('a', NOW + 10)], NOW + 11)).toBe(true);
  });

  test('a still-live reservation blocks even when the sweep has not run', () => {
    // Correctness must not depend on eviction keeping up: fill the store with
    // entries the sweep budget cannot cover in one call, then replay an old one.
    const store = new NonceStore();
    store.reserve([entry('target', NOW + 86_400)], NOW);
    for (let i = 0; i < 500; i += 1) store.reserve([entry(`filler-${i}`, NOW + 86_400)], NOW);
    expect(store.reserve([entry('target', NOW + 86_400)], NOW + 1)).toBe(false);
  });
});

describe('NonceStore — retention is honoured, never silently shortened', () => {
  // EVC 3.2: the host MUST retain until the stated retain_until. Quietly
  // retaining for less would surface as a replay being accepted.
  test('honours a century-long retain_until rather than truncating it', () => {
    const store = new NonceStore();
    store.reserve([entry('a', YEAR_2100)], NOW);
    expect(store.reserve([entry('a', YEAR_2100)], NOW + MAX_NONCE_RETENTION_SECONDS + 1)).toBe(
      false,
    );
  });

  test('refuses retention beyond maxRetentionSeconds instead of shortening it', () => {
    const store = new NonceStore({ maxRetentionSeconds: MAX_NONCE_RETENTION_SECONDS });
    expect(() => store.reserve([entry('a', YEAR_2100)], NOW)).toThrow(NonceRetentionTooLongError);
    // Nothing was recorded by the refused call.
    expect(store.size).toBe(0);
  });

  test('the refusal names the cause and the fix', () => {
    const store = new NonceStore({ maxRetentionSeconds: 60 });
    expect(() => store.reserve([entry('a', NOW + 3600)], NOW)).toThrow(
      /NOT authorized.*Cause:.*Fix:/s,
    );
  });

  test('a requirement inside the limit is accepted', () => {
    const store = new NonceStore({ maxRetentionSeconds: MAX_NONCE_RETENTION_SECONDS });
    expect(store.reserve([entry('a', NOW + 60)], NOW)).toBe(true);
  });

  test('the retention bound Bolyra verifiers emit is 30 days', () => {
    expect(MAX_NONCE_RETENTION_SECONDS).toBe(30 * 86_400);
  });

  test('a shorter retain_until is honoured as-is, not extended', () => {
    const store = new NonceStore();
    store.reserve([entry('a', NOW + 60)], NOW);
    expect(store.reserve([entry('a', NOW + 60)], NOW + 61)).toBe(true);
  });
});

describe('NonceStore — bounded memory', () => {
  test('sustained arrivals of bounded reservations do not grow without bound', () => {
    // With verifiers clamping retain_until (what 0.6.0 ships), entries age out
    // and the cursor reclaims them as the clock advances.
    const store = new NonceStore();
    const step = 3600;
    for (let i = 0; i < 400; i += 1) {
      store.reserve([entry(`n-${i}`, NOW + i * step + 60)], NOW + i * step);
    }
    expect(store.size).toBeLessThan(400);
  });

  // Regression: a front-anchored sweep restarts every call, so long-lived
  // entries at the front hide every expired entry behind them forever.
  test('the sweep advances past long-lived entries to reclaim expired ones', () => {
    const store = new NonceStore();
    for (let i = 0; i < 64; i += 1) store.reserve([entry(`live-${i}`, YEAR_2100)], NOW);
    for (let i = 0; i < 300; i += 1) store.reserve([entry(`dead-${i}`, NOW + 10)], NOW);
    const before = store.size;
    // Drive sweeps with an unrelated key, well past the short retention.
    for (let i = 0; i < 20; i += 1) store.reserve([entry(`drive-${i}`, NOW + 20)], NOW + 100);
    expect(store.size).toBeLessThan(before);
  });

  // Regression: a full rescan on every rejected reservation at capacity is
  // attacker-triggerable unbounded work (the capacity path is reached by
  // UNPAID discovery requests). Count actual entries VISITED by full sweeps,
  // not iterator creations: sweepAll iterates the map, so instrumenting only
  // `.entries()` misses a `for...of`, which goes through `[Symbol.iterator]`.
  function countSweepVisits(store: NonceStore): () => number {
    const reserved = (store as unknown as { reserved: Map<string, number> }).reserved;
    let visits = 0;
    const wrap = (real: () => IterableIterator<[string, number]>) =>
      function (this: Map<string, number>) {
        const it = real.call(this);
        return {
          [Symbol.iterator]() {
            return this;
          },
          next() {
            const r = it.next();
            if (r.done !== true) visits += 1;
            return r;
          },
        } as IterableIterator<[string, number]>;
      };
    reserved.entries = wrap(Map.prototype.entries) as typeof reserved.entries;
    (reserved as unknown as Record<symbol, unknown>)[Symbol.iterator] = wrap(
      Map.prototype[Symbol.iterator],
    );
    return () => visits;
  }

  test('repeated refusals at capacity do not rescan the store each time', () => {
    const store = new NonceStore({ maxEntries: 200 });
    for (let i = 0; i < 200; i += 1) store.reserve([entry(`live-${i}`, YEAR_2100)], NOW);
    const visits = countSweepVisits(store);
    for (let i = 0; i < 25; i += 1) {
      expect(() => store.reserve([entry(`new-${i}`, NOW + 60)], NOW)).toThrow(
        NonceStoreCapacityError,
      );
    }
    // Budget arithmetic: each reserve() also runs the amortized sweep, capped
    // at SWEEP_BUDGET (64), so 25 calls cost at most 1,600 there, plus ONE full
    // pass of 200 = 1,800. Without the guard every refusal rescans: 1,600 +
    // 25 x 200 = 6,600. The bound below separates the two.
    expect(visits()).toBeLessThanOrEqual(2_500);
  });

  // The gate samples its clock before awaiting the verifier, so concurrent
  // requests reach reserve() with interleaved instants. An equality-based
  // guard rescans on every transition; a high-water mark does not.
  test('interleaved timestamps do not re-trigger full sweeps', () => {
    const store = new NonceStore({ maxEntries: 200 });
    for (let i = 0; i < 200; i += 1) store.reserve([entry(`live-${i}`, YEAR_2100)], NOW);
    const visits = countSweepVisits(store);
    for (let i = 0; i < 25; i += 1) {
      const clock = NOW + (i % 2); // t, t+1, t, t+1, ...
      expect(() => store.reserve([entry(`new-${i}`, clock + 60)], clock)).toThrow(
        NonceStoreCapacityError,
      );
    }
    // With a high-water mark, two distinct instants allow at most two full
    // passes: 1,600 + 400 = 2,000. With an equality check every transition
    // rescans: 1,600 + 25 x 200 = 6,600.
    expect(visits()).toBeLessThanOrEqual(2_500);
  });

  test('refuses new reservations at capacity instead of evicting live ones', () => {
    const store = new NonceStore({ maxEntries: 3 });
    expect(store.reserve([entry('a')], NOW)).toBe(true);
    expect(store.reserve([entry('b')], NOW)).toBe(true);
    expect(store.reserve([entry('c')], NOW)).toBe(true);
    expect(() => store.reserve([entry('d')], NOW)).toThrow(NonceStoreCapacityError);
    // The live reservations survived the refusal — that is the whole point.
    expect(store.reserve([entry('a')], NOW)).toBe(false);
  });

  test('capacity refusal names the cause and the fix', () => {
    const store = new NonceStore({ maxEntries: 1 });
    store.reserve([entry('a')], NOW);
    expect(() => store.reserve([entry('b')], NOW)).toThrow(
      /at capacity.*NOT authorized.*Cause:.*Fix:/s,
    );
  });

  test('capacity frees up once retention elapses', () => {
    const store = new NonceStore({ maxEntries: 1 });
    store.reserve([entry('a', NOW + 10)], NOW);
    expect(() => store.reserve([entry('b', NOW + 10)], NOW)).toThrow(NonceStoreCapacityError);
    expect(store.reserve([entry('b', NOW + 10)], NOW + 11)).toBe(true);
  });

  test('the default ceiling is a real bound, not Infinity', () => {
    expect(Number.isFinite(DEFAULT_MAX_ENTRIES)).toBe(true);
    expect(DEFAULT_MAX_ENTRIES).toBeGreaterThan(0);
  });

  test('re-reserving an elapsed key does not double-count against capacity', () => {
    const store = new NonceStore({ maxEntries: 1 });
    store.reserve([entry('a', NOW + 10)], NOW);
    expect(store.reserve([entry('a', NOW + 10)], NOW + 11)).toBe(true);
    expect(store.size).toBe(1);
  });
});
