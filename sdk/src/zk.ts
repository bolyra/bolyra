/**
 * Lazy snarkjs loader — the ONLY place the SDK resolves snarkjs.
 *
 * snarkjs (and its native/WASM dependency chain: ffjavascript, wasmcurves,
 * web-worker) is a ZK-only cost. Classical "Core" paths — dev identities,
 * identity/credential creation, Poseidon/EdDSA helpers, proof envelopes —
 * must never pay its module-load cost, and must keep working in environments
 * where the native/WASM stack misbehaves or snarkjs cannot be resolved.
 *
 * Contract: importing the SDK entry never loads snarkjs; only Groth16
 * prove/verify calls do, via `loadSnarkjs()`. The dynamic import defers
 * resolution to the first ZK call and caches the in-flight promise. A failed
 * load clears the cache so a transient failure isn't sticky.
 *
 * Enforced by test/lazy-loading.test.ts.
 */

type SnarkjsModule = typeof import('snarkjs');

let cached: Promise<SnarkjsModule> | undefined;

/** Resolve snarkjs on first use (ZK paths only). Cached after first success. */
export function loadSnarkjs(): Promise<SnarkjsModule> {
  if (!cached) {
    cached = import('snarkjs');
    cached.catch(() => {
      cached = undefined;
    });
  }
  return cached;
}
