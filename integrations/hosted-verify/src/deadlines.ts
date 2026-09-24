/**
 * The registry deadline (constant, sentinel and race helper) lives here, outside the entry module, on purpose:
 * the Workers runtime accepts only handlers, classes and functions as exports of the
 * entry module and refuses to instantiate it otherwise — a rule the vitest pool does not
 * enforce. Keep every non-function value out of the entry module's *exports*; unexported
 * constants are fine where they are.
 */

/**
 * The registry read on the verify path is raced against this deadline. An
 * `AbortSignal` cannot cancel a Durable Object RPC, so the race is the only
 * bound; on expiry the verdict is the fail-closed 500 and the orphaned RPC's
 * eventual settlement is ignored.
 */
export const REGISTRY_DEADLINE_MS = 2_000;

/** The deadline's own resolution value: a symbol no registry status can collide with. */
export const TIMEOUT = Symbol('registry deadline');

/**
 * Race a registry read against `REGISTRY_DEADLINE_MS`. The timer is cleared as soon as
 * either side settles; a late rejection of the orphaned RPC is swallowed. A rejection
 * that wins the race propagates to the caller. Shared by the verify path and `/health`
 * so the two deadlines cannot drift.
 */
export async function withRegistryDeadline<T>(read: Promise<T>): Promise<T | typeof TIMEOUT> {
  read.catch(() => {}); // never an unhandled rejection after the deadline wins
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<typeof TIMEOUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMEOUT), REGISTRY_DEADLINE_MS);
  });
  try {
    return await Promise.race([read, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
