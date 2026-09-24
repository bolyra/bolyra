/**
 * The deadlines (constants, sentinel and race helpers) live here, outside the entry module, on purpose:
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

/**
 * A request body must finish arriving within this bound (both `/v1/verify` and
 * registration). The byte caps bound a fast body; this bounds a slow one — a client that
 * opens a request and trickles or stops sending would otherwise hold the invocation until
 * the runtime kills it, with no verdict and no analytics point. On expiry `/v1/verify`
 * answers the fail-closed 500 `internal_error` verdict ("request body stalled") and a
 * registration a 500 `internal_error`.
 */
export const BODY_READ_DEADLINE_MS = 5_000;

/** A deadline's own resolution value: a symbol no raced result can collide with. */
export const TIMEOUT = Symbol('deadline');

/**
 * Race `work` against `ms`. The timer is cleared as soon as either side settles; a late
 * rejection of the orphaned work is swallowed. A rejection that wins the race propagates
 * to the caller.
 */
export async function withDeadline<T>(work: Promise<T>, ms: number): Promise<T | typeof TIMEOUT> {
  work.catch(() => {}); // never an unhandled rejection after the deadline wins
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<typeof TIMEOUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMEOUT), ms);
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Race a registry read against `REGISTRY_DEADLINE_MS` (see `withDeadline`). Shared by the
 * verify path and `/health` so the two deadlines cannot drift.
 */
export function withRegistryDeadline<T>(read: Promise<T>): Promise<T | typeof TIMEOUT> {
  return withDeadline(read, REGISTRY_DEADLINE_MS);
}
