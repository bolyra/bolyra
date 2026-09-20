/**
 * The verify path's timing constant lives here, outside the entry module, on purpose:
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
