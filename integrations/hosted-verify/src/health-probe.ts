/**
 * `/health`'s registry liveness probe. Outside the entry module on purpose: it keeps
 * module-scope state and a test-only reset (see src/deadlines.ts on entry-module exports).
 */
import type { TenantRegistry } from './registry';
import { TIMEOUT, withRegistryDeadline } from './deadlines';

/**
 * The object `/health` probes. It can never be a tenant's registry: `ORG_ID_PATTERN`
 * (src/tenants.ts) forbids `_`, so no configured org id can name it (worker.spec.ts pins this).
 */
const HEALTH_PROBE_ID = '__health__';
/** A well-formed credential id that is never registered: the probe reads, and expects ABSENT. */
const HEALTH_PROBE_CREDENTIAL = '0'.repeat(64);

export type RegistryHealth = 'ok' | 'unavailable' | 'timeout';

/**
 * One status read of a constant id on the constant `HEALTH_PROBE_ID` object, under the
 * verify path's deadline. Liveness only — `registry_enforced` stays the build marker,
 * since a live object is not proof of enforcement.
 */
export async function probeRegistry(ns: DurableObjectNamespace<TenantRegistry>): Promise<RegistryHealth> {
  try {
    const outcome = await withRegistryDeadline(ns.get(ns.idFromName(HEALTH_PROBE_ID)).status(HEALTH_PROBE_CREDENTIAL));
    if (outcome === TIMEOUT) return 'timeout';
    switch (outcome) {
      case 'ABSENT':
      case 'ACTIVE':
      case 'REVOKED':
        return 'ok';
      case 'invalid_input':
      case 'storage_error':
        return 'unavailable';
    }
    return 'unavailable'; // a status the declared union does not name
  } catch {
    return 'unavailable';
  }
}

/** How long one isolate reuses a HEALTHY probe result. */
const HEALTH_PROBE_TTL_MS = 10_000;

/** The in-flight or recent probe of this isolate (module scope = one per isolate). */
let cached: { at: number; result: Promise<RegistryHealth> } | undefined;

/**
 * `/health` is unauthenticated and every probe lands on the ONE shared `__health__`
 * object, so probes are single-flight per isolate and a healthy result is reused for
 * `HEALTH_PROBE_TTL_MS`. While the registry is HEALTHY, a flood therefore reaches the
 * object with at most one RPC per isolate per 10 s, and the signal may be up to 10 s stale.
 * That bound does not hold while it is FAILING: a failed result (`unavailable` / `timeout`,
 * or a rejection) is dropped as soon as it settles, so each /health call may probe again,
 * and an RPC that hit the deadline stays outstanding until it settles.
 */
export function cachedProbeRegistry(
  ns: DurableObjectNamespace<TenantRegistry>,
  probe: (ns: DurableObjectNamespace<TenantRegistry>) => Promise<RegistryHealth> = probeRegistry, // injectable for tests only
): Promise<RegistryHealth> {
  const now = Date.now();
  if (cached !== undefined && now - cached.at < HEALTH_PROBE_TTL_MS) return cached.result;
  const entry = { at: now, result: probe(ns) };
  cached = entry;
  // Registered before any caller awaits `result`, so a failure is evicted before it is reported.
  // A rejection (probeRegistry catches today; a future probe might not) is evicted too.
  void entry.result.then(
    (r) => {
      if (r !== 'ok' && cached === entry) cached = undefined;
    },
    () => {
      if (cached === entry) cached = undefined;
    },
  );
  return entry.result;
}

/** Test-only: forget any cached probe result. */
export function resetHealthProbeCache(): void {
  cached = undefined;
}
