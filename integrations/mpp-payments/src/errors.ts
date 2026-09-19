/**
 * Denials as control flow. mppx converts any non-402 `Response` returned from
 * a method `preflight` into an outer `{ status: 200, withReceipt }` result, so
 * a returned denial reaches the application as success and the protected
 * action runs before the denial is sent. A thrown `BolyraDeniedError` leaves
 * `await mppx.charge(...)(request)` by exception, so the statements after it
 * never execute.
 */
import type { DenyVerdict } from './types';

export class BolyraDeniedError extends Error {
  override readonly name = 'BolyraDeniedError' as const;
  constructor(
    /** The gate's verdict (EVC §9 code or the gate-local missing_authorization). */
    readonly verdict: DenyVerdict,
    /** RFC 9457 Problem Details — identical to the body the gate used to return. */
    readonly response: Response,
  ) {
    super(`@bolyra/mpp: authorization denied (${verdict.code}): ${verdict.message}`);
  }
}

/** Thrown synchronously by `bolyraGate()` for hook combinations it cannot keep fail-closed. */
export class BolyraGateConfigError extends Error {
  override readonly name = 'BolyraGateConfigError' as const;
}

/** `instanceof` plus a structural fallback: two hoisted copies of this package must still recognize each other's denials. */
export function isBolyraDeniedError(err: unknown): err is BolyraDeniedError {
  if (err instanceof BolyraDeniedError) return true;
  return (
    typeof err === 'object' && err !== null &&
    (err as { name?: unknown }).name === 'BolyraDeniedError' &&
    (err as { response?: unknown }).response instanceof Response &&
    typeof (err as { verdict?: { code?: unknown } }).verdict?.code === 'string'
  );
}
