import type { ReceiptClaims, VerifyOptions, VerifyFailureReasonV01 } from "./types";
import { permImplies } from "./permissions";

/**
 * Returns null on pass, or a failure reason. Time-of-check is `now` (epoch seconds).
 *
 * Note on the return type: this internal helper emits the v0.1-style lowercase
 * `VerifyFailureReasonV01` literals (e.g. "expired", "audience_mismatch") — the
 * Task 13 v0.2 orchestrator (verify.ts) translates these into the canonical
 * UPPER_SNAKE_CASE `VerifyFailureReason` union when assembling its result. The
 * lowercase enum is kept here as the stable internal contract.
 */
export function checkIssuerClaims(
  claims: ReceiptClaims,
  opts: VerifyOptions,
  now: number,
): VerifyFailureReasonV01 | null {
  const skew = opts.clockSkewSeconds ?? 30;

  // <= matches jose's expiry boundary (exp + tolerance === now is expired) —
  // a strict < here would accept a receipt jose already considers expired
  // when the clock ticks between jwtVerify and this check.
  if (typeof claims.exp !== "number" || claims.exp + skew <= now) return "expired";
  if (typeof claims.iat === "number" && claims.iat - skew > now) return "not_yet_valid";

  if (claims.aud !== opts.audience) return "audience_mismatch";

  if (opts.expectedSubject && claims.sub !== opts.expectedSubject) return "agent_mismatch";
  if (opts.action && claims.act !== opts.action) return "action_mismatch";

  if (opts.perm && !permImplies(claims.perm, opts.perm)) return "permission_violation";

  if (typeof opts.amount === "number") {
    if (!claims.max) return "amount_exceeds_cap";
    if (claims.max.amount < opts.amount) return "amount_exceeds_cap";
    if (opts.currency && claims.max.currency !== opts.currency) return "currency_mismatch";
  }

  return null;
}
