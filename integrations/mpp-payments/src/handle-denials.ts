import { isBolyraDeniedError } from './errors';

/**
 * Wrap a route handler so a `BolyraDeniedError` thrown from `preflight`
 * becomes its Problem Details response. Any other error propagates unchanged.
 * (Denials thrown from `verify` are caught by mppx itself and re-issued as a
 * 402 challenge; they never reach this helper.)
 *
 * Variadic so it wraps handlers from any framework — Next App Router
 * `(req, { params })`, Workers `(req, env, ctx)`, Express
 * `(req, res, next)` — by forwarding every argument through. The wrapper is
 * an arrow function, so `this` is not forwarded; none of the listed
 * frameworks call route handlers with a meaningful `this`.
 */
export function handleDenials<Args extends unknown[], Res>(
  fn: (...args: Args) => Promise<Res>,
): (...args: Args) => Promise<Res | Response> {
  return async (...args: Args) => {
    try {
      return await fn(...args);
    } catch (err) {
      if (isBolyraDeniedError(err)) return err.response;
      throw err;
    }
  };
}
