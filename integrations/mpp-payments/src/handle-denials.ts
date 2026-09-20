import { isBolyraDeniedError } from './errors';

/**
 * Wrap a route handler so a `BolyraDeniedError` thrown from `preflight`
 * becomes its Problem Details response. Any other error propagates unchanged.
 * (Denials thrown from `verify` are caught by mppx itself and re-issued as a
 * 402 challenge; they never reach this helper.)
 *
 * FOR FRAMEWORKS THAT CONSUME A RETURNED `Response` ONLY — Fetch-style
 * handlers: Next App Router, Cloudflare Workers, Hono, Bun. The wrapper hands
 * the denial back as its return value and writes nothing itself. It does NOT
 * complete Node/Express-style handlers `(req, res, next)` that must write to
 * `res`: there a returned `Response` is discarded, nothing is written, `next`
 * is never called, and the denied request hangs. Use {@link sendDenial} in
 * those handlers instead.
 *
 * Variadic so every argument is forwarded through unchanged. The wrapper is
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

/**
 * The subset of a Node/Express response a denial needs. Express's `res` has
 * `status()`; plain `http.ServerResponse` has only the `statusCode` property —
 * both satisfy this. `headersSent` is honored when present.
 */
export interface DenialResponseWriter {
  status?(code: number): unknown;
  statusCode?: number;
  headersSent?: boolean;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}

/**
 * Write a `BolyraDeniedError` to a Node/Express-style response. Returns `true`
 * after writing the denial's status, `content-type`, and Problem Details body
 * (one `end` call). Returns `false` without touching `res` when `err` is not
 * a denial, or when `res.headersSent` is already true (the response is
 * committed; the caller decides what to do) — in both cases the caller
 * rethrows or calls `next(err)`. The body is read via `err.response.text()`
 * before any write, so a denial can be sent once per error instance.
 * Ending with a string lets Node set `Content-Length` but bypasses Express's
 * ETag/HEAD handling — acceptable for an error body.
 */
export async function sendDenial(err: unknown, res: DenialResponseWriter): Promise<boolean> {
  if (!isBolyraDeniedError(err)) return false;
  if (res.headersSent === true) return false;
  const body = await err.response.text();
  const code = err.response.status;
  if (typeof res.status === 'function') res.status(code);
  else res.statusCode = code;
  const contentType = err.response.headers.get('content-type');
  if (contentType !== null) res.setHeader('content-type', contentType);
  res.end(body);
  return true;
}
