/**
 * Usage signals for bolyra.ai/playground.
 *
 * Sends ONLY a literal event name from a fixed allowlist, as a same-origin
 * `GET /e?v=1&ev=<name>` with no body, no cookies, no referrer, no IDs. Nothing
 * derived from user input (no content, sizes, counts, hashes, codes, reasons) is
 * ever sent. Each event is sent at most once per page load, with a hard cap per
 * page load; failures are swallowed and never retried. These are counts of first
 * occurrences per page load, read from CloudFront access logs
 * (tools/usage-report.mjs). They are not sessions, journeys, or people.
 */
export const EVENTS = Object.freeze([
  'interacted',
  'tab_verify', 'tab_simulate', 'tab_decode', 'tab_evc',
  'sample_verify', 'sample_simulate', 'sample_decode',
  'run_verify', 'run_simulate', 'run_decode',
  'verify_ok', 'verify_failed', 'verify_invalid',
  'simulate_ok', 'simulate_failed', 'simulate_invalid',
  'decode_ok', 'decode_invalid',
  'copy_clicked', 'export_clicked',
]);
const ALLOWED = new Set(EVENTS);
export const EVENT_CAP = 32;
export const BEACON_INIT = Object.freeze({ method: 'GET', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', keepalive: true, redirect: 'error' });
export const beaconUrl = (ev) => `/e?v=1&ev=${ev}`;

export function createTracker({ send, fetchImpl = globalThis.fetch, cap = EVENT_CAP, strict = false } = {}) {
  const transport = send ?? (typeof fetchImpl === 'function' ? (url, init) => fetchImpl(url, init) : () => undefined);
  const seen = new Set();
  let sent = 0;
  const emit = (ev) => {
    if (seen.has(ev) || sent >= cap) return;
    seen.add(ev); sent += 1;
    try { const p = transport(beaconUrl(ev), BEACON_INIT); if (p && typeof p.catch === 'function') p.catch(() => {}); } catch { /* never surface */ }
  };
  return {
    track(ev) {
      if (typeof ev !== 'string' || !ALLOWED.has(ev)) { if (strict) throw new Error(`not an allowlisted usage event: ${String(typeof ev === 'string' ? ev : typeof ev)}`); return; }
      if (ev !== 'interacted') emit('interacted');
      emit(ev);
    },
  };
}

/** The page's single tracker. */
const pageTracker = createTracker();
export const track = (ev) => pageTracker.track(ev);
