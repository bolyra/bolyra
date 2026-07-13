/**
 * Fetch + validate a Receipt Signer Discovery v1 document for --signer-from
 * (spec/receipt-signer-discovery-v1.md). Every failure throws — callers MUST
 * treat a throw as verification failure (fail closed), never as "no signer
 * restriction". https-only, except loopback hosts for development.
 */
import { parseSignerDiscovery, acceptedSigners } from '@bolyra/receipts';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
const FETCH_TIMEOUT_MS = 10_000;

export async function fetchAcceptedSigners(rawUrl: string): Promise<Set<string>> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`--signer-from is not a valid URL: ${rawUrl}`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    throw new Error('--signer-from requires https (plain http is allowed only for loopback hosts)');
  }

  let res: Response;
  try {
    // redirect:'error' — following redirects would let an https URL land on
    // a plaintext or attacker-chosen origin AFTER the protocol check (spec:
    // consumers MUST NOT follow redirects).
    res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), redirect: 'error' });
  } catch (err) {
    throw new Error(
      `signer discovery fetch failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!res.ok) {
    throw new Error(`signer discovery fetch failed: HTTP ${res.status}`);
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new Error('signer discovery document is not valid JSON');
  }

  // parseSignerDiscovery throws SignerDiscoveryError on any schema violation.
  return acceptedSigners(parseSignerDiscovery(body));
}
