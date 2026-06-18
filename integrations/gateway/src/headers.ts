/**
 * @bolyra/gateway — header injection.
 *
 * Builds X-Bolyra-* headers from a BolyraAuthContext for injection into
 * proxied requests. Optionally signs all X-Bolyra-* headers with HMAC-SHA256
 * so the upstream can verify they were set by the gateway.
 */

import type { BolyraAuthContext } from '@bolyra/mcp';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

/** Header name constants. */
const HEADER_PREFIX = 'X-Bolyra-';
const HEADER_VERIFIED = `${HEADER_PREFIX}Verified`;
const HEADER_DID = `${HEADER_PREFIX}DID`;
const HEADER_SCORE = `${HEADER_PREFIX}Score`;
const HEADER_PERMISSIONS = `${HEADER_PREFIX}Permissions`;
const HEADER_CHAIN_DEPTH = `${HEADER_PREFIX}Chain-Depth`;
const HEADER_RECEIPT_ID = `${HEADER_PREFIX}Receipt-ID`;
const HEADER_HMAC = `${HEADER_PREFIX}HMAC`;

/**
 * Build X-Bolyra-* headers from a verified auth context.
 * Does NOT include the HMAC header — call computeHmac separately if needed.
 */
export function injectBolyraHeaders(
  authCtx: BolyraAuthContext,
  receiptId?: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    [HEADER_VERIFIED]: 'true',
    [HEADER_DID]: authCtx.did,
    [HEADER_SCORE]: String(authCtx.score),
    [HEADER_PERMISSIONS]: authCtx.permissionBitmask.toString(),
    [HEADER_CHAIN_DEPTH]: String(authCtx.chainDepth),
  };

  if (receiptId) {
    headers[HEADER_RECEIPT_ID] = receiptId;
  }

  return headers;
}

/**
 * Compute HMAC-SHA256 over sorted X-Bolyra-* header key=value pairs.
 * The HMAC header itself is excluded from the computation.
 *
 * @param headers - X-Bolyra-* headers (output of injectBolyraHeaders)
 * @param secret - Shared secret as hex string
 * @returns Hex-encoded HMAC
 */
export function computeHmac(
  headers: Record<string, string>,
  secret: string,
): string {
  const sortedPairs = Object.entries(headers)
    .filter(([key]) => key.startsWith(HEADER_PREFIX) && key !== HEADER_HMAC)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretBytes = hexToBytes(secret);
  const mac = hmac(sha256, secretBytes, new TextEncoder().encode(sortedPairs));
  return bytesToHex(mac);
}

/**
 * Verify an HMAC signature on X-Bolyra-* headers.
 *
 * @param headers - All headers including X-Bolyra-HMAC
 * @param secret - Shared secret as hex string
 * @param hmacValue - The HMAC value to verify
 * @returns true if HMAC is valid
 */
export function verifyHmac(
  headers: Record<string, string>,
  secret: string,
  hmacValue: string,
): boolean {
  const expected = computeHmac(headers, secret);
  // Constant-time comparison
  if (expected.length !== hmacValue.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ hmacValue.charCodeAt(i);
  }
  return diff === 0;
}

/** Convert hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
