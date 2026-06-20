/**
 * @bolyra/ai — utility helpers.
 *
 * Proof bundle encoding/decoding, header construction, and nonce generation.
 * Mirrors patterns from @bolyra/mcp client.ts.
 */

import type { BolyraProofBundle } from '@bolyra/mcp';

/**
 * Encode a proof bundle to a base64 string suitable for an Authorization header.
 */
export function encodeBundle(bundle: BolyraProofBundle): string {
  return Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
}

/**
 * Decode a base64-encoded proof bundle from an Authorization header value.
 * Expects the format: "Bolyra <base64>"
 *
 * Returns null if the header is malformed or not a Bolyra auth header.
 */
export function decodeBundleFromHeader(authHeader: string): BolyraProofBundle | null {
  const prefix = 'Bolyra ';
  if (!authHeader.startsWith(prefix)) {
    return null;
  }
  try {
    const base64 = authHeader.slice(prefix.length);
    const json = Buffer.from(base64, 'base64').toString('utf8');
    return JSON.parse(json) as BolyraProofBundle;
  } catch {
    return null;
  }
}

/**
 * Build an Authorization header value from a proof bundle.
 */
export function buildAuthHeader(bundle: BolyraProofBundle): string {
  return `Bolyra ${encodeBundle(bundle)}`;
}

/**
 * Generate a fresh session nonce.
 * Layout: (unix_seconds << 64) | random_entropy
 * Matches the nonce layout expected by @bolyra/mcp verifier.
 */
export function generateNonce(): bigint {
  const ts = BigInt(Math.floor(Date.now() / 1000));
  const entropy = BigInt(Math.floor(Math.random() * 2 ** 48));
  return (ts << 64n) | entropy;
}

/**
 * Build X-Bolyra-* headers from a verification context.
 * Injected by server middleware on successful verification.
 */
export function buildBolyraHeaders(ctx: {
  did: string;
  permissionBitmask: bigint;
  score: number;
  chainDepth: number;
}): Record<string, string> {
  return {
    'X-Bolyra-DID': ctx.did,
    'X-Bolyra-Permissions': ctx.permissionBitmask.toString(2),
    'X-Bolyra-Score': ctx.score.toString(),
    'X-Bolyra-Chain-Depth': ctx.chainDepth.toString(),
  };
}
