/**
 * @bolyra/ai — utility helpers.
 *
 * Proof bundle encoding/decoding, header construction, and nonce generation.
 * Mirrors patterns from @bolyra/mcp client.ts.
 */

import { randomBytes } from 'crypto';
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
    if (!base64) return null;
    const json = Buffer.from(base64, 'base64').toString('utf8');
    const parsed = JSON.parse(json);
    // Validate expected shape before returning
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof parsed.v !== 'number' ||
      !parsed.humanProof ||
      !parsed.agentProof ||
      !parsed.nonce ||
      !parsed.credentialCommitment
    ) {
      return null;
    }
    return parsed as BolyraProofBundle;
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
  const entropy = BigInt('0x' + randomBytes(8).toString('hex'));
  return (ts << 64n) | entropy;
}

/**
 * Build a dev-mode proof bundle (no circuit artifacts needed).
 * Shared by middleware.ts and tools.ts.
 */
export function buildDevBundle(
  credential: import('@bolyra/sdk').AgentCredential,
  nonce: bigint,
): BolyraProofBundle {
  const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
  const mockProofStrings = Array.from({ length: 8 }, () =>
    BigInt('0x' + randomBytes(4).toString('hex')).toString(),
  );

  return {
    v: 1,
    humanProof: {
      proof: mockProofStrings as unknown as import('@bolyra/sdk').Proof['proof'],
      publicSignals: ['0', '0', '0', '0', nonce.toString()],
    },
    agentProof: {
      proof: mockProofStrings as unknown as import('@bolyra/sdk').Proof['proof'],
      publicSignals: [
        '0',
        '0',
        credential.commitment.toString(),
        credential.permissionBitmask.toString(),
        currentTimestamp.toString(),
        nonce.toString(),
      ],
    },
    nonce: nonce.toString(),
    credentialCommitment: credential.commitment.toString(),
    _dev: true,
  };
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
