/**
 * SD-JWT session token issuer.
 *
 * After verifyHandshake() succeeds, mint a compact SD-JWT token that binds
 * nullifierHash, scopeCommitment, agentId, and humanMerkleRoot. Subsequent
 * API calls present the token instead of re-proving (~1-5s savings per call).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHmac, randomBytes, createHash } from 'crypto';
import type { HandshakeResult, SessionTokenOptions, SessionTokenPayload } from './types.js';
import { SessionTokenInvalidError } from './errors.js';

const DEFAULT_TTL = 300;
const MIN_TTL = 60;
const MAX_TTL = 3600;
const DEFAULT_ISSUER = 'bolyra.ai';
const SD_ALG = 'sha-256';

const ALL_DISCLOSABLE: Array<keyof SessionTokenPayload> = [
  'nullifierHash',
  'scopeCommitment',
  'agentId',
  'humanMerkleRoot',
];

// ── SD-JWT Helpers ──────────────────────────────────────────────────────

function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function sha256(data: string): Buffer {
  return createHash('sha256').update(data).digest();
}

interface Disclosure {
  salt: string;
  claimName: string;
  claimValue: string;
  encoded: string;
  digest: string;
}

function createDisclosure(claimName: string, claimValue: string): Disclosure {
  const salt = base64url(randomBytes(16));
  const arr = JSON.stringify([salt, claimName, claimValue]);
  const encoded = base64url(Buffer.from(arr));
  const digest = base64url(sha256(encoded));
  return { salt, claimName, claimValue, encoded, digest };
}

function hmacSign(secret: Uint8Array, data: string): string {
  return base64url(createHmac('sha256', secret).update(data).digest());
}

function resolveKey(key: Uint8Array | string): Uint8Array {
  if (typeof key === 'string') return Buffer.from(key, 'hex');
  return key;
}

/**
 * Mints SD-JWT session tokens from verified handshake results.
 */
export class SessionTokenIssuer {
  /**
   * Mint an SD-JWT session token.
   *
   * @param handshakeResult - Output from verifyHandshake(). Must have `verified: true`.
   * @param opts - Signing key, TTL, issuer, selective disclosure config.
   * @returns SD-JWT compact serialization: `<jwt>~<disclosure1>~<disclosure2>~...~`
   */
  static mint(
    handshakeResult: HandshakeResult,
    opts: SessionTokenOptions,
  ): string {
    if (!handshakeResult.verified) {
      throw new SessionTokenInvalidError(
        'Cannot mint session token from unverified handshake',
      );
    }

    const ttl = opts.ttl ?? DEFAULT_TTL;
    if (ttl < MIN_TTL || ttl > MAX_TTL) {
      throw new SessionTokenInvalidError(
        `TTL must be between ${MIN_TTL}s and ${MAX_TTL}s, got ${ttl}s`,
      );
    }

    const secret = resolveKey(opts.signingKey);
    const discloseClaims = opts.selectiveDisclosureFields ?? ALL_DISCLOSABLE;
    const issuer = opts.issuer ?? DEFAULT_ISSUER;

    // Build claim values from handshake result
    const claimValues: Record<string, string> = {
      nullifierHash: '0x' + handshakeResult.humanProof.nullifierHash.toString(16),
      scopeCommitment: handshakeResult.scopeCommitment
        ? '0x' + handshakeResult.scopeCommitment.toString(16)
        : '0x0',
      agentId: handshakeResult.agentCredentialHash
        ? '0x' + handshakeResult.agentCredentialHash.toString(16)
        : '0x' + handshakeResult.agentProof.nullifierHash.toString(16),
      humanMerkleRoot:
        '0x' + handshakeResult.humanProof.humanMerkleRoot.toString(16),
    };

    // Create SD-JWT disclosures for selected claims
    const disclosures: Disclosure[] = [];
    for (const name of discloseClaims) {
      if (claimValues[name] !== undefined) {
        disclosures.push(createDisclosure(name, claimValues[name]));
      }
    }

    const now = Math.floor(Date.now() / 1000);

    // JWT payload with _sd digest array
    const payload: Record<string, unknown> = {
      iss: issuer,
      iat: now,
      exp: now + ttl,
      _sd_alg: SD_ALG,
      _sd: disclosures.map((d) => d.digest),
    };
    if (opts.audience) {
      payload.aud = opts.audience;
    }

    // header.payload.signature
    const header = { alg: 'HS256', typ: 'sd+jwt' };
    const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
    const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = hmacSign(secret, signingInput);
    const jwt = `${signingInput}.${signature}`;

    // SD-JWT compact: jwt~disc1~disc2~...~
    const disclosureParts = disclosures.map((d) => d.encoded).join('~');
    return `${jwt}~${disclosureParts}~`;
  }
}
