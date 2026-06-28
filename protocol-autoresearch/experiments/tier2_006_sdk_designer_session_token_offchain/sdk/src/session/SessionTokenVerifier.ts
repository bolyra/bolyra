/**
 * SD-JWT session token verifier.
 *
 * Verifies signature, expiry, disclosure integrity, and required claims.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHmac, createHash } from 'crypto';
import type { SessionTokenPayload, SessionVerifyOptions } from './types.js';
import {
  SessionTokenExpiredError,
  SessionTokenInvalidError,
  SessionTokenClaimMissingError,
} from './errors.js';

const DEFAULT_CLOCK_SKEW = 30;

function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(str: string): Buffer {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  return Buffer.from(s, 'base64');
}

function sha256(data: string): Buffer {
  return createHash('sha256').update(data).digest();
}

function hmacSign(secret: Uint8Array, data: string): string {
  return base64url(createHmac('sha256', secret).update(data).digest());
}

function resolveKey(key: Uint8Array | string): Uint8Array {
  if (typeof key === 'string') return Buffer.from(key, 'hex');
  return key;
}

/**
 * Verifies SD-JWT session tokens.
 */
export class SessionTokenVerifier {
  /**
   * Verify an SD-JWT session token.
   *
   * @param token - SD-JWT compact serialization.
   * @param opts - Verification key, required claims, clock skew tolerance.
   * @returns Decoded SessionTokenPayload with disclosed claims.
   * @throws SessionTokenInvalidError on malformed token or bad signature.
   * @throws SessionTokenExpiredError on expired token.
   * @throws SessionTokenClaimMissingError if a required claim is not disclosed.
   */
  static verify(
    token: string,
    opts: SessionVerifyOptions,
  ): SessionTokenPayload {
    const secret = resolveKey(opts.signingKey);

    // Split SD-JWT: jwt~disc1~disc2~...~ (trailing empty after last ~)
    const parts = token.split('~');
    const jwtPart = parts[0];
    const disclosureParts = parts.slice(1).filter((p) => p.length > 0);

    // Verify JWT structure
    const jwtSegments = jwtPart.split('.');
    if (jwtSegments.length !== 3) {
      throw new SessionTokenInvalidError('Malformed JWT: expected 3 dot-separated segments');
    }

    const [headerB64, payloadB64, signatureB64] = jwtSegments;

    // Verify HMAC signature
    const signingInput = `${headerB64}.${payloadB64}`;
    const expectedSig = hmacSign(secret, signingInput);
    if (expectedSig !== signatureB64) {
      throw new SessionTokenInvalidError('JWT signature verification failed');
    }

    const payload = JSON.parse(
      base64urlDecode(payloadB64).toString(),
    ) as Record<string, unknown>;

    // Check expiry with clock skew tolerance
    const now = Math.floor(Date.now() / 1000);
    const tolerance = opts.clockSkew ?? DEFAULT_CLOCK_SKEW;
    const exp = payload.exp as number;
    if (exp + tolerance <= now) {
      throw new SessionTokenExpiredError(
        `Session token expired at ${exp} (now: ${now}, tolerance: ${tolerance}s)`,
      );
    }

    // Verify disclosures against _sd digests
    const sdDigests = new Set(payload._sd as string[]);
    const claims: Record<string, string> = {};

    for (const disc of disclosureParts) {
      const digest = base64url(sha256(disc));
      if (!sdDigests.has(digest)) {
        throw new SessionTokenInvalidError(
          'Disclosure digest does not match any _sd entry',
        );
      }
      const decoded = JSON.parse(
        base64urlDecode(disc).toString(),
      ) as [string, string, string];
      const [, claimName, claimValue] = decoded;
      claims[claimName] = claimValue;
    }

    // Check required claims
    if (opts.requiredClaims) {
      for (const req of opts.requiredClaims) {
        if (!(req in claims)) {
          throw new SessionTokenClaimMissingError(req);
        }
      }
    }

    return {
      nullifierHash: claims.nullifierHash ?? '',
      scopeCommitment: claims.scopeCommitment ?? '',
      agentId: claims.agentId ?? '',
      humanMerkleRoot: claims.humanMerkleRoot ?? '',
      iat: payload.iat as number,
      exp,
      iss: payload.iss as string,
      aud: payload.aud as string | undefined,
    };
  }
}
