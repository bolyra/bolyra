/**
 * Off-chain JWT session token from a verified Bolyra handshake.
 *
 * After a single on-chain verifyHandshake(), the verifier mints a short-lived
 * JWT (ES256 / P-256 ECDSA) binding the nullifierHash and scopeCommitment.
 * Subsequent calls present only the JWT — reducing per-call overhead from
 * ~200ms proof verification to a single ECDSA check (~0.5ms).
 *
 * @module session
 */

import { SignJWT, jwtVerify } from 'jose';

// ── Types ────────────────────────────────────────────────────────────────────

/** Subset of verifyHandshake() output needed for token minting. */
export interface VerifiedHandshakeProof {
  nullifierHash: string;
  scopeCommitment: string;
}

/** Options for handshakeToSessionToken(). */
export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 3600 (1 hour). */
  ttlSeconds?: number;
  /** JWT audience claim. Default: '*'. */
  audience?: string;
}

/** Decoded session token claims. */
export interface SessionTokenClaims {
  nullifier: string;
  scope: string;
  expiry: number;
}

export type SessionErrorCode =
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'MISSING_CLAIMS'
  | 'INVALID_TOKEN';

export class BolyraSessionError extends Error {
  constructor(public readonly code: SessionErrorCode, message: string) {
    super(message);
    this.name = 'BolyraSessionError';
  }
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 3600;
const ISSUER = 'bolyra';
const DEFAULT_AUDIENCE = '*';

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Mint a session JWT from a verified handshake proof.
 *
 * @param proof - Output from verifyHandshake() containing nullifierHash and scopeCommitment.
 * @param signingKey - An ES256 (P-256) private CryptoKey.
 * @param options - Optional TTL and audience overrides.
 * @returns Compact-serialized JWT string.
 */
export async function handshakeToSessionToken(
  proof: VerifiedHandshakeProof,
  signingKey: CryptoKey,
  options: SessionTokenOptions = {},
): Promise<string> {
  if (!proof.nullifierHash || !proof.scopeCommitment) {
    throw new BolyraSessionError(
      'INVALID_TOKEN',
      'Proof must contain nullifierHash and scopeCommitment',
    );
  }

  const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const audience = options.audience ?? DEFAULT_AUDIENCE;

  const jwt = await new SignJWT({
    sub: proof.nullifierHash,
    scope: proof.scopeCommitment,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setIssuer(ISSUER)
    .setAudience(audience)
    .sign(signingKey);

  return jwt;
}

/**
 * Verify and decode a Bolyra session JWT.
 *
 * @param jwt - The compact JWT string.
 * @param pubKey - The ES256 (P-256) public CryptoKey that corresponds to the signer.
 * @returns Decoded claims: nullifier, scope, and expiry.
 * @throws {BolyraSessionError} On invalid signature, expiry, or missing claims.
 */
export async function verifySessionToken(
  jwt: string,
  pubKey: CryptoKey,
): Promise<SessionTokenClaims> {
  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(jwt, pubKey, {
      issuer: ISSUER,
      algorithms: ['ES256'],
    });
    payload = result.payload as Record<string, unknown>;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('expired') || message.includes('exp')) {
      throw new BolyraSessionError('TOKEN_EXPIRED', 'Session token has expired');
    }
    throw new BolyraSessionError('INVALID_SIGNATURE', `JWT verification failed: ${message}`);
  }

  const nullifier = payload.sub;
  const scope = payload.scope;
  const expiry = payload.exp;

  if (typeof nullifier !== 'string' || typeof scope !== 'string' || typeof expiry !== 'number') {
    throw new BolyraSessionError(
      'MISSING_CLAIMS',
      'Required claims (sub, scope, exp) missing or invalid',
    );
  }

  return { nullifier, scope, expiry };
}
