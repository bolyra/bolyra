/**
 * Off-chain session token (JWT) after on-chain handshake verification.
 *
 * Uses EdDSA (Ed25519) via the `jose` library. After a single on-chain
 * verifyHandshake(), the verifier mints a short-lived JWT binding the
 * nullifierHash, scopeCommitment, and sessionNonce. Subsequent calls
 * present only the JWT — reducing per-call overhead to a signature check.
 */

import { SignJWT, jwtVerify, importJWK, type JWK } from 'jose';

// ── Types ──────────────────────────────────────────────────────────────────

export interface SessionClaims {
  nullifierHash: string;
  scopeCommitment: string;
  sessionNonce: string;
  iat: number;
  exp: number;
}

export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 300 (5 minutes). */
  ttlSeconds?: number;
  /** JWT issuer claim. Default: 'bolyra.ai'. */
  issuer?: string;
}

export interface HandshakeVerifyResult {
  valid: boolean;
  nullifierHash: string;
  scopeCommitment: string;
  sessionNonce: string;
}

export type SessionErrorCode =
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'CLAIMS_TAMPERED'
  | 'INVALID_TOKEN';

export class BolyraSessionError extends Error {
  constructor(public readonly code: SessionErrorCode, message: string) {
    super(message);
    this.name = 'BolyraSessionError';
  }
}

// ── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 300;
const MIN_TTL_SECONDS = 60;
const MAX_TTL_SECONDS = 900;
const DEFAULT_ISSUER = 'bolyra.ai';

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Mint a session token after a successful verifyHandshake().
 *
 * @param verifyResult - The result from verifyHandshake() containing
 *   nullifierHash, scopeCommitment, and sessionNonce.
 * @param signerKey - An Ed25519 private key in JWK format.
 * @param options - Optional TTL and issuer overrides.
 * @returns A signed JWT string.
 */
export async function mintSessionToken(
  verifyResult: HandshakeVerifyResult,
  signerKey: JWK,
  options: SessionTokenOptions = {},
): Promise<string> {
  if (!verifyResult.valid) {
    throw new BolyraSessionError(
      'INVALID_TOKEN',
      'Cannot mint session token from invalid handshake result',
    );
  }

  const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new BolyraSessionError(
      'INVALID_TOKEN',
      `TTL must be between ${MIN_TTL_SECONDS}s and ${MAX_TTL_SECONDS}s, got ${ttl}s`,
    );
  }

  const issuer = options.issuer ?? DEFAULT_ISSUER;
  const privateKey = await importJWK(signerKey, 'EdDSA');

  const jwt = await new SignJWT({
    nullifierHash: verifyResult.nullifierHash,
    scopeCommitment: verifyResult.scopeCommitment,
    sessionNonce: verifyResult.sessionNonce,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setIssuer(issuer)
    .sign(privateKey);

  return jwt;
}

/**
 * Verify a session token off-chain.
 *
 * @param token - The JWT string to verify.
 * @param publicKey - An Ed25519 public key in JWK format.
 * @param expectedIssuer - Expected issuer. Default: 'bolyra.ai'.
 * @returns Decoded SessionClaims on success.
 * @throws BolyraSessionError on invalid signature, expiry, or tampering.
 */
export async function verifySessionToken(
  token: string,
  publicKey: JWK,
  expectedIssuer: string = DEFAULT_ISSUER,
): Promise<SessionClaims> {
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(publicKey, 'EdDSA');
    const result = await jwtVerify(token, key, {
      issuer: expectedIssuer,
      algorithms: ['EdDSA'],
    });
    payload = result.payload as Record<string, unknown>;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('expired') || message.includes('exp')) {
      throw new BolyraSessionError('TOKEN_EXPIRED', 'Session token has expired');
    }
    throw new BolyraSessionError('INVALID_SIGNATURE', `JWT verification failed: ${message}`);
  }

  const nullifierHash = payload.nullifierHash;
  const scopeCommitment = payload.scopeCommitment;
  const sessionNonce = payload.sessionNonce;

  if (
    typeof nullifierHash !== 'string' ||
    typeof scopeCommitment !== 'string' ||
    typeof sessionNonce !== 'string'
  ) {
    throw new BolyraSessionError(
      'CLAIMS_TAMPERED',
      'Required claims (nullifierHash, scopeCommitment, sessionNonce) missing or invalid',
    );
  }

  return {
    nullifierHash,
    scopeCommitment,
    sessionNonce,
    iat: payload.iat as number,
    exp: payload.exp as number,
  };
}
