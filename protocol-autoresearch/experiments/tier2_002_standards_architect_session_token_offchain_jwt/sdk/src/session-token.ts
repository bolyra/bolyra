/**
 * Bolyra JWT Session Token — issue and verify.
 *
 * After a single on-chain verifyHandshake(), the relayer mints a short-lived
 * JWT (ES256 or EdDSA) carrying the handshake's public signals. Subsequent
 * API calls present only this JWT, reducing per-call cost from ~200ms proof
 * verification to a single signature check (~0.5ms).
 *
 * @see spec/bolyra-session-token-jwt-01.md
 * @module session-token
 */

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type {
  HandshakeResult,
  SessionTokenOptions,
  VerifiedSessionClaims,
  BolyraJWTPayload,
  SessionTokenErrorCode,
} from './types/session-token.js';

export type { SessionTokenErrorCode };
export type {
  HandshakeResult,
  SessionTokenOptions,
  VerifiedSessionClaims,
  BolyraJWTPayload,
} from './types/session-token.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 300;
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 3600;
const MAX_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_ISSUER = 'did:bolyra:relayer';
const DEFAULT_CHAIN_ID = 84532; // Base Sepolia
const DEFAULT_VERIFIER = '0x0000000000000000000000000000000000000000';
const TOKEN_TYPE = 'bolyra+jwt';

const HEX32_RE = /^0x[0-9a-f]{64}$/;
const ETH_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

// ── Error ─────────────────────────────────────────────────────────────────────

export class BolyraSessionTokenError extends Error {
  constructor(
    public readonly code: SessionTokenErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BolyraSessionTokenError';
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function validateHex32(value: string, label: string): void {
  if (!HEX32_RE.test(value)) {
    throw new BolyraSessionTokenError(
      'INVALID_CLAIMS',
      `${label} must be a 0x-prefixed, 64-char lowercase hex string, got: ${value}`,
    );
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Mint a Bolyra session JWT from a verified handshake result.
 *
 * @param handshake - Output from verifyHandshake() with the four public signals.
 * @param signingKey - Private key (CryptoKey or KeyLike) for ES256 or EdDSA.
 * @param options - TTL, issuer, delegation chain, chain ID, and verifier address.
 * @returns Compact-serialized JWT string.
 * @throws {BolyraSessionTokenError} On invalid handshake or options.
 */
export async function issueSessionToken(
  handshake: HandshakeResult,
  signingKey: CryptoKey | Uint8Array,
  options: SessionTokenOptions = {},
): Promise<string> {
  if (!handshake.verified) {
    throw new BolyraSessionTokenError(
      'UNVERIFIED_HANDSHAKE',
      'Cannot issue session token for unverified handshake',
    );
  }

  // Validate hex32 fields
  validateHex32(handshake.humanNullifier, 'humanNullifier');
  validateHex32(handshake.agentNullifier, 'agentNullifier');
  validateHex32(handshake.sessionNonce, 'sessionNonce');
  validateHex32(handshake.scopeCommitment, 'scopeCommitment');

  // Validate TTL
  const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new BolyraSessionTokenError(
      'TTL_EXCEEDED',
      `TTL must be between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS} seconds, got: ${ttl}`,
    );
  }

  // Validate delegation chain entries
  const delegationChain = options.delegationChain ?? [];
  for (let i = 0; i < delegationChain.length; i++) {
    validateHex32(delegationChain[i], `delegationChain[${i}]`);
  }

  const alg = options.algorithm ?? 'ES256';
  if (alg !== 'ES256' && alg !== 'EdDSA') {
    throw new BolyraSessionTokenError(
      'INVALID_ALG',
      `Algorithm must be ES256 or EdDSA, got: ${alg}`,
    );
  }

  const chainId = options.chainId ?? DEFAULT_CHAIN_ID;
  const verifierContract = options.verifierContract ?? DEFAULT_VERIFIER;
  const issuer = options.issuer ?? DEFAULT_ISSUER;

  const jwt = await new SignJWT({
    humanNullifier: handshake.humanNullifier,
    agentNullifier: handshake.agentNullifier,
    sessionNonce: handshake.sessionNonce,
    scopeCommitment: handshake.scopeCommitment,
    delegationChain,
    chainId,
    verifierContract,
  } as unknown as JWTPayload)
    .setProtectedHeader({ alg, typ: TOKEN_TYPE })
    .setSubject(handshake.humanNullifier)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setIssuer(issuer)
    .sign(signingKey);

  return jwt;
}

/**
 * Verify and decode a Bolyra session JWT.
 *
 * @param token - Compact JWT string.
 * @param publicKey - Public key corresponding to the relayer's signing key.
 * @param expectedIssuer - If provided, issuer must match exactly.
 * @returns Verified session claims with remaining lifetime.
 * @throws {BolyraSessionTokenError} On invalid signature, expiry, or claims.
 */
export async function verifySessionToken(
  token: string,
  publicKey: CryptoKey | Uint8Array,
  expectedIssuer?: string,
): Promise<VerifiedSessionClaims> {
  let rawPayload: JWTPayload;
  let alg: string;

  try {
    const result = await jwtVerify(token, publicKey, {
      algorithms: ['ES256', 'EdDSA'],
      issuer: expectedIssuer,
      clockTolerance: MAX_CLOCK_SKEW_SECONDS,
    });
    rawPayload = result.payload;
    alg = result.protectedHeader.alg;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (
      message.includes('expired') ||
      message.includes('exp') ||
      message.includes('"exp" claim')
    ) {
      throw new BolyraSessionTokenError('TOKEN_EXPIRED', 'Session token has expired');
    }
    throw new BolyraSessionTokenError(
      'INVALID_SIGNATURE',
      `JWT verification failed: ${message}`,
    );
  }

  // Extract and validate required Bolyra claims
  const p = rawPayload as Record<string, unknown>;
  const requiredStrings = [
    'humanNullifier',
    'agentNullifier',
    'sessionNonce',
    'scopeCommitment',
    'verifierContract',
  ] as const;

  for (const key of requiredStrings) {
    if (typeof p[key] !== 'string') {
      throw new BolyraSessionTokenError(
        'MISSING_CLAIMS',
        `Required claim "${key}" missing or not a string`,
      );
    }
  }

  // Validate hex32 format
  for (const key of ['humanNullifier', 'agentNullifier', 'sessionNonce', 'scopeCommitment'] as const) {
    validateHex32(p[key] as string, key);
  }

  if (typeof p.chainId !== 'number' || !Number.isInteger(p.chainId) || (p.chainId as number) <= 0) {
    throw new BolyraSessionTokenError(
      'MISSING_CLAIMS',
      'Required claim "chainId" missing or not a positive integer',
    );
  }

  if (!Array.isArray(p.delegationChain)) {
    throw new BolyraSessionTokenError(
      'MISSING_CLAIMS',
      'Required claim "delegationChain" missing or not an array',
    );
  }

  for (let i = 0; i < (p.delegationChain as string[]).length; i++) {
    validateHex32((p.delegationChain as string[])[i], `delegationChain[${i}]`);
  }

  // sub must equal humanNullifier
  if (p.sub !== p.humanNullifier) {
    throw new BolyraSessionTokenError(
      'INVALID_CLAIMS',
      'sub claim must equal humanNullifier',
    );
  }

  // TTL guard: exp - iat must not exceed MAX_TTL
  const iat = p.iat as number;
  const exp = p.exp as number;
  if (exp - iat > MAX_TTL_SECONDS) {
    throw new BolyraSessionTokenError(
      'TTL_EXCEEDED',
      `Token TTL ${exp - iat}s exceeds maximum ${MAX_TTL_SECONDS}s`,
    );
  }

  // Future iat guard
  const now = nowSeconds();
  if (iat > now + MAX_CLOCK_SKEW_SECONDS) {
    throw new BolyraSessionTokenError(
      'FUTURE_IAT',
      `Token iat ${iat} is too far in the future (now: ${now})`,
    );
  }

  const payload: BolyraJWTPayload = {
    humanNullifier: p.humanNullifier as string,
    agentNullifier: p.agentNullifier as string,
    sessionNonce: p.sessionNonce as string,
    scopeCommitment: p.scopeCommitment as string,
    delegationChain: p.delegationChain as string[],
    chainId: p.chainId as number,
    verifierContract: p.verifierContract as string,
    iss: p.iss as string,
    sub: p.sub as string,
    iat,
    exp,
  };

  const remaining = Math.max(0, exp - now);

  return {
    payload,
    algorithm: alg as 'ES256' | 'EdDSA',
    active: remaining > 0,
    remainingSeconds: remaining,
  };
}
