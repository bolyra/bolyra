/**
 * Bolyra Off-Chain Session Token (JWT)
 *
 * After a single on-chain verifyHandshake(), the relayer mints a short-lived
 * ES256 JWT carrying the handshake's public signals. Subsequent API calls
 * present only this JWT, reducing per-call cost from ~200ms proof verification
 * to a single ECDSA signature check (~0.5ms).
 *
 * @see spec/draft-bolyra-mutual-zkp-auth-01.md Section 7
 * @module sessionToken
 */

import { SignJWT, jwtVerify, type JWTPayload, type JWTHeaderParameters } from 'jose';
import { randomUUID } from 'crypto';

// ── Types ────────────────────────────────────────────────────────────────────

/** Claims extracted from a verified Bolyra session JWT. */
export interface SessionTokenClaims {
  /** Issuer — registry contract address. */
  iss: string;
  /** Subject — nullifierHash from HumanUniqueness circuit (hex32). */
  sub: string;
  /** scopeCommitment encoded as base64url. */
  scope: string;
  /** sessionNonce from the handshake (hex32). */
  nonce: string;
  /** Expiration timestamp (Unix seconds). */
  exp: number;
  /** Issued-at timestamp (Unix seconds). */
  iat: number;
  /** UUID v4 for replay prevention. */
  jti: string;
  /** humanMerkleRoot from the proof (hex32). */
  bolyra_root: string;
  /** Registry address from the header. */
  registry: string;
  /** Chain ID from the header. */
  chainId: number;
}

/** ES256 key material accepted by jose. */
export type RelayerKey = CryptoKey | Uint8Array;

/** Result shape from verifyHandshake(). */
export interface HandshakeResult {
  nullifierHash: string;
  scopeCommitment: string;
  sessionNonce: string;
  registryAddress: string;
  humanMerkleRoot: string;
  verified: boolean;
}

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 900; // 15 minutes
const MIN_TTL_SECONDS = 60;
const MAX_TTL_SECONDS = 3600;
const MAX_CLOCK_SKEW_SECONDS = 60;
const ALG = 'ES256';

const HEX32_RE = /^0x[0-9a-f]{64}$/;

// ── Error ────────────────────────────────────────────────────────────────────

export type SessionTokenErrorCode =
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'MISSING_CLAIMS'
  | 'INVALID_CLAIMS'
  | 'TTL_EXCEEDED'
  | 'FUTURE_IAT'
  | 'UNVERIFIED_HANDSHAKE'
  | 'REGISTRY_MISMATCH'
  | 'CHAIN_ID_MISMATCH';

export class SessionTokenError extends Error {
  constructor(
    public readonly code: SessionTokenErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'SessionTokenError';
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function validateHex32(value: string, label: string): void {
  if (!HEX32_RE.test(value)) {
    throw new SessionTokenError(
      'INVALID_CLAIMS',
      `${label} must be a 0x-prefixed, 64-char lowercase hex string, got: ${value}`,
    );
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function scopeToBase64url(scopeCommitment: string): string {
  // Remove 0x prefix, convert hex to bytes, then base64url encode
  const hex = scopeCommitment.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  // Base64url encode without padding
  const b64 = Buffer.from(bytes).toString('base64url');
  return b64;
}

function base64urlToScope(b64: string): string {
  const bytes = Buffer.from(b64, 'base64url');
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return '0x' + hex.padStart(64, '0');
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Mint a Bolyra session JWT from a verified handshake result.
 *
 * @param handshakeResult - Output from verifyHandshake().
 * @param relayerPrivKey  - ES256 private key (CryptoKey or raw bytes).
 * @param ttl             - Token lifetime in seconds. Default: 900 (15 min).
 * @param chainId         - EIP-155 chain ID. Default: 84532 (Base Sepolia).
 * @returns Compact-serialized JWT string.
 */
export async function encodeSessionToken(
  handshakeResult: HandshakeResult,
  relayerPrivKey: RelayerKey,
  ttl: number = DEFAULT_TTL_SECONDS,
  chainId: number = 84532,
): Promise<string> {
  if (!handshakeResult.verified) {
    throw new SessionTokenError(
      'UNVERIFIED_HANDSHAKE',
      'Cannot issue session token for unverified handshake',
    );
  }

  // Validate hex32 fields
  validateHex32(handshakeResult.nullifierHash, 'nullifierHash');
  validateHex32(handshakeResult.scopeCommitment, 'scopeCommitment');
  validateHex32(handshakeResult.sessionNonce, 'sessionNonce');
  validateHex32(handshakeResult.humanMerkleRoot, 'humanMerkleRoot');

  // Validate TTL
  if (ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new SessionTokenError(
      'TTL_EXCEEDED',
      `TTL must be between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS} seconds, got: ${ttl}`,
    );
  }

  // Validate chainId
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new SessionTokenError(
      'INVALID_CLAIMS',
      `chainId must be a positive integer, got: ${chainId}`,
    );
  }

  const registryAddress = handshakeResult.registryAddress;

  const jwt = await new SignJWT({
    scope: scopeToBase64url(handshakeResult.scopeCommitment),
    nonce: handshakeResult.sessionNonce,
    bolyra_root: handshakeResult.humanMerkleRoot,
  } as unknown as JWTPayload)
    .setProtectedHeader({
      alg: ALG,
      typ: 'JWT',
      'x-bolyra-registry': registryAddress,
      'x-bolyra-chain-id': chainId,
    } as JWTHeaderParameters)
    .setSubject(handshakeResult.nullifierHash)
    .setIssuer(registryAddress)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setJti(randomUUID())
    .sign(relayerPrivKey);

  return jwt;
}

/**
 * Verify and decode a Bolyra session JWT.
 *
 * @param jwt              - Compact JWT string.
 * @param relayerPubKey    - ES256 public key corresponding to the relayer.
 * @param expectedRegistry - Expected registry contract address.
 * @param expectedChainId  - Expected EIP-155 chain ID.
 * @returns Typed SessionTokenClaims on success.
 */
export async function verifySessionToken(
  jwt: string,
  relayerPubKey: RelayerKey,
  expectedRegistry: string,
  expectedChainId: number,
): Promise<SessionTokenClaims> {
  let rawPayload: JWTPayload;
  let header: JWTHeaderParameters;

  try {
    const result = await jwtVerify(jwt, relayerPubKey, {
      algorithms: [ALG],
      clockTolerance: MAX_CLOCK_SKEW_SECONDS,
    });
    rawPayload = result.payload;
    header = result.protectedHeader;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (
      message.includes('expired') ||
      message.includes('exp') ||
      message.includes('"exp" claim')
    ) {
      throw new SessionTokenError('TOKEN_EXPIRED', 'Session token has expired');
    }
    throw new SessionTokenError(
      'INVALID_SIGNATURE',
      `JWT verification failed: ${message}`,
    );
  }

  // ── Header validation ────────────────────────────────────────────────────

  const headerRegistry = (header as Record<string, unknown>)['x-bolyra-registry'];
  const headerChainId = (header as Record<string, unknown>)['x-bolyra-chain-id'];

  if (typeof headerRegistry !== 'string' || headerRegistry === '') {
    throw new SessionTokenError(
      'MISSING_CLAIMS',
      'JOSE header missing x-bolyra-registry',
    );
  }

  if (headerRegistry !== expectedRegistry) {
    throw new SessionTokenError(
      'REGISTRY_MISMATCH',
      `x-bolyra-registry "${headerRegistry}" does not match expected "${expectedRegistry}"`,
    );
  }

  if (typeof headerChainId !== 'number' || !Number.isInteger(headerChainId) || headerChainId <= 0) {
    throw new SessionTokenError(
      'MISSING_CLAIMS',
      'JOSE header missing or invalid x-bolyra-chain-id',
    );
  }

  if (headerChainId !== expectedChainId) {
    throw new SessionTokenError(
      'CHAIN_ID_MISMATCH',
      `x-bolyra-chain-id ${headerChainId} does not match expected ${expectedChainId}`,
    );
  }

  // ── Payload validation ───────────────────────────────────────────────────

  const p = rawPayload as Record<string, unknown>;

  // Required string claims
  for (const key of ['sub', 'iss', 'scope', 'nonce', 'jti', 'bolyra_root'] as const) {
    if (typeof p[key] !== 'string' || (p[key] as string).length === 0) {
      throw new SessionTokenError(
        'MISSING_CLAIMS',
        `Required claim "${key}" missing or empty`,
      );
    }
  }

  // Validate hex32 fields
  validateHex32(p.sub as string, 'sub');
  validateHex32(p.nonce as string, 'nonce');
  validateHex32(p.bolyra_root as string, 'bolyra_root');

  // iss must match header registry
  if (p.iss !== expectedRegistry) {
    throw new SessionTokenError(
      'REGISTRY_MISMATCH',
      `iss "${p.iss}" does not match expected registry "${expectedRegistry}"`,
    );
  }

  // TTL guard: exp - iat must not exceed MAX_TTL
  const iat = p.iat as number;
  const exp = p.exp as number;
  if (exp - iat > MAX_TTL_SECONDS) {
    throw new SessionTokenError(
      'TTL_EXCEEDED',
      `Token TTL ${exp - iat}s exceeds maximum ${MAX_TTL_SECONDS}s`,
    );
  }

  // Future iat guard
  const now = nowSeconds();
  if (iat > now + MAX_CLOCK_SKEW_SECONDS) {
    throw new SessionTokenError(
      'FUTURE_IAT',
      `Token iat ${iat} is too far in the future (now: ${now})`,
    );
  }

  return {
    iss: p.iss as string,
    sub: p.sub as string,
    scope: p.scope as string,
    nonce: p.nonce as string,
    exp,
    iat,
    jti: p.jti as string,
    bolyra_root: p.bolyra_root as string,
    registry: headerRegistry,
    chainId: headerChainId,
  };
}
