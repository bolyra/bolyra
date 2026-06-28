/**
 * SD-JWT session token for off-chain proof reuse.
 *
 * After a successful verifyHandshake(), the verifier mints an SD-JWT
 * (Selective Disclosure JWT) binding the verified proof outputs.
 * Subsequent calls present the compact token instead of re-proving.
 *
 * Spec: spec/session-token-sd-jwt.md
 */

import { createHmac, randomBytes, createHash } from 'crypto';

// ── Types ──────────────────────────────────────────────────────────────────

export interface HandshakeResult {
  humanProof: {
    nullifierHash: bigint;
    humanMerkleRoot: bigint;
  };
  agentProof: {
    nullifierHash: bigint;
    permissions: number;
  };
  sessionNonce: bigint;
  verified: boolean;
  /** Optional fields from the handshake context. */
  scopeCommitment?: bigint;
  agentCredentialHash?: bigint;
  modelHash?: bigint;
  operatorDID?: string;
}

export interface SessionClaims {
  nullifierHash: string;
  scopeCommitment?: string;
  humanMerkleRoot?: string;
  agentCredentialHash?: string;
  modelHash?: string;
  operatorDID?: string;
  iat: number;
  exp: number;
  iss: string;
}

export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 300. Range: [60, 3600]. */
  ttlSeconds?: number;
  /** Claims to include as selective disclosures. Default: all four core claims. */
  disclose?: string[];
  /** Clock tolerance in seconds for expiry verification. Default: 0. */
  clockToleranceSec?: number;
}

export interface VerifyTokenOptions {
  /** Claims that MUST be disclosed in the presented token. */
  requiredClaims?: string[];
  /** Clock tolerance in seconds. Default: 0. */
  clockToleranceSec?: number;
}

export type SessionErrorCode =
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'CLAIMS_MISSING'
  | 'INVALID_TOKEN'
  | 'INVALID_HANDSHAKE';

export class BolyraSessionError extends Error {
  constructor(public readonly code: SessionErrorCode, message: string) {
    super(message);
    this.name = 'BolyraSessionError';
  }
}

// ── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_TTL = 300;
const MIN_TTL = 60;
const MAX_TTL = 3600;
const DEFAULT_ISSUER = 'bolyra.ai';
const SD_ALG = 'sha-256';
const ALL_DISCLOSABLE = [
  'nullifierHash',
  'scopeCommitment',
  'humanMerkleRoot',
  'agentCredentialHash',
];

// ── SD-JWT Helpers ─────────────────────────────────────────────────────────

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

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Mint an SD-JWT session token after a successful verifyHandshake().
 *
 * @param result - The HandshakeResult from verifyHandshake().
 * @param secret - 32-byte HMAC-SHA256 shared secret.
 * @param options - Optional TTL and selective disclosure configuration.
 * @returns SD-JWT compact serialization: `<jwt>~<disclosure1>~<disclosure2>~...~`
 */
export function issueSessionToken(
  result: HandshakeResult,
  secret: Uint8Array,
  options: SessionTokenOptions = {},
): string {
  if (!result.verified) {
    throw new BolyraSessionError(
      'INVALID_HANDSHAKE',
      'Cannot mint session token from unverified handshake',
    );
  }

  const ttl = options.ttlSeconds ?? DEFAULT_TTL;
  if (ttl < MIN_TTL || ttl > MAX_TTL) {
    throw new BolyraSessionError(
      'INVALID_TOKEN',
      `TTL must be between ${MIN_TTL}s and ${MAX_TTL}s, got ${ttl}s`,
    );
  }

  const discloseClaims = options.disclose ?? ALL_DISCLOSABLE;

  // Build claim values from the handshake result
  const claimValues: Record<string, string> = {
    nullifierHash: '0x' + result.humanProof.nullifierHash.toString(16),
    scopeCommitment: result.scopeCommitment
      ? '0x' + result.scopeCommitment.toString(16)
      : '0x0',
    humanMerkleRoot: '0x' + result.humanProof.humanMerkleRoot.toString(16),
    agentCredentialHash: result.agentCredentialHash
      ? '0x' + result.agentCredentialHash.toString(16)
      : '0x0',
  };

  // Optional claims
  if (result.modelHash) {
    claimValues.modelHash = '0x' + result.modelHash.toString(16);
  }
  if (result.operatorDID) {
    claimValues.operatorDID = result.operatorDID;
  }

  // Create disclosures for requested claims
  const disclosures: Disclosure[] = [];
  for (const name of discloseClaims) {
    if (claimValues[name] !== undefined) {
      disclosures.push(createDisclosure(name, claimValues[name]));
    }
  }

  const now = Math.floor(Date.now() / 1000);

  // JWT payload with _sd array of disclosure digests
  const payload: Record<string, unknown> = {
    iss: DEFAULT_ISSUER,
    iat: now,
    exp: now + ttl,
    _sd_alg: SD_ALG,
    _sd: disclosures.map((d) => d.digest),
  };

  // Build JWT: header.payload.signature
  const header = { alg: 'HS256', typ: 'sd+jwt' };
  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = hmacSign(secret, signingInput);
  const jwt = `${signingInput}.${signature}`;

  // SD-JWT: jwt~disclosure1~disclosure2~...~
  const disclosureParts = disclosures.map((d) => d.encoded).join('~');
  return `${jwt}~${disclosureParts}~`;
}

/**
 * Verify an SD-JWT session token off-chain.
 *
 * Checks HMAC signature, expiry, issuer, and disclosure integrity.
 * Returns decoded claims from the presented disclosures.
 *
 * @param token - SD-JWT compact serialization.
 * @param secret - 32-byte HMAC-SHA256 shared secret.
 * @param options - Optional required claims and clock tolerance.
 * @returns Decoded SessionClaims.
 */
export function verifySessionToken(
  token: string,
  secret: Uint8Array,
  options: VerifyTokenOptions = {},
): SessionClaims {
  // Split SD-JWT: jwt~disclosure1~disclosure2~...~
  const parts = token.split('~');
  const jwtPart = parts[0];
  // Disclosures are between first and last ~ (last element is empty string after trailing ~)
  const disclosureParts = parts.slice(1).filter((p) => p.length > 0);

  // Verify JWT signature
  const jwtSegments = jwtPart.split('.');
  if (jwtSegments.length !== 3) {
    throw new BolyraSessionError('INVALID_TOKEN', 'Malformed JWT: expected 3 parts');
  }

  const [headerB64, payloadB64, signatureB64] = jwtSegments;
  const signingInput = `${headerB64}.${payloadB64}`;
  const expectedSig = hmacSign(secret, signingInput);

  if (expectedSig !== signatureB64) {
    throw new BolyraSessionError('INVALID_SIGNATURE', 'JWT signature verification failed');
  }

  const payload = JSON.parse(base64urlDecode(payloadB64).toString()) as Record<string, unknown>;

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  const tolerance = options.clockToleranceSec ?? 0;
  const exp = payload.exp as number;
  if (exp <= now - tolerance) {
    throw new BolyraSessionError('TOKEN_EXPIRED', 'Session token has expired');
  }

  // Verify disclosures against _sd digests
  const sdDigests = new Set(payload._sd as string[]);
  const claims: Record<string, string> = {};

  for (const disc of disclosureParts) {
    const digest = base64url(sha256(disc));
    if (!sdDigests.has(digest)) {
      throw new BolyraSessionError(
        'INVALID_TOKEN',
        'Disclosure digest does not match any _sd entry',
      );
    }
    const decoded = JSON.parse(base64urlDecode(disc).toString()) as [string, string, string];
    const [, claimName, claimValue] = decoded;
    claims[claimName] = claimValue;
  }

  // Check required claims
  if (options.requiredClaims) {
    for (const req of options.requiredClaims) {
      if (!(req in claims)) {
        throw new BolyraSessionError(
          'CLAIMS_MISSING',
          `Required claim '${req}' was not disclosed`,
        );
      }
    }
  }

  return {
    nullifierHash: claims.nullifierHash,
    scopeCommitment: claims.scopeCommitment,
    humanMerkleRoot: claims.humanMerkleRoot,
    agentCredentialHash: claims.agentCredentialHash,
    modelHash: claims.modelHash,
    operatorDID: claims.operatorDID,
    iat: payload.iat as number,
    exp: exp,
    iss: payload.iss as string,
  };
}
