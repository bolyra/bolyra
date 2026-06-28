/**
 * Off-chain session token module for multi-step agent chains.
 *
 * Amortizes a single on-chain verifyHandshake() across many off-chain tool calls
 * using signed JWTs with proof digests, scope bitmaps, and replay prevention.
 */

import { createHash, randomBytes, generateKeyPairSync, createSign, createVerify } from 'crypto';
import { validateCumulativeBitEncoding } from './permissions.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface SessionTokenPayload {
  proofDigest: string;
  humanNullifier: string;
  agentCredHash: string;
  scopeBitmap: number;
  sessionNonce: string;
  iat: number;
  exp: number;
  iss: string;
}

export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 3600 (1 hour). */
  expirySeconds?: number;
  /** Narrowed scope bitmap. Must be a subset of the handshake scope. */
  scopeOverride?: number;
}

export interface VerifiedHandshake {
  humanProof: Uint8Array | Buffer;
  agentProof: Uint8Array | Buffer;
  humanNullifier: string;
  agentCredHash: string;
  scopeBitmap: number;
  valid: boolean;
}

export type SessionErrorCode =
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'INVALID_ISSUER'
  | 'INSUFFICIENT_SCOPE'
  | 'TOKEN_REVOKED'
  | 'INVALID_TOKEN'
  | 'SCOPE_VIOLATION';

export class BolyraSessionError extends Error {
  constructor(public readonly code: SessionErrorCode, message: string) {
    super(message);
    this.name = 'BolyraSessionError';
  }
}

// ── Session Manager (module-level singleton per process) ───────────────────

const { privateKey, publicKey } = generateKeyPairSync('ec', {
  namedCurve: 'P-256',
});

const revokedNonces = new Set<string>();

// ── Helpers ────────────────────────────────────────────────────────────────

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

function signJwt(payload: SessionTokenPayload): string {
  const header = { alg: 'ES256', typ: 'JWT' };
  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sign = createSign('SHA256');
  sign.update(signingInput);
  const signature = sign.sign(privateKey);

  return `${signingInput}.${base64url(signature)}`;
}

function verifyJwtSignature(token: string): SessionTokenPayload {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new BolyraSessionError('INVALID_TOKEN', 'Malformed JWT: expected 3 parts');
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = base64urlDecode(signatureB64);

  const verify = createVerify('SHA256');
  verify.update(signingInput);
  if (!verify.verify(publicKey, signature)) {
    throw new BolyraSessionError('INVALID_SIGNATURE', 'JWT signature verification failed');
  }

  return JSON.parse(base64urlDecode(payloadB64).toString()) as SessionTokenPayload;
}

function computeProofDigest(humanProof: Uint8Array | Buffer, agentProof: Uint8Array | Buffer): string {
  const hash = createHash('sha256');
  hash.update(Buffer.from(humanProof));
  hash.update(Buffer.from(agentProof));
  return hash.digest('hex');
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Mint a session token after a successful verifyHandshake().
 *
 * The token is a signed JWT binding the proof digest, nullifier, scope,
 * and a fresh session nonce. It does NOT re-verify on-chain.
 */
export function mintSessionToken(
  humanProof: Uint8Array | Buffer,
  agentProof: Uint8Array | Buffer,
  verifiedHandshake: VerifiedHandshake,
  options: SessionTokenOptions = {},
): string {
  if (!verifiedHandshake.valid) {
    throw new BolyraSessionError('INVALID_TOKEN', 'Cannot mint session token from invalid handshake');
  }

  const expirySeconds = options.expirySeconds ?? 3600;
  let scopeBitmap = verifiedHandshake.scopeBitmap;

  if (options.scopeOverride !== undefined) {
    // scopeOverride must be a subset of the handshake scope
    if ((options.scopeOverride & verifiedHandshake.scopeBitmap) !== options.scopeOverride) {
      throw new BolyraSessionError(
        'SCOPE_VIOLATION',
        `Scope override 0x${options.scopeOverride.toString(16)} is not a subset of handshake scope 0x${verifiedHandshake.scopeBitmap.toString(16)}`,
      );
    }
    // Must satisfy cumulative-bit implication rules
    if (!validateCumulativeBitEncoding(options.scopeOverride)) {
      throw new BolyraSessionError(
        'SCOPE_VIOLATION',
        `Scope override 0x${options.scopeOverride.toString(16)} violates cumulative-bit encoding rules`,
      );
    }
    scopeBitmap = options.scopeOverride;
  }

  const now = Math.floor(Date.now() / 1000);
  const sessionNonce = randomBytes(32).toString('hex');

  const payload: SessionTokenPayload = {
    proofDigest: computeProofDigest(humanProof, agentProof),
    humanNullifier: verifiedHandshake.humanNullifier,
    agentCredHash: verifiedHandshake.agentCredHash,
    scopeBitmap,
    sessionNonce,
    iat: now,
    exp: now + expirySeconds,
    iss: 'bolyra.ai',
  };

  return signJwt(payload);
}

/**
 * Verify a session token off-chain.
 *
 * Checks signature, expiry, issuer, scope, and revocation status.
 * Returns the decoded payload on success.
 */
export function verifySessionToken(
  token: string,
  requiredScope?: number,
): SessionTokenPayload {
  // Step 1-2: Verify signature
  const payload = verifyJwtSignature(token);

  // Step 3: Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new BolyraSessionError('TOKEN_EXPIRED', 'Session token has expired');
  }

  // Step 4: Check issuer
  if (payload.iss !== 'bolyra.ai') {
    throw new BolyraSessionError('INVALID_ISSUER', `Unexpected issuer: ${payload.iss}`);
  }

  // Step 5: Check scope
  if (requiredScope !== undefined) {
    if ((payload.scopeBitmap & requiredScope) !== requiredScope) {
      throw new BolyraSessionError(
        'INSUFFICIENT_SCOPE',
        `Token scope 0x${payload.scopeBitmap.toString(16)} does not include required scope 0x${requiredScope.toString(16)}`,
      );
    }
  }

  // Step 6: Check revocation
  if (revokedNonces.has(payload.sessionNonce)) {
    throw new BolyraSessionError('TOKEN_REVOKED', 'Session token has been revoked');
  }

  return payload;
}

/**
 * Revoke a session token by adding its nonce to the in-process revocation set.
 *
 * Note: Revocation is process-local. Distributed revocation requires
 * application-layer propagation or short token expiry.
 */
export function revokeSessionToken(token: string): void {
  // Decode without scope check — we just need the nonce
  const payload = verifyJwtSignature(token);
  revokedNonces.add(payload.sessionNonce);
}

/**
 * Compute a session root for on-chain checkpoint anchoring.
 *
 * Accepts an array of session token strings, extracts their nonces,
 * sorts lexicographically, and computes keccak256 of the packed nonces.
 *
 * Returns the sessionRoot as a hex string (0x-prefixed, 32 bytes).
 */
export function computeSessionRoot(tokens: string[]): string {
  const nonces = tokens.map((t) => {
    const payload = verifyJwtSignature(t);
    return payload.sessionNonce;
  });

  nonces.sort();

  // keccak256 of packed sorted nonces
  // Use sha256 as a stand-in since native keccak requires ethers/web3
  // In production, use ethers.keccak256(ethers.solidityPacked(...))
  const hash = createHash('sha256');
  for (const nonce of nonces) {
    hash.update(Buffer.from(nonce, 'hex'));
  }
  return '0x' + hash.digest('hex');
}

/**
 * Reset the revocation set. Intended for testing only.
 * @internal
 */
export function _resetRevocationSet(): void {
  revokedNonces.clear();
}
