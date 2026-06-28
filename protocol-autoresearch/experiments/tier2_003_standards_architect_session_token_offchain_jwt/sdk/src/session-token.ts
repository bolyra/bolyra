/**
 * Bolyra session token (bolyra+jwt profile) — issuance and verification.
 *
 * After a successful on-chain verifyHandshake(), the verifier mints a
 * short-lived JWT encoding the handshake outputs. Subsequent interactions
 * present only the JWT, reducing per-call overhead to a signature check.
 *
 * Spec: draft-bolyra-session-token-01
 *
 * @module
 */

import { SignJWT, jwtVerify, importJWK, decodeProtectedHeader } from 'jose';
import type { JWK, JWTVerifyResult } from 'jose';
import { randomUUID } from 'crypto';
import type {
  BolyraSessionTokenHeader,
  BolyraSessionTokenPayload,
  BolyraSessionTokenOptions,
  BolyraVerifyOptions,
  HandshakeResultForToken,
  NonceStore,
  SessionTokenErrorCode,
} from './types/session-token.js';

// ── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 300;
const MIN_TTL_SECONDS = 60;
const MAX_TTL_SECONDS = 900;
const DEFAULT_ISSUER = 'https://verify.bolyra.ai';
const DEFAULT_ALGORITHMS: ('EdDSA' | 'ES256')[] = ['EdDSA', 'ES256'];
const DEFAULT_CLOCK_TOLERANCE = 30;
const HEX_66_RE = /^0x[0-9a-f]{64}$/;

// ── Error ───────────────────────────────────────────────────────────────────

export class BolyraSessionTokenError extends Error {
  constructor(
    public readonly code: SessionTokenErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BolyraSessionTokenError';
  }
}

// ── In-Memory Nonce Store ───────────────────────────────────────────────────

/**
 * Default in-memory nonce store. Suitable for single-process deployments.
 * For production, inject a Redis/DB-backed NonceStore via BolyraVerifyOptions.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly consumed = new Map<string, number>();

  async checkAndConsume(nonce: string, expiresAt: number): Promise<boolean> {
    this.evictExpired();
    if (this.consumed.has(nonce)) return true;
    this.consumed.set(nonce, expiresAt);
    return false;
  }

  private evictExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [nonce, exp] of this.consumed) {
      if (exp <= now) this.consumed.delete(nonce);
    }
  }
}

// Singleton for default usage
const defaultNonceStore = new InMemoryNonceStore();

// ── Helpers ─────────────────────────────────────────────────────────────────

function assertHex66(value: string, label: string): void {
  if (!HEX_66_RE.test(value)) {
    throw new BolyraSessionTokenError(
      'CLAIMS_MISSING',
      `${label} must be a 0x-prefixed 64-char lowercase hex string, got: ${value}`,
    );
  }
}

function validatePermissions(perm: number): void {
  if (!Number.isInteger(perm) || perm < 0 || perm > 255) {
    throw new BolyraSessionTokenError(
      'INVALID_PERMISSIONS',
      `Permissions must be integer 0-255, got: ${perm}`,
    );
  }
  // Cumulative bit rules: bit 4 implies 3,2; bit 3 implies 2
  if ((perm & 0x10) && !(perm & 0x08)) {
    throw new BolyraSessionTokenError(
      'INVALID_PERMISSIONS',
      'FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)',
    );
  }
  if ((perm & 0x08) && !(perm & 0x04)) {
    throw new BolyraSessionTokenError(
      'INVALID_PERMISSIONS',
      'FINANCIAL_MEDIUM (bit 3) requires FINANCIAL_SMALL (bit 2)',
    );
  }
}

// ── Issue ───────────────────────────────────────────────────────────────────

/**
 * Issue a signed session token after a successful handshake verification.
 *
 * @param handshakeResult - Verified handshake outputs (humanNullifier, etc.).
 * @param signingKey - JWK private key (Ed25519 or P-256).
 * @param options - TTL, issuer, algorithm, vtx, permissions overrides.
 * @returns Compact JWS string (three dot-separated base64url parts).
 */
export async function issueSessionToken(
  handshakeResult: HandshakeResultForToken,
  signingKey: JWK,
  options: BolyraSessionTokenOptions = {},
): Promise<string> {
  if (!handshakeResult.valid) {
    throw new BolyraSessionTokenError(
      'INVALID_HANDSHAKE',
      'Cannot issue session token from invalid handshake result',
    );
  }

  const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new BolyraSessionTokenError(
      'TTL_OUT_OF_RANGE',
      `TTL must be ${MIN_TTL_SECONDS}-${MAX_TTL_SECONDS}s, got ${ttl}s`,
    );
  }

  const alg = options.algorithm ?? 'EdDSA';
  const issuer = options.issuer ?? DEFAULT_ISSUER;

  // Validate hex encoding of handshake outputs
  assertHex66(handshakeResult.humanNullifier, 'humanNullifier');
  assertHex66(handshakeResult.agentNullifier, 'agentNullifier');
  assertHex66(handshakeResult.scopeCommitment, 'scopeCommitment');
  assertHex66(handshakeResult.sessionNonce, 'sessionNonce');

  if (options.verificationTxHash) {
    assertHex66(options.verificationTxHash, 'verificationTxHash');
  }

  if (options.permissions !== undefined) {
    validatePermissions(options.permissions);
  }

  const privateKey = await importJWK(signingKey, alg);

  const header: BolyraSessionTokenHeader = { alg, typ: 'bolyra+jwt' };
  if (options.verificationTxHash) {
    header.vtx = options.verificationTxHash;
  }

  const claims: Record<string, unknown> = {
    'bolyra.agn': handshakeResult.agentNullifier,
    'bolyra.scp': handshakeResult.scopeCommitment,
    'bolyra.nonce': handshakeResult.sessionNonce,
  };

  if (options.verificationTxHash) {
    claims['bolyra.vtx'] = options.verificationTxHash;
  }
  if (options.permissions !== undefined) {
    claims['bolyra.perm'] = options.permissions;
  }

  const jwt = await new SignJWT(claims)
    .setProtectedHeader(header)
    .setSubject(handshakeResult.humanNullifier)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setIssuer(issuer)
    .setJti(randomUUID())
    .sign(privateKey);

  return jwt;
}

// ── Verify ──────────────────────────────────────────────────────────────────

/**
 * Verify a bolyra+jwt session token.
 *
 * @param token - The compact JWS string.
 * @param verificationKey - JWK public key (Ed25519 or P-256).
 * @param options - Issuer, algorithms, clock tolerance, nonce store, scope.
 * @returns The validated payload as BolyraSessionTokenPayload.
 */
export async function verifySessionToken(
  token: string,
  verificationKey: JWK,
  options: BolyraVerifyOptions = {},
): Promise<BolyraSessionTokenPayload> {
  const issuer = options.issuer ?? DEFAULT_ISSUER;
  const algorithms = options.algorithms ?? DEFAULT_ALGORITHMS;
  const clockTolerance = options.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE;
  const nonceStore = options.nonceStore ?? defaultNonceStore;

  // 1. Verify typ header
  let protectedHeader: Record<string, unknown>;
  try {
    protectedHeader = decodeProtectedHeader(token);
  } catch {
    throw new BolyraSessionTokenError('INVALID_SIGNATURE', 'Failed to decode JOSE header');
  }

  if (protectedHeader.typ !== 'bolyra+jwt') {
    throw new BolyraSessionTokenError(
      'INVALID_TYP',
      `Expected typ 'bolyra+jwt', got '${protectedHeader.typ}'`,
    );
  }

  // Validate vtx header format if present
  if (protectedHeader.vtx !== undefined) {
    if (typeof protectedHeader.vtx !== 'string' || !HEX_66_RE.test(protectedHeader.vtx)) {
      throw new BolyraSessionTokenError(
        'INVALID_VTX',
        'Header vtx must be a 0x-prefixed 64-char lowercase hex string',
      );
    }
  }

  // 2. Verify JWS signature, iat, exp, iss
  let result: JWTVerifyResult;
  try {
    const key = await importJWK(verificationKey, protectedHeader.alg as string);
    result = await jwtVerify(token, key, {
      issuer,
      algorithms,
      clockTolerance,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('expired') || message.includes('"exp"')) {
      throw new BolyraSessionTokenError('TOKEN_EXPIRED', 'Session token has expired');
    }
    throw new BolyraSessionTokenError('INVALID_SIGNATURE', `JWT verification failed: ${message}`);
  }

  const payload = result.payload as Record<string, unknown>;

  // 3. Validate required Bolyra claims
  const sub = payload.sub;
  const agn = payload['bolyra.agn'];
  const scp = payload['bolyra.scp'];
  const nonce = payload['bolyra.nonce'];
  const jti = payload.jti;

  if (
    typeof sub !== 'string' ||
    typeof agn !== 'string' ||
    typeof scp !== 'string' ||
    typeof nonce !== 'string' ||
    typeof jti !== 'string'
  ) {
    throw new BolyraSessionTokenError(
      'CLAIMS_MISSING',
      'Required claims (sub, bolyra.agn, bolyra.scp, bolyra.nonce, jti) missing or invalid',
    );
  }

  assertHex66(sub, 'sub');
  assertHex66(agn as string, 'bolyra.agn');
  assertHex66(scp as string, 'bolyra.scp');
  assertHex66(nonce as string, 'bolyra.nonce');

  // 4. Validate vtx consistency (header vs payload)
  const vtxPayload = payload['bolyra.vtx'];
  if (vtxPayload !== undefined && protectedHeader.vtx !== undefined) {
    if (vtxPayload !== protectedHeader.vtx) {
      throw new BolyraSessionTokenError(
        'INVALID_VTX',
        'Header vtx and payload bolyra.vtx must match',
      );
    }
  }

  // 5. Validate permissions if present
  const perm = payload['bolyra.perm'];
  if (perm !== undefined) {
    validatePermissions(perm as number);
  }

  // 6. Check expected scope
  if (options.expectedScope && scp !== options.expectedScope) {
    throw new BolyraSessionTokenError(
      'SCOPE_MISMATCH',
      `Expected scope ${options.expectedScope}, got ${scp}`,
    );
  }

  // 7. Check nonce replay
  const exp = payload.exp as number;
  const replayed = await nonceStore.checkAndConsume(nonce as string, exp);
  if (replayed) {
    throw new BolyraSessionTokenError(
      'NONCE_REPLAYED',
      `Session nonce ${nonce} has already been consumed`,
    );
  }

  // 8. Validate max TTL
  const iat = payload.iat as number;
  if (exp - iat > MAX_TTL_SECONDS) {
    throw new BolyraSessionTokenError(
      'TTL_OUT_OF_RANGE',
      `Token lifetime ${exp - iat}s exceeds maximum ${MAX_TTL_SECONDS}s`,
    );
  }

  return payload as unknown as BolyraSessionTokenPayload;
}

// ── Re-exports ──────────────────────────────────────────────────────────────

export type {
  BolyraSessionTokenHeader,
  BolyraSessionTokenPayload,
  BolyraSessionTokenOptions,
  BolyraVerifyOptions,
  HandshakeResultForToken,
  NonceStore,
  SessionTokenErrorCode,
} from './types/session-token.js';
