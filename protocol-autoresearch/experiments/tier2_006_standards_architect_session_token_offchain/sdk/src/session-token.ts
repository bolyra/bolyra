/**
 * Bolyra Session Token — off-chain bearer credential after on-chain handshake.
 *
 * Uses the `jose` library for JWS compact serialization with EdDSA (Ed25519)
 * or ES256 (P-256). After a single on-chain verifyHandshake(), the relying
 * party mints a BST binding the public signals. Subsequent API calls present
 * the BST as a Bearer token — reducing per-call cost to a signature check.
 *
 * Media type: application/bolyra-session+jwt
 *
 * @see spec/session-token-format.md
 * @module @bolyra/sdk/session-token
 */

import { SignJWT, jwtVerify, importJWK, decodeJwt, decodeProtectedHeader, type JWK } from 'jose';
import type {
  BolyraSessionPayload,
  HandshakePublicSignals,
  SessionTokenOptions,
  SessionTokenErrorCode,
  VerifiedSession,
} from './types/session.js';

export type { BolyraSessionPayload, HandshakePublicSignals, SessionTokenOptions, VerifiedSession };

// ── Constants ──────────────────────────────────────────────────────────────

export const BOLYRA_SESSION_MEDIA_TYPE = 'application/bolyra-session+jwt';
export const BOLYRA_SESSION_TYP = 'bolyra-session+jwt';

const DEFAULT_TTL_SECONDS = 300;
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 86400;
const DEFAULT_ISSUER = 'did:bolyra:verifier';
const DEFAULT_ALGORITHM = 'EdDSA';

const BYTES32_HEX_RE = /^0x[0-9a-f]{64}$/;

// ── Error ──────────────────────────────────────────────────────────────────

export class BolyraSessionError extends Error {
  constructor(
    public readonly code: SessionTokenErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BolyraSessionError';
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function assertBytes32Hex(value: string, name: string): void {
  if (!BYTES32_HEX_RE.test(value)) {
    throw new BolyraSessionError(
      'INVALID_SIGNATURE',
      `${name} must be 0x-prefixed 64-char lowercase hex, got: ${value}`,
    );
  }
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Mint a session token after a successful verifyHandshake().
 *
 * @param handshakeResult - Public signals from the verified on-chain handshake.
 * @param signingKey - An Ed25519 or P-256 private key in JWK format.
 * @param options - TTL, issuer, and algorithm overrides.
 * @returns A signed JWS compact serialization string.
 */
export async function mintSessionToken(
  handshakeResult: HandshakePublicSignals,
  signingKey: JWK,
  options: SessionTokenOptions = {},
): Promise<string> {
  if (!handshakeResult.verified) {
    throw new BolyraSessionError(
      'INVALID_SIGNATURE',
      'Cannot mint session token from unverified handshake',
    );
  }

  // Validate bytes32 hex format
  assertBytes32Hex(handshakeResult.humanNullifier, 'humanNullifier');
  assertBytes32Hex(handshakeResult.agentNullifier, 'agentNullifier');
  assertBytes32Hex(handshakeResult.sessionNonce, 'sessionNonce');
  assertBytes32Hex(handshakeResult.scopeCommitment, 'scopeCommitment');

  const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new BolyraSessionError(
      'INVALID_SIGNATURE',
      `TTL must be between ${MIN_TTL_SECONDS}s and ${MAX_TTL_SECONDS}s, got ${ttl}s`,
    );
  }

  const alg = options.algorithm ?? DEFAULT_ALGORITHM;
  const issuer = options.issuer ?? DEFAULT_ISSUER;
  const privateKey = await importJWK(signingKey, alg);

  const jwt = await new SignJWT({
    humanNullifier: handshakeResult.humanNullifier,
    agentNullifier: handshakeResult.agentNullifier,
    sessionNonce: handshakeResult.sessionNonce,
    scopeCommitment: handshakeResult.scopeCommitment,
  })
    .setProtectedHeader({ alg, typ: BOLYRA_SESSION_TYP })
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setIssuer(issuer)
    .sign(privateKey);

  return jwt;
}

/**
 * Verify a session token off-chain.
 *
 * @param token - The JWS compact serialization string.
 * @param verifyingKey - The issuer's public key in JWK format.
 * @param expectedNonce - If provided, assert sessionNonce matches.
 * @param expectedIssuer - If provided, assert iss matches.
 * @returns VerifiedSession with decoded payload and metadata.
 */
export async function verifySessionToken(
  token: string,
  verifyingKey: JWK,
  expectedNonce?: string,
  expectedIssuer?: string,
): Promise<VerifiedSession> {
  // Check typ header before signature verification
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new BolyraSessionError('INVALID_SIGNATURE', 'Malformed token: cannot decode header');
  }

  if (header.typ !== BOLYRA_SESSION_TYP) {
    throw new BolyraSessionError(
      'INVALID_SIGNATURE',
      `Invalid typ: expected ${BOLYRA_SESSION_TYP}, got ${header.typ}`,
    );
  }

  const alg = header.alg as 'ES256' | 'EdDSA';
  if (alg !== 'ES256' && alg !== 'EdDSA') {
    throw new BolyraSessionError(
      'INVALID_SIGNATURE',
      `Unsupported algorithm: ${alg}. Must be ES256 or EdDSA.`,
    );
  }

  // Verify signature and expiry
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(verifyingKey, alg);
    const verifyOpts: { algorithms: string[]; issuer?: string } = {
      algorithms: [alg],
    };
    if (expectedIssuer) {
      verifyOpts.issuer = expectedIssuer;
    }
    const result = await jwtVerify(token, key, verifyOpts);
    payload = result.payload as Record<string, unknown>;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('expired') || message.includes('exp') || message.includes('"exp"')) {
      throw new BolyraSessionError('EXPIRED_SESSION', 'Session token has expired');
    }
    throw new BolyraSessionError('INVALID_SIGNATURE', `Token verification failed: ${message}`);
  }

  // Validate required claims
  const humanNullifier = payload.humanNullifier as string;
  const agentNullifier = payload.agentNullifier as string;
  const sessionNonce = payload.sessionNonce as string;
  const scopeCommitment = payload.scopeCommitment as string;

  if (!humanNullifier || !agentNullifier || !sessionNonce || !scopeCommitment) {
    throw new BolyraSessionError(
      'INVALID_SIGNATURE',
      'Missing required claims: humanNullifier, agentNullifier, sessionNonce, scopeCommitment',
    );
  }

  assertBytes32Hex(humanNullifier, 'humanNullifier');
  assertBytes32Hex(agentNullifier, 'agentNullifier');
  assertBytes32Hex(sessionNonce, 'sessionNonce');
  assertBytes32Hex(scopeCommitment, 'scopeCommitment');

  // Nonce binding check
  if (expectedNonce && sessionNonce !== expectedNonce) {
    throw new BolyraSessionError(
      'NONCE_MISMATCH',
      `Session nonce mismatch: expected ${expectedNonce}, got ${sessionNonce}`,
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = payload.exp as number;

  const sessionPayload: BolyraSessionPayload = {
    humanNullifier,
    agentNullifier,
    sessionNonce,
    scopeCommitment,
    iat: payload.iat as number,
    exp,
    iss: payload.iss as string,
  };

  return {
    payload: sessionPayload,
    algorithm: alg,
    active: exp > now,
    remainingSeconds: Math.max(0, exp - now),
  };
}

/**
 * Extract permission bits from a session token's scopeCommitment.
 *
 * This is a convenience helper that decodes the token without full
 * signature verification — useful when the RP has already verified
 * the token and just needs to check scope for a specific API call.
 *
 * NOTE: For the 8-bit cumulative encoding, the scopeCommitment in the
 * token is the Poseidon hash of the actual permission bits. In practice,
 * the RP must have a lookup or the raw bits alongside the commitment.
 * This helper extracts the raw scopeCommitment hex for the caller to
 * resolve against their own records.
 *
 * @param token - The JWS compact serialization string.
 * @returns The scopeCommitment hex string from the token payload.
 */
export function extractScopeFromToken(token: string): string {
  const payload = decodeJwt(token);
  const scope = payload.scopeCommitment as string | undefined;
  if (!scope || !BYTES32_HEX_RE.test(scope)) {
    throw new BolyraSessionError(
      'SCOPE_INSUFFICIENT',
      'Token does not contain a valid scopeCommitment claim',
    );
  }
  return scope;
}
