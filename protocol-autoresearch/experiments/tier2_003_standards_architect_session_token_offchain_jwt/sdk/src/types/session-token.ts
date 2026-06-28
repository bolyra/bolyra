/**
 * Type definitions for Bolyra session tokens (bolyra+jwt profile).
 *
 * @module
 */

import type { JWTPayload } from 'jose';

// ── JOSE Header ─────────────────────────────────────────────────────────────

/**
 * JOSE protected header for a bolyra+jwt token.
 */
export interface BolyraSessionTokenHeader {
  /** Signing algorithm. MUST be 'EdDSA' or 'ES256'. */
  alg: 'EdDSA' | 'ES256';
  /** Media type. MUST be 'bolyra+jwt'. */
  typ: 'bolyra+jwt';
  /** Hex-encoded on-chain verification tx hash (0x-prefixed). */
  vtx?: string;
}

// ── Payload ─────────────────────────────────────────────────────────────────

/**
 * JWT payload for a bolyra+jwt token. Extends the standard JWTPayload
 * with Bolyra-specific private claims under the bolyra.* namespace.
 */
export interface BolyraSessionTokenPayload extends JWTPayload {
  /** Human nullifier hash (registered as `sub`). */
  sub: string;
  /** Issuer URI or DID. */
  iss: string;
  /** Issued-at timestamp (Unix epoch seconds). */
  iat: number;
  /** Expiration timestamp (Unix epoch seconds). */
  exp: number;
  /** Unique token identifier (UUID v4). */
  jti: string;
  /** Agent nullifier hash. */
  'bolyra.agn': string;
  /** Scope commitment hash. */
  'bolyra.scp': string;
  /** Session nonce (ZKP-bound). */
  'bolyra.nonce': string;
  /** On-chain verification tx hash (optional, mirrors header vtx). */
  'bolyra.vtx'?: string;
  /** Permission bitmask 0-255 (optional). */
  'bolyra.perm'?: number;
}

// ── Options ─────────────────────────────────────────────────────────────────

/**
 * Options for issuing a session token.
 */
export interface BolyraSessionTokenOptions {
  /** Token lifetime in seconds. Default: 300. Min: 60. Max: 900. */
  ttlSeconds?: number;
  /** JWT issuer claim (URI or DID). Default: 'https://verify.bolyra.ai'. */
  issuer?: string;
  /** Signing algorithm. Default: 'EdDSA'. */
  algorithm?: 'EdDSA' | 'ES256';
  /** On-chain verification tx hash to include in header and payload. */
  verificationTxHash?: string;
  /** Permission bitmask (0-255) to include as bolyra.perm. */
  permissions?: number;
}

/**
 * Options for verifying a session token.
 */
export interface BolyraVerifyOptions {
  /** Expected issuer. Default: 'https://verify.bolyra.ai'. */
  issuer?: string;
  /** Allowed algorithms. Default: ['EdDSA', 'ES256']. */
  algorithms?: ('EdDSA' | 'ES256')[];
  /** Clock tolerance in seconds for iat/exp checks. Default: 30. */
  clockToleranceSeconds?: number;
  /** Nonce store for replay detection. Default: in-memory store. */
  nonceStore?: NonceStore;
  /** If provided, assert bolyra.scp matches this value. */
  expectedScope?: string;
}

// ── Nonce Store ─────────────────────────────────────────────────────────────

/**
 * Interface for nonce replay detection stores.
 * Implementations may use Redis, a database, or in-memory maps.
 */
export interface NonceStore {
  /**
   * Check if a nonce has been consumed. If not, mark it as consumed.
   * @returns `true` if the nonce was already consumed (replay), `false` if fresh.
   */
  checkAndConsume(nonce: string, expiresAt: number): Promise<boolean>;
}

// ── Handshake Input ─────────────────────────────────────────────────────────

/**
 * The verified handshake result that feeds into session token issuance.
 * This is the subset of HandshakeResult needed for token creation.
 */
export interface HandshakeResultForToken {
  valid: boolean;
  humanNullifier: string;
  agentNullifier: string;
  scopeCommitment: string;
  sessionNonce: string;
}

// ── Error Codes ─────────────────────────────────────────────────────────────

export type SessionTokenErrorCode =
  | 'INVALID_HANDSHAKE'
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'NONCE_REPLAYED'
  | 'CLAIMS_MISSING'
  | 'SCOPE_MISMATCH'
  | 'INVALID_TYP'
  | 'TTL_OUT_OF_RANGE'
  | 'INVALID_VTX'
  | 'INVALID_PERMISSIONS';
