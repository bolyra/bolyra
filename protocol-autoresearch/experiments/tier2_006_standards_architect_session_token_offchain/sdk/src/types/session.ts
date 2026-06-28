/**
 * TypeScript types for Bolyra Session Tokens (BST).
 *
 * @see spec/session-token-format.md
 */

/**
 * JOSE header for a Bolyra Session Token.
 */
export interface BolyraSessionHeader {
  /** Signing algorithm. MUST be 'ES256' or 'EdDSA'. */
  alg: 'ES256' | 'EdDSA';
  /** Token type. MUST be 'bolyra-session+jwt'. */
  typ: 'bolyra-session+jwt';
}

/**
 * JWT payload claims for a Bolyra Session Token.
 *
 * All bytes32 values are `0x`-prefixed, 64-char lowercase hex strings.
 */
export interface BolyraSessionPayload {
  /** Nullifier hash from the HumanUniqueness circuit. */
  humanNullifier: string;
  /** Nullifier hash from the AgentPolicy circuit. */
  agentNullifier: string;
  /** Session nonce binding the handshake to this session. */
  sessionNonce: string;
  /** Poseidon hash of the 8-bit cumulative permission encoding. */
  scopeCommitment: string;
  /** Issued-at timestamp (seconds since Unix epoch). */
  iat: number;
  /** Expiration timestamp (seconds since Unix epoch). */
  exp: number;
  /** Issuer DID (did:bolyra:<verifier-id>). */
  iss: string;
}

/**
 * Options for minting a session token.
 */
export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 300. Must be >= 30 and <= 86400. */
  ttlSeconds?: number;
  /** Issuer DID. Default: 'did:bolyra:verifier'. */
  issuer?: string;
  /** Signing algorithm. Default: 'EdDSA'. */
  algorithm?: 'ES256' | 'EdDSA';
}

/**
 * Result of successfully verifying a session token.
 */
export interface VerifiedSession {
  /** Decoded and validated payload claims. */
  payload: BolyraSessionPayload;
  /** The algorithm used to sign the token. */
  algorithm: 'ES256' | 'EdDSA';
  /** Whether the token is still valid (not expired). */
  active: boolean;
  /** Remaining lifetime in seconds. */
  remainingSeconds: number;
}

/**
 * Handshake result shape expected by mintSessionToken.
 * Must expose the four public signals from on-chain verification.
 */
export interface HandshakePublicSignals {
  humanNullifier: string;
  agentNullifier: string;
  sessionNonce: string;
  scopeCommitment: string;
  verified: boolean;
}

/**
 * Error codes for session token operations.
 */
export type SessionTokenErrorCode =
  | 'EXPIRED_SESSION'
  | 'NONCE_MISMATCH'
  | 'SCOPE_INSUFFICIENT'
  | 'INVALID_SIGNATURE';
