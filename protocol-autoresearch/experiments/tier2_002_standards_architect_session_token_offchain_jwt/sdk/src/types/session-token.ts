/**
 * TypeScript interfaces for Bolyra JWT Session Tokens.
 *
 * @see spec/bolyra-session-token-jwt-01.md
 */

/**
 * JOSE header for a Bolyra Session Token.
 */
export interface BolyraJWTHeader {
  /** Signing algorithm. MUST be 'ES256' or 'EdDSA'. */
  alg: 'ES256' | 'EdDSA';
  /** Token type. MUST be 'bolyra+jwt'. */
  typ: 'bolyra+jwt';
}

/**
 * JWT payload claims for a Bolyra Session Token.
 *
 * All hex32 values are 0x-prefixed, 64-char lowercase hex strings.
 */
export interface BolyraJWTPayload {
  /** Nullifier hash from the HumanUniqueness circuit (hex32). */
  humanNullifier: string;
  /** Nullifier hash from the AgentPolicy circuit (hex32). */
  agentNullifier: string;
  /** Session nonce binding the handshake to this session (hex32). */
  sessionNonce: string;
  /** Poseidon(permissions, salt) committed on-chain (hex32). */
  scopeCommitment: string;
  /** Ordered delegation chain, root to leaf. Empty for non-delegated. */
  delegationChain: string[];
  /** EVM chain ID of the verifier network. */
  chainId: number;
  /** Address of the on-chain verifier contract (0x + 40 hex). */
  verifierContract: string;
  /** Issuer identifier (DID or URI). */
  iss: string;
  /** Subject — MUST equal humanNullifier. */
  sub: string;
  /** Issued-at timestamp (Unix seconds). */
  iat: number;
  /** Expiration timestamp (Unix seconds). */
  exp: number;
}

/**
 * Handshake result shape expected by issueSessionToken.
 * Must expose the four public signals from on-chain verification.
 */
export interface HandshakeResult {
  humanNullifier: string;
  agentNullifier: string;
  sessionNonce: string;
  scopeCommitment: string;
  /** Whether on-chain verification succeeded. */
  verified: boolean;
}

/**
 * Options for issuing a session token.
 */
export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 300. Range: [30, 3600]. */
  ttlSeconds?: number;
  /** Issuer identifier. Default: 'did:bolyra:relayer'. */
  issuer?: string;
  /** Signing algorithm. Default: 'ES256'. */
  algorithm?: 'ES256' | 'EdDSA';
  /** Ordered delegation chain of nullifier hex strings (root to leaf). Default: []. */
  delegationChain?: string[];
  /** EVM chain ID. Default: 84532 (Base Sepolia). */
  chainId?: number;
  /** Verifier contract address. */
  verifierContract?: string;
}

/**
 * Result of successfully verifying a session token.
 */
export interface VerifiedSessionClaims {
  /** Decoded and validated payload. */
  payload: BolyraJWTPayload;
  /** Algorithm used to sign the token. */
  algorithm: 'ES256' | 'EdDSA';
  /** Whether the token is still valid (not expired). */
  active: boolean;
  /** Remaining lifetime in seconds (0 if expired). */
  remainingSeconds: number;
}

/**
 * Error codes for session token operations.
 */
export type SessionTokenErrorCode =
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'MISSING_CLAIMS'
  | 'INVALID_CLAIMS'
  | 'TTL_EXCEEDED'
  | 'FUTURE_IAT'
  | 'UNVERIFIED_HANDSHAKE'
  | 'INVALID_ALG';
