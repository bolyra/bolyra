/**
 * Session token types for SD-JWT off-chain proof reuse.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Claims bound into an SD-JWT session token.
 * Extracted from a verified HandshakeResult.
 */
export interface SessionTokenPayload {
  /** Human nullifier hash (hex). Single-use at proof time; short-lived in token. */
  nullifierHash: string;
  /** Scope commitment binding (hex). */
  scopeCommitment: string;
  /** Agent credential identifier (hex). */
  agentId: string;
  /** Human Merkle tree root at proof time (hex). */
  humanMerkleRoot: string;
  /** Issued-at (unix seconds). */
  iat: number;
  /** Expiry (unix seconds). */
  exp: number;
  /** Issuer identifier. */
  iss: string;
  /** Audience (optional). */
  aud?: string;
}

/**
 * Options for minting a session token.
 */
export interface SessionTokenOptions {
  /** Token lifetime in seconds. Default: 300. Min: 60. Max: 3600. */
  ttl?: number;
  /** Issuer claim. Default: 'bolyra.ai'. */
  issuer?: string;
  /** Audience claim (optional). */
  audience?: string;
  /** 32-byte HMAC-SHA256 signing key (Buffer, Uint8Array, or hex string). */
  signingKey: Uint8Array | string;
  /** Claims to include as selective disclosures. Default: all four core claims. */
  selectiveDisclosureFields?: Array<'nullifierHash' | 'scopeCommitment' | 'agentId' | 'humanMerkleRoot'>;
}

/**
 * Options for verifying a session token.
 */
export interface SessionVerifyOptions {
  /** 32-byte HMAC-SHA256 verification key. */
  signingKey: Uint8Array | string;
  /** Claims that MUST be disclosed in the presented token. */
  requiredClaims?: string[];
  /** Clock skew tolerance in seconds. Default: 30. */
  clockSkew?: number;
}

/**
 * Minimal handshake result shape consumed by the session module.
 * Compatible with the full HandshakeResult from sdk/src/core/types.ts.
 */
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
  scopeCommitment?: bigint;
  agentCredentialHash?: bigint;
  modelHash?: bigint;
  operatorDID?: string;
}
