/**
 * Bolyra SDK type definitions.
 *
 * @module types
 */

/**
 * Human identity created from a secret.
 */
export interface HumanIdentity {
  /** The secret key (keep private). */
  secret: bigint;
  /** Identity nonce for commitment derivation. */
  identityNonce: bigint;
  /** Poseidon(secret, identityNonce) — the leaf in the identity tree. */
  identityCommitment: bigint;
}

/**
 * Result of a HumanUniqueness proof.
 *
 * Two-nullifier architecture (v3.0.0):
 *   - `nullifierHash`: per-session nullifier, unique to each handshake.
 *     Used for replay prevention. NOT linkable across sessions.
 *   - `externalNullifierCommitment`: stable commitment derived from the
 *     identity's raw nullifier. Used on-chain for sybil gating and
 *     revocation. The raw nullifier is never exposed.
 */
export interface HumanProof {
  /** The Groth16/PLONK proof bytes. */
  proof: Uint8Array;

  /** Merkle root of the identity tree at proof time. */
  humanMerkleRoot: bigint;

  /**
   * Per-session nullifier hash.
   *
   * Derived as Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce).
   * Unique per handshake — verifiers cannot link sessions.
   *
   * Used for: replay prevention (on-chain sessionNullifiers mapping).
   */
  nullifierHash: bigint;

  /** The session nonce used to derive this nullifier. */
  sessionNonce: bigint;

  /** Application scope identifier. */
  scope: bigint;

  /**
   * Stable external nullifier commitment.
   *
   * Derived as Poseidon₁(Poseidon₃(DOMAIN_HUMAN, scope, secret)).
   * Same value across all sessions for the same identity+scope.
   *
   * Used for: on-chain sybil gating, revocation.
   * WARNING: Verifiers MUST NOT log this value alongside session data,
   * as it would re-enable cross-session linkability.
   */
  externalNullifierCommitment: bigint;

  /** Nonce binding for handshake freshness. */
  nonceBinding: bigint;
}

/**
 * Agent credential for the AgentPolicy circuit.
 */
export interface AgentCredential {
  modelHash: bigint;
  operatorPubKey: [bigint, bigint];
  permissions: number;
  expiry: bigint;
  credentialCommitment: bigint;
}

/**
 * Result of an AgentPolicy proof.
 */
export interface AgentProof {
  proof: Uint8Array;
  nullifierHash: bigint;
  policyScope: bigint;
  permissions: number;
  expiry: bigint;
}

/**
 * Combined handshake result from mutual ZKP authentication.
 */
export interface HandshakeResult {
  humanProof: HumanProof;
  agentProof: AgentProof;
  sessionNonce: bigint;
  verified: boolean;
}
