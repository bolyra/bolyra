/**
 * Bolyra SDK types — extended with chainId for cross-chain replay prevention.
 */

export type BigIntish = bigint | string | number;

/** 8-bit cumulative permission encoding. */
export enum Permission {
  READ_DATA          = 0,
  WRITE_DATA         = 1,
  FINANCIAL_SMALL    = 2,
  FINANCIAL_MEDIUM   = 3,
  FINANCIAL_UNLIMITED = 4,
  SIGN_ON_BEHALF     = 5,
  SUB_DELEGATE       = 6,
  ACCESS_PII         = 7,
}

export interface HumanIdentity {
  identitySecret: bigint;
  identityCommitment: bigint;
}

export interface AgentCredential {
  modelHash: bigint;
  operatorPubKeyX: bigint;
  operatorPubKeyY: bigint;
  signatureR8x: bigint;
  signatureR8y: bigint;
  signatureS: bigint;
  permissions: number;
  expiry: bigint;
  credentialHash: bigint;
}

export interface MerkleProof {
  root: bigint;
  depth: number;
  siblings: bigint[];
  indices: number[];
}

export interface HandshakeOptions {
  /** Human identity (private). */
  human: HumanIdentity;
  /** Human Merkle proof. */
  humanMerkleProof: MerkleProof;
  /** External nullifier (scope). */
  externalNullifier: bigint;
  /** Agent credential (private). */
  agent: AgentCredential;
  /** Agent Merkle proof. */
  agentMerkleProof: MerkleProof;
  /** Required permission bitmask. */
  requiredPermissions: number;
  /** Current timestamp for expiry check. */
  currentTimestamp: bigint;
  /** Fresh session nonce — must be unique per handshake. */
  sessionNonce: bigint;
  /**
   * EIP-155 chain ID to bind the proof to a specific chain.
   * Prevents cross-chain replay: a proof generated for chain A
   * will not verify on chain B.
   */
  chainId: bigint;
}

export interface HandshakeProof {
  humanProof: Groth16Proof;
  humanPublicSignals: bigint[];
  agentProof: Groth16Proof;
  agentPublicSignals: bigint[];
  /** The chain ID this proof is bound to. */
  chainId: bigint;
}

export interface Groth16Proof {
  pi_a: [bigint, bigint];
  pi_b: [[bigint, bigint], [bigint, bigint]];
  pi_c: [bigint, bigint];
  protocol: string;
  curve: string;
}

export interface ProofInputs {
  /** Human circuit witness inputs. */
  humanInputs: {
    identitySecret: bigint;
    merkleProofLength: number;
    merkleProofSiblings: bigint[];
    merkleProofIndices: number[];
    humanMerkleRoot: bigint;
    externalNullifier: bigint;
    sessionNonce: bigint;
    chainId: bigint;
  };
  /** Agent circuit witness inputs. */
  agentInputs: {
    modelHash: bigint;
    operatorPubKeyX: bigint;
    operatorPubKeyY: bigint;
    signatureR8x: bigint;
    signatureR8y: bigint;
    signatureS: bigint;
    permissions: number;
    expiry: bigint;
    merkleProofLength: number;
    merkleProofSiblings: bigint[];
    merkleProofIndices: number[];
    agentMerkleRoot: bigint;
    currentTimestamp: bigint;
    requiredPermissions: number;
    sessionNonce: bigint;
    chainId: bigint;
  };
}

export interface VerifyHandshakeOptions {
  humanProof: Groth16Proof;
  humanPublicSignals: bigint[];
  agentProof: Groth16Proof;
  agentPublicSignals: bigint[];
  /** Session nonce to check binding. */
  sessionNonce: bigint;
  /** Expected chain ID — must match what was proven. */
  chainId: bigint;
}
