import * as snarkjs from 'snarkjs';
import * as path from 'path';
import * as fs from 'fs';
import { ethers } from 'ethers';
import {
  Proof,
  BolyraConfig,
  HandshakeResult,
  OffchainVerificationResult,
  BatchCheckpoint,
} from './types';
import { VerificationError, CircuitArtifactNotFoundError } from './errors';
import { poseidon2 } from './utils';

// Default paths to circuit artifacts (relative to package root)
const DEFAULT_CIRCUIT_DIR = path.join(__dirname, '../../circuits/build');

/**
 * Verify a handshake off-chain using local snarkjs verification.
 * Same interface as verifyHandshake but never touches the chain.
 * Produces a HandshakeResult suitable for batching.
 *
 * Gas savings: 0 gas per verification (vs ~300k+ on-chain).
 * The batch root is posted once for N verifications.
 */
export async function verifyHandshakeOffchain(
  humanProof: Proof,
  agentProof: Proof,
  nonce: bigint,
  config?: BolyraConfig,
): Promise<HandshakeResult> {
  const circuitDir = config?.circuitDir ?? DEFAULT_CIRCUIT_DIR;

  // Validate proof structure
  if (!humanProof || !humanProof.proof || !Array.isArray(humanProof.publicSignals)) {
    throw new VerificationError(
      'Invalid humanProof structure: expected { proof: object, publicSignals: string[] }.'
    );
  }
  if (!agentProof || !agentProof.proof || !Array.isArray(agentProof.publicSignals)) {
    throw new VerificationError(
      'Invalid agentProof structure: expected { proof: object, publicSignals: string[] }.'
    );
  }
  if (humanProof.publicSignals.length < 2) {
    throw new VerificationError(
      `humanProof has ${humanProof.publicSignals.length} public signals, expected at least 2.`
    );
  }
  if (agentProof.publicSignals.length < 3) {
    throw new VerificationError(
      `agentProof has ${agentProof.publicSignals.length} public signals, expected at least 3.`
    );
  }

  // Load verification keys
  const humanVkeyPath = path.join(circuitDir, 'HumanUniqueness_vkey.json');
  if (!fs.existsSync(humanVkeyPath)) {
    throw new CircuitArtifactNotFoundError(humanVkeyPath, 'vkey');
  }
  const agentVkeyPath = path.join(circuitDir, 'AgentPolicy_groth16_vkey.json');
  if (!fs.existsSync(agentVkeyPath)) {
    throw new CircuitArtifactNotFoundError(agentVkeyPath, 'vkey');
  }

  // Verify both proofs locally (no on-chain interaction)
  const humanVkey = require(humanVkeyPath);
  const humanValid = await snarkjs.groth16.verify(
    humanVkey,
    humanProof.publicSignals,
    humanProof.proof,
  );

  const agentVkey = require(agentVkeyPath);
  const agentValid = await snarkjs.groth16.verify(
    agentVkey,
    agentProof.publicSignals,
    agentProof.proof,
  );

  return {
    humanNullifier: BigInt(humanProof.publicSignals[1]),
    agentNullifier: BigInt(agentProof.publicSignals[1]),
    sessionNonce: nonce,
    scopeCommitment: BigInt(agentProof.publicSignals[2]),
    verified: humanValid && agentValid,
  };
}

/**
 * Compute the session commitment for a HandshakeResult.
 * sessionCommitment = Poseidon2(humanNullifier, Poseidon2(agentNullifier, sessionNonce))
 * This binds all three fields into a single leaf for the batch Merkle tree.
 */
export async function computeSessionCommitment(result: HandshakeResult): Promise<bigint> {
  const inner = await poseidon2(result.agentNullifier, result.sessionNonce);
  return poseidon2(result.humanNullifier, inner);
}

/**
 * Accumulates verified handshake sessions and produces a Poseidon Merkle root.
 * The root can be posted on-chain in a single transaction, amortizing gas
 * across all sessions in the batch (target: ~100x reduction).
 *
 * Tree construction: binary Poseidon Merkle tree. If the number of leaves
 * is not a power of 2, zero-padding is applied to the right.
 */
export class OffchainVerificationBatch {
  private sessions: HandshakeResult[] = [];
  private commitments: bigint[] = [];
  private cachedRoot: bigint | null = null;

  /** Number of sessions in the batch. */
  get size(): number {
    return this.sessions.length;
  }

  /**
   * Add a verified handshake result to the batch.
   * Resets the cached Merkle root (will be recomputed on next getMerkleRoot call).
   *
   * @returns The OffchainVerificationResult with batchIndex set.
   */
  async add(result: HandshakeResult): Promise<OffchainVerificationResult> {
    if (!result.verified) {
      throw new VerificationError(
        'Cannot add unverified handshake to batch. Verify the handshake first.'
      );
    }

    const batchIndex = this.sessions.length;
    const commitment = await computeSessionCommitment(result);

    this.sessions.push(result);
    this.commitments.push(commitment);
    this.cachedRoot = null; // invalidate cache

    return {
      ...result,
      batchIndex,
    };
  }

  /**
   * Compute the Poseidon Merkle root of all session commitments.
   * Uses a binary tree with zero-padding to the next power of 2.
   * Result is cached until a new session is added.
   */
  async getMerkleRoot(): Promise<bigint> {
    if (this.sessions.length === 0) {
      return 0n;
    }

    if (this.cachedRoot !== null) {
      return this.cachedRoot;
    }

    this.cachedRoot = await buildPoseidonMerkleRoot(this.commitments);
    return this.cachedRoot;
  }

  /**
   * Get a Merkle inclusion proof for a specific session in the batch.
   * Returns sibling hashes and path indices (0 = left, 1 = right) from leaf to root.
   *
   * @param sessionIndex - Index of the session (from OffchainVerificationResult.batchIndex)
   * @returns Merkle proof (siblings + pathIndices) or throws if index is out of bounds.
   */
  async getProofOfInclusion(
    sessionIndex: number,
  ): Promise<{ siblings: bigint[]; pathIndices: number[] }> {
    if (sessionIndex < 0 || sessionIndex >= this.sessions.length) {
      throw new VerificationError(
        `Session index ${sessionIndex} out of bounds (batch has ${this.sessions.length} sessions).`
      );
    }

    return buildPoseidonMerkleProof(this.commitments, sessionIndex);
  }

  /**
   * Get the session commitment at a given index.
   */
  getCommitment(index: number): bigint {
    if (index < 0 || index >= this.commitments.length) {
      throw new VerificationError(
        `Index ${index} out of bounds (batch has ${this.commitments.length} sessions).`
      );
    }
    return this.commitments[index];
  }

  /**
   * Get all session commitments (for external verification).
   */
  getCommitments(): bigint[] {
    return [...this.commitments];
  }
}

/**
 * Post a batch Merkle root on-chain. A single transaction checkpoints N sessions.
 *
 * Gas cost: ~50k-80k gas for a single storage write + event emission,
 * regardless of how many sessions are in the batch.
 * For 100 sessions: ~500 gas/session vs ~300k gas/session on-chain = ~600x reduction.
 *
 * @param batch - The batch to checkpoint
 * @param signer - An ethers Signer (connected to the target chain)
 * @param registryAddress - Address of the IdentityRegistry (or a BatchCheckpoint contract)
 * @returns The BatchCheckpoint with on-chain timestamp
 */
export async function postBatchRoot(
  batch: OffchainVerificationBatch,
  signer: ethers.Signer,
  registryAddress: string,
): Promise<BatchCheckpoint> {
  if (batch.size === 0) {
    throw new VerificationError('Cannot post empty batch root on-chain.');
  }

  const root = await batch.getMerkleRoot();

  // ABI for the postBatchRoot function on the BatchCheckpoint extension contract.
  // function postBatchRoot(uint256 root, uint256 sessionCount) external
  const abi = [
    'function postBatchRoot(uint256 root, uint256 sessionCount) external',
    'event BatchRootPosted(uint256 indexed root, uint256 sessionCount, uint256 timestamp)',
  ];

  const contract = new ethers.Contract(registryAddress, abi, signer);
  const tx = await contract.postBatchRoot(root, batch.size);
  const receipt = await tx.wait();

  const timestamp = receipt?.blockNumber
    ? (await signer.provider!.getBlock(receipt.blockNumber))?.timestamp ?? Math.floor(Date.now() / 1000)
    : Math.floor(Date.now() / 1000);

  return {
    root,
    timestamp,
    sessionCount: batch.size,
  };
}

// ============ Internal Merkle Tree Helpers ============

/**
 * Pad leaves array to the next power of 2 with zeros.
 */
function padToPowerOfTwo(leaves: bigint[]): bigint[] {
  if (leaves.length === 0) return [0n];
  let size = 1;
  while (size < leaves.length) {
    size *= 2;
  }
  const padded = [...leaves];
  while (padded.length < size) {
    padded.push(0n);
  }
  return padded;
}

/**
 * Build a Poseidon Merkle root from a list of leaf commitments.
 * Binary tree, zero-padded to next power of 2.
 */
async function buildPoseidonMerkleRoot(leaves: bigint[]): Promise<bigint> {
  let layer = padToPowerOfTwo(leaves);

  while (layer.length > 1) {
    const nextLayer: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      nextLayer.push(await poseidon2(layer[i], layer[i + 1]));
    }
    layer = nextLayer;
  }

  return layer[0];
}

/**
 * Build a Merkle inclusion proof for a specific leaf index.
 * Returns siblings and path indices (0 = leaf is on the left, 1 = leaf is on the right).
 */
async function buildPoseidonMerkleProof(
  leaves: bigint[],
  index: number,
): Promise<{ siblings: bigint[]; pathIndices: number[] }> {
  const padded = padToPowerOfTwo(leaves);
  const siblings: bigint[] = [];
  const pathIndices: number[] = [];

  let layer = padded;
  let currentIndex = index;

  while (layer.length > 1) {
    const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
    siblings.push(layer[siblingIndex]);
    pathIndices.push(currentIndex % 2); // 0 = left, 1 = right

    // Build next layer
    const nextLayer: bigint[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      nextLayer.push(await poseidon2(layer[i], layer[i + 1]));
    }
    layer = nextLayer;
    currentIndex = Math.floor(currentIndex / 2);
  }

  return { siblings, pathIndices };
}

/**
 * Verify a Merkle inclusion proof against a known root.
 * Useful for verifiers who receive a proof-of-inclusion from a session participant.
 *
 * @param leaf - The session commitment (leaf value)
 * @param siblings - Sibling hashes from the proof
 * @param pathIndices - Path indices (0 = left, 1 = right)
 * @param expectedRoot - The expected Merkle root (from on-chain checkpoint)
 * @returns true if the proof is valid
 */
export async function verifyMerkleInclusion(
  leaf: bigint,
  siblings: bigint[],
  pathIndices: number[],
  expectedRoot: bigint,
): Promise<boolean> {
  if (siblings.length !== pathIndices.length) {
    return false;
  }

  let current = leaf;
  for (let i = 0; i < siblings.length; i++) {
    if (pathIndices[i] === 0) {
      current = await poseidon2(current, siblings[i]);
    } else {
      current = await poseidon2(siblings[i], current);
    }
  }

  return current === expectedRoot;
}
