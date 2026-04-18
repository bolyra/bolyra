import * as snarkjs from 'snarkjs';
import * as path from 'path';
import {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  Proof,
  BolyraConfig,
} from './types';
import { ProofGenerationError } from './errors';

// Default paths to circuit artifacts (relative to package root)
const DEFAULT_CIRCUIT_DIR = path.join(__dirname, '../../circuits/build');

/**
 * Generate a mutual handshake proof (human + agent).
 * Both proofs can be generated in parallel for wall-clock optimization.
 *
 * @param human - The human's identity (secret + publicKey + commitment)
 * @param agent - The agent's credential (signed by operator)
 * @param options - Optional scope, nonce override, and SDK config
 * @returns Both proofs and the session nonce
 *
 * @example
 * ```ts
 * const { humanProof, agentProof, nonce } = await proveHandshake(
 *   humanIdentity,
 *   agentCredential,
 *   { scope: 1n }
 * );
 * // Submit both proofs to IdentityRegistry.verifyHandshake()
 * ```
 */
export async function proveHandshake(
  human: HumanIdentity,
  agent: AgentCredential,
  options?: {
    scope?: bigint;
    nonce?: bigint;
    config?: BolyraConfig;
  },
): Promise<{ humanProof: Proof; agentProof: Proof; nonce: bigint }> {
  const scope = options?.scope ?? 1n;
  const nonce = options?.nonce ?? BigInt(Date.now());
  const circuitDir = options?.config?.circuitDir ?? DEFAULT_CIRCUIT_DIR;

  // Generate both proofs in parallel
  const [humanProof, agentProof] = await Promise.all([
    generateHumanProof(human, scope, nonce, circuitDir),
    generateAgentProof(agent, nonce, circuitDir),
  ]);

  return { humanProof, agentProof, nonce };
}

async function generateHumanProof(
  human: HumanIdentity,
  scope: bigint,
  nonce: bigint,
  circuitDir: string,
): Promise<Proof> {
  const wasmPath = path.join(
    circuitDir,
    'HumanUniqueness_js/HumanUniqueness.wasm',
  );
  const zkeyPath = path.join(circuitDir, 'HumanUniqueness_final.zkey');

  // Build Merkle proof inputs (single leaf: depth 0, padded to 20)
  const siblings = new Array(20).fill('0');

  const input = {
    secret: human.secret.toString(),
    merkleProofLength: '0', // depth 0 for single-leaf tree
    merkleProofIndex: '0',
    merkleProofSiblings: siblings,
    scope: scope.toString(),
    sessionNonce: nonce.toString(),
  };

  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      wasmPath,
      zkeyPath,
    );
    return { proof, publicSignals };
  } catch (err: any) {
    throw new ProofGenerationError(
      'HumanUniqueness',
      err.message ?? String(err),
    );
  }
}

async function generateAgentProof(
  agent: AgentCredential,
  nonce: bigint,
  circuitDir: string,
): Promise<Proof> {
  const wasmPath = path.join(
    circuitDir,
    'AgentPolicy_js/AgentPolicy.wasm',
  );
  const zkeyPath = path.join(circuitDir, 'AgentPolicy_plonk.zkey');

  const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
  const requiredScopeMask = 0n; // no required scope for basic handshake

  const siblings = new Array(20).fill('0');

  const input = {
    modelHash: agent.modelHash.toString(),
    operatorPubkeyAx: agent.operatorPublicKey.x.toString(),
    operatorPubkeyAy: agent.operatorPublicKey.y.toString(),
    permissionBitmask: agent.permissionBitmask.toString(),
    expiryTimestamp: agent.expiryTimestamp.toString(),
    sigR8x: agent.signature.R8.x.toString(),
    sigR8y: agent.signature.R8.y.toString(),
    sigS: agent.signature.S.toString(),
    merkleProofLength: '0',
    merkleProofIndex: '0',
    merkleProofSiblings: siblings,
    requiredScopeMask: requiredScopeMask.toString(),
    currentTimestamp: currentTimestamp.toString(),
    sessionNonce: nonce.toString(),
  };

  try {
    const { proof, publicSignals } = await snarkjs.plonk.fullProve(
      input,
      wasmPath,
      zkeyPath,
    );
    return { proof, publicSignals };
  } catch (err: any) {
    throw new ProofGenerationError(
      'AgentPolicy',
      err.message ?? String(err),
    );
  }
}

/**
 * Verify a handshake result (check proof validity without on-chain submission).
 * For on-chain verification, submit proofs to IdentityRegistry.verifyHandshake().
 *
 * @param humanProof - The human's ZK proof
 * @param agentProof - The agent's ZK proof
 * @param nonce - The session nonce used during proof generation
 * @param config - SDK configuration (circuitDir for vkey paths)
 * @returns HandshakeResult with nullifiers and verification status
 */
export async function verifyHandshake(
  humanProof: Proof,
  agentProof: Proof,
  nonce: bigint,
  config?: BolyraConfig,
): Promise<HandshakeResult> {
  const circuitDir = config?.circuitDir ?? DEFAULT_CIRCUIT_DIR;

  // Verify human proof (Groth16)
  const humanVkeyPath = path.join(circuitDir, 'HumanUniqueness_vkey.json');
  const humanVkey = require(humanVkeyPath);
  const humanValid = await snarkjs.groth16.verify(
    humanVkey,
    humanProof.publicSignals,
    humanProof.proof,
  );

  // Verify agent proof (PLONK)
  const agentVkeyPath = path.join(circuitDir, 'AgentPolicy_vkey.json');
  const agentVkey = require(agentVkeyPath);
  const agentValid = await snarkjs.plonk.verify(
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
