import { randomBytes } from 'crypto';
import * as snarkjs from 'snarkjs';
import * as path from 'path';
import * as fs from 'fs';
import {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  Proof,
  BolyraConfig,
} from './types';
import { ProofGenerationError, CircuitArtifactNotFoundError, VerificationError } from './errors';
import { proveGroth16, ProverBackend } from './prover';

// Default paths to circuit artifacts (relative to package root)
const DEFAULT_CIRCUIT_DIR = path.join(__dirname, '../../circuits/build');

/**
 * Cryptographically unpredictable nonce that embeds a Unix-seconds timestamp
 * in the upper bits so the MCP verifier can still check freshness.
 *
 * Layout (fits in uint256):
 *   nonce = (unix_seconds << 64) | random_64_bits
 *
 * Extract timestamp: `nonce >> 64n`
 */
export function defaultNonce(): bigint {
  const ts = BigInt(Math.floor(Date.now() / 1000));
  const rand = BigInt('0x' + randomBytes(8).toString('hex'));
  return (ts << 64n) | rand;
}

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
    backend?: ProverBackend;
  },
): Promise<{ humanProof: Proof; agentProof: Proof; nonce: bigint }> {
  const scope = options?.scope ?? 1n;
  const nonce = options?.nonce ?? defaultNonce();
  const circuitDir = options?.config?.circuitDir ?? DEFAULT_CIRCUIT_DIR;
  const backend = options?.backend ?? 'auto';

  // Validate circuit artifacts exist before attempting proof generation
  const humanWasm = path.join(circuitDir, 'HumanUniqueness_js/HumanUniqueness.wasm');
  const humanZkey = path.join(circuitDir, 'HumanUniqueness_final.zkey');
  const agentWasm = path.join(circuitDir, 'AgentPolicy_js/AgentPolicy.wasm');
  const agentZkey = path.join(circuitDir, 'AgentPolicy_final.zkey');

  if (!fs.existsSync(humanWasm)) {
    throw new CircuitArtifactNotFoundError(humanWasm, 'wasm');
  }
  if (!fs.existsSync(humanZkey)) {
    throw new CircuitArtifactNotFoundError(humanZkey, 'zkey');
  }
  if (!fs.existsSync(agentWasm)) {
    throw new CircuitArtifactNotFoundError(agentWasm, 'wasm');
  }
  if (!fs.existsSync(agentZkey)) {
    throw new CircuitArtifactNotFoundError(agentZkey, 'zkey');
  }

  // Generate both proofs in parallel
  const [humanProof, agentProof] = await Promise.all([
    generateHumanProof(human, scope, nonce, circuitDir, backend),
    generateAgentProof(agent, nonce, circuitDir, backend),
  ]);

  return { humanProof, agentProof, nonce };
}

async function generateHumanProof(
  human: HumanIdentity,
  scope: bigint,
  nonce: bigint,
  circuitDir: string,
  backend: ProverBackend,
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
    return await proveGroth16(input, wasmPath, zkeyPath, backend);
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
  backend: ProverBackend,
): Promise<Proof> {
  const wasmPath = path.join(
    circuitDir,
    'AgentPolicy_js/AgentPolicy.wasm',
  );
  const zkeyPath = path.join(circuitDir, 'AgentPolicy_final.zkey');

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
    return await proveGroth16(input, wasmPath, zkeyPath, backend);
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
  // Resolve relative paths against process.cwd() so callers can pass
  // `./demo` or any project-relative location without hitting the
  // cryptic "Cannot find module 'demo/HumanUniqueness_vkey.json'"
  // require() error.
  const circuitDir = path.resolve(config?.circuitDir ?? DEFAULT_CIRCUIT_DIR);

  // Validate proof structure before verification
  if (!humanProof || !humanProof.proof || !Array.isArray(humanProof.publicSignals)) {
    throw new VerificationError(
      'Invalid humanProof structure: expected { proof: object, publicSignals: string[] }. ' +
        'Ensure you are passing the proof object returned by proveHandshake().'
    );
  }
  if (!agentProof || !agentProof.proof || !Array.isArray(agentProof.publicSignals)) {
    throw new VerificationError(
      'Invalid agentProof structure: expected { proof: object, publicSignals: string[] }. ' +
        'Ensure you are passing the proof object returned by proveHandshake().'
    );
  }
  // HumanUniqueness publicSignals layout (length 5):
  //   [0] humanMerkleRoot   [1] nullifierHash   [2] nonceBinding
  //   [3] scope             [4] sessionNonce
  if (humanProof.publicSignals.length < 5) {
    throw new VerificationError(
      `humanProof has ${humanProof.publicSignals.length} public signals, expected at least 5. ` +
        'The proof may have been generated with an incompatible circuit version.'
    );
  }
  // AgentPolicy publicSignals layout (length 6):
  //   [0] agentMerkleRoot   [1] nullifierHash   [2] scopeCommitment
  //   [3] requiredScopeMask [4] currentTimestamp [5] sessionNonce
  if (agentProof.publicSignals.length < 6) {
    throw new VerificationError(
      `agentProof has ${agentProof.publicSignals.length} public signals, expected at least 6. ` +
        'The proof may have been generated with an incompatible circuit version.'
    );
  }

  // Bind the nonce argument to the nonce that each circuit committed
  // to. Without this, the `nonce` parameter is decorative: snarkjs
  // verifies the proof against its embedded publicSignals regardless
  // of what the caller passed, and the returned `sessionNonce` would
  // echo a value that was never cryptographically bound to the proof.
  // Refuse to claim verified=true whenever drift is detected.
  //
  // publicSignals are caller-supplied strings; a malformed entry would
  // otherwise turn the fail-closed drift branch into a thrown
  // exception. tryBigInt() yields `null` on parse failure, which is
  // never equal to `nonce` (forcing the drift return) and is rendered
  // as 0n in the returned nullifier/scope fields so the caller still
  // gets a well-typed `HandshakeResult` with `verified: false`.
  const tryBigInt = (s: string): bigint | null => {
    try {
      return BigInt(s);
    } catch {
      return null;
    }
  };
  const humanNonceCommitted = tryBigInt(humanProof.publicSignals[4]);
  const agentNonceCommitted = tryBigInt(agentProof.publicSignals[5]);
  if (humanNonceCommitted !== nonce || agentNonceCommitted !== nonce) {
    return {
      humanNullifier: tryBigInt(humanProof.publicSignals[1]) ?? 0n,
      agentNullifier: tryBigInt(agentProof.publicSignals[1]) ?? 0n,
      sessionNonce: nonce,
      scopeCommitment: tryBigInt(agentProof.publicSignals[2]) ?? 0n,
      verified: false,
    };
  }

  // Verify vkey files exist
  const humanVkeyPath = path.join(circuitDir, 'HumanUniqueness_vkey.json');
  if (!fs.existsSync(humanVkeyPath)) {
    throw new CircuitArtifactNotFoundError(humanVkeyPath, 'vkey');
  }
  const agentVkeyPath = path.join(circuitDir, 'AgentPolicy_groth16_vkey.json');
  if (!fs.existsSync(agentVkeyPath)) {
    throw new CircuitArtifactNotFoundError(agentVkeyPath, 'vkey');
  }

  // Verify human proof (Groth16)
  const humanVkey = require(humanVkeyPath);
  const humanValid = await snarkjs.groth16.verify(
    humanVkey,
    humanProof.publicSignals,
    humanProof.proof,
  );

  // Verify agent proof (Groth16)
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
