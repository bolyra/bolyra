/**
 * Bolyra SDK — Mutual ZKP Handshake
 *
 * proveHandshake() generates paired HumanUniqueness + AgentPolicy proofs
 * bound to a shared sessionNonce AND chainId.
 *
 * verifyHandshake() checks both proofs off-chain (snarkjs) or on-chain.
 */

import * as snarkjs from "snarkjs";
import path from "path";
import type {
  HandshakeOptions,
  HandshakeProof,
  VerifyHandshakeOptions,
  ProofInputs,
} from "./types";

const CIRCUITS_BUILD = path.resolve(__dirname, "../../circuits/build");

function buildProofInputs(opts: HandshakeOptions): ProofInputs {
  return {
    humanInputs: {
      identitySecret: opts.human.identitySecret,
      merkleProofLength: opts.humanMerkleProof.depth,
      merkleProofSiblings: opts.humanMerkleProof.siblings,
      merkleProofIndices: opts.humanMerkleProof.indices,
      humanMerkleRoot: opts.humanMerkleProof.root,
      externalNullifier: opts.externalNullifier,
      sessionNonce: opts.sessionNonce,
      chainId: opts.chainId,
    },
    agentInputs: {
      modelHash: opts.agent.modelHash,
      operatorPubKeyX: opts.agent.operatorPubKeyX,
      operatorPubKeyY: opts.agent.operatorPubKeyY,
      signatureR8x: opts.agent.signatureR8x,
      signatureR8y: opts.agent.signatureR8y,
      signatureS: opts.agent.signatureS,
      permissions: opts.agent.permissions,
      expiry: opts.agent.expiry,
      merkleProofLength: opts.agentMerkleProof.depth,
      merkleProofSiblings: opts.agentMerkleProof.siblings,
      merkleProofIndices: opts.agentMerkleProof.indices,
      agentMerkleRoot: opts.agentMerkleProof.root,
      currentTimestamp: opts.currentTimestamp,
      requiredPermissions: opts.requiredPermissions,
      sessionNonce: opts.sessionNonce,
      chainId: opts.chainId,
    },
  };
}

/**
 * Generate a mutual handshake proof pair bound to sessionNonce and chainId.
 *
 * @param opts - Handshake options including both identities, Merkle proofs,
 *               sessionNonce, and chainId.
 * @returns Paired Groth16 proofs and public signals for both circuits.
 */
export async function proveHandshake(
  opts: HandshakeOptions
): Promise<HandshakeProof> {
  const inputs = buildProofInputs(opts);

  const [humanResult, agentResult] = await Promise.all([
    snarkjs.groth16.fullProve(
      inputs.humanInputs,
      path.join(CIRCUITS_BUILD, "HumanUniqueness_js", "HumanUniqueness.wasm"),
      path.join(CIRCUITS_BUILD, "HumanUniqueness.zkey")
    ),
    snarkjs.groth16.fullProve(
      inputs.agentInputs,
      path.join(CIRCUITS_BUILD, "AgentPolicy_js", "AgentPolicy.wasm"),
      path.join(CIRCUITS_BUILD, "AgentPolicy.zkey")
    ),
  ]);

  return {
    humanProof: humanResult.proof,
    humanPublicSignals: humanResult.publicSignals.map(BigInt),
    agentProof: agentResult.proof,
    agentPublicSignals: agentResult.publicSignals.map(BigInt),
    chainId: opts.chainId,
  };
}

/**
 * Verify a mutual handshake off-chain using snarkjs.
 *
 * @param opts - Proofs, public signals, sessionNonce, and expected chainId.
 * @returns true if both proofs verify and chainId matches.
 */
export async function verifyHandshake(
  opts: VerifyHandshakeOptions
): Promise<boolean> {
  // Extract chainId from public signals and verify it matches expected
  const humanChainId = opts.humanPublicSignals[5];
  const agentChainId = opts.agentPublicSignals[6];

  if (humanChainId !== opts.chainId) {
    throw new Error(
      `Human proof chainId mismatch: expected ${opts.chainId}, got ${humanChainId}`
    );
  }
  if (agentChainId !== opts.chainId) {
    throw new Error(
      `Agent proof chainId mismatch: expected ${opts.chainId}, got ${agentChainId}`
    );
  }

  const humanVkey = await snarkjs.zKey.exportVerificationKey(
    path.join(CIRCUITS_BUILD, "HumanUniqueness.zkey")
  );
  const agentVkey = await snarkjs.zKey.exportVerificationKey(
    path.join(CIRCUITS_BUILD, "AgentPolicy.zkey")
  );

  const [humanValid, agentValid] = await Promise.all([
    snarkjs.groth16.verify(
      humanVkey,
      opts.humanPublicSignals.map(String),
      opts.humanProof
    ),
    snarkjs.groth16.verify(
      agentVkey,
      opts.agentPublicSignals.map(String),
      opts.agentProof
    ),
  ]);

  return humanValid && agentValid;
}
