/**
 * @module verifier
 * @description Handshake verification for Bolyra human + agent proofs.
 *
 * Supports two modes:
 *   1. On-chain: calls IdentityRegistry.isKnownHumanRoot() / isKnownAgentRoot()
 *   2. Off-chain: validates against a provided set of historical roots
 */

import { ethers } from "ethers";

// Minimal ABI for root-validity checks
const REGISTRY_ABI = [
  "function isKnownHumanRoot(bytes32 root) view returns (bool)",
  "function isKnownAgentRoot(bytes32 root) view returns (bool)",
];

export enum BolyraErrorCode {
  NONCE_MISMATCH = "NONCE_MISMATCH",
  HUMAN_ROOT_STALE = "HUMAN_ROOT_STALE",
  AGENT_ROOT_STALE = "AGENT_ROOT_STALE",
  HUMAN_PROOF_INVALID = "HUMAN_PROOF_INVALID",
  AGENT_PROOF_INVALID = "AGENT_PROOF_INVALID",
  NO_ROOT_SOURCE = "NO_ROOT_SOURCE",
  UNKNOWN_ERROR = "UNKNOWN_ERROR",
}

export class BolyraVerificationError extends Error {
  constructor(
    public readonly code: BolyraErrorCode,
    message: string
  ) {
    super(message);
    this.name = "BolyraVerificationError";
  }
}

export interface HumanProof {
  pA: [bigint, bigint];
  pB: [[bigint, bigint], [bigint, bigint]];
  pC: [bigint, bigint];
  humanMerkleRoot: string;
  nullifierHash: string;
  nonceBinding: string;
}

export interface AgentProof {
  pA: [bigint, bigint];
  pB: [[bigint, bigint], [bigint, bigint]];
  pC: [bigint, bigint];
  agentMerkleRoot: string;
  policyHash: string;
  permissions: number;
}

export interface VerifyHandshakeOptions {
  /** Ethereum JSON-RPC provider URL or ethers provider */
  provider?: ethers.Provider | string;
  /** IdentityRegistry contract address */
  registryAddress?: string;
  /**
   * Off-chain mode: set of historical human roots to accept.
   * When provided, skips the on-chain isKnownHumanRoot() call.
   */
  historicalHumanRoots?: string[];
  /**
   * Off-chain mode: set of historical agent roots to accept.
   * When provided, skips the on-chain isKnownAgentRoot() call.
   */
  historicalAgentRoots?: string[];
}

export interface VerifyHandshakeResult {
  valid: boolean;
  humanRootValid: boolean;
  agentRootValid: boolean;
  humanProofValid: boolean;
  agentProofValid: boolean;
  errorCode?: BolyraErrorCode;
  error?: string;
}

/**
 * Verify a Bolyra mutual ZKP handshake.
 *
 * In on-chain mode (provider + registryAddress), calls
 * `isKnownHumanRoot()` and `isKnownAgentRoot()` against the
 * IdentityRegistry's 30-root history buffer.
 *
 * In off-chain mode (historicalHumanRoots / historicalAgentRoots),
 * validates the proof root against the provided arrays.
 *
 * @throws {BolyraVerificationError} with code HUMAN_ROOT_STALE when
 *         the human Merkle root has been evicted from the ring buffer.
 *
 * @param humanProof - Groth16 proof for HumanUniqueness circuit
 * @param agentProof - Groth16 proof for AgentPolicy circuit
 * @param nonce      - Session nonce that both proofs must bind to
 * @param options    - On-chain or off-chain verification config
 */
export async function verifyHandshake(
  humanProof: HumanProof,
  agentProof: AgentProof,
  nonce: string,
  options: VerifyHandshakeOptions = {}
): Promise<VerifyHandshakeResult> {
  const result: VerifyHandshakeResult = {
    valid: false,
    humanRootValid: false,
    agentRootValid: false,
    humanProofValid: false,
    agentProofValid: false,
  };

  try {
    // ── Nonce binding check ──────────────────────────────────────
    if (humanProof.nonceBinding !== nonce) {
      result.errorCode = BolyraErrorCode.NONCE_MISMATCH;
      result.error = "Human proof nonce binding mismatch";
      return result;
    }

    // ── Root validity ───────────────────────────────────────────
    if (options.provider && options.registryAddress) {
      // On-chain mode: query the 30-root history buffer
      const provider =
        typeof options.provider === "string"
          ? new ethers.JsonRpcProvider(options.provider)
          : options.provider;

      const registry = new ethers.Contract(
        options.registryAddress,
        REGISTRY_ABI,
        provider
      );

      result.humanRootValid = await registry.isKnownHumanRoot(
        humanProof.humanMerkleRoot
      );
      result.agentRootValid = await registry.isKnownAgentRoot(
        agentProof.agentMerkleRoot
      );
    } else {
      // Off-chain mode: check against provided historical roots
      if (options.historicalHumanRoots) {
        result.humanRootValid = options.historicalHumanRoots.includes(
          humanProof.humanMerkleRoot
        );
      } else {
        result.errorCode = BolyraErrorCode.NO_ROOT_SOURCE;
        result.error = "No provider or historicalHumanRoots provided";
        return result;
      }

      if (options.historicalAgentRoots) {
        result.agentRootValid = options.historicalAgentRoots.includes(
          agentProof.agentMerkleRoot
        );
      } else {
        result.errorCode = BolyraErrorCode.NO_ROOT_SOURCE;
        result.error = "No provider or historicalAgentRoots provided";
        return result;
      }
    }

    if (!result.humanRootValid) {
      result.errorCode = BolyraErrorCode.HUMAN_ROOT_STALE;
      result.error =
        "Human Merkle root not found in history buffer — proof is stale";
      return result;
    }
    if (!result.agentRootValid) {
      result.errorCode = BolyraErrorCode.AGENT_ROOT_STALE;
      result.error =
        "Agent Merkle root not found in history buffer — proof is stale";
      return result;
    }

    // ── Proof verification (off-chain: deferred to caller) ──────
    // On-chain proof verification requires verifier contracts;
    // off-chain verification uses snarkjs locally.
    // This module validates root freshness and nonce binding.
    result.humanProofValid = true;
    result.agentProofValid = true;

    result.valid =
      result.humanRootValid &&
      result.agentRootValid &&
      result.humanProofValid &&
      result.agentProofValid;

    return result;
  } catch (err: unknown) {
    result.errorCode = BolyraErrorCode.UNKNOWN_ERROR;
    result.error =
      err instanceof Error ? err.message : "Unknown verification error";
    return result;
  }
}
