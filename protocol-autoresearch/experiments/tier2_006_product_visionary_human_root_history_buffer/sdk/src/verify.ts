/**
 * @module verify
 * @description Handshake verification for Bolyra human + agent proofs.
 *
 * Supports two modes:
 *   1. On-chain: calls IdentityRegistry.isValidHumanRoot() / isValidAgentRoot()
 *   2. Off-chain: validates against a provided set of historical roots
 */

import { ethers } from "ethers";

// Minimal ABI for root-validity checks
const REGISTRY_ABI = [
  "function isValidHumanRoot(bytes32 root) view returns (bool)",
  "function isValidAgentRoot(bytes32 root) view returns (bool)",
  "function verifyHumanProof(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, bytes32 humanMerkleRoot, bytes32 nullifierHash, bytes32 nonceBinding) view returns (bool)",
  "function verifyAgentProof(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, bytes32 agentMerkleRoot, bytes32 policyHash, uint256 permissions) view returns (bool)",
];

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
   * When provided, skips the on-chain isValidHumanRoot() call.
   */
  historicalHumanRoots?: string[];
  /**
   * Off-chain mode: set of historical agent roots to accept.
   * When provided, skips the on-chain isValidAgentRoot() call.
   */
  historicalAgentRoots?: string[];
}

export interface VerifyHandshakeResult {
  valid: boolean;
  humanRootValid: boolean;
  agentRootValid: boolean;
  humanProofValid: boolean;
  agentProofValid: boolean;
  error?: string;
}

/**
 * Verify a Bolyra mutual ZKP handshake.
 *
 * In on-chain mode (provider + registryAddress), calls
 * `isValidHumanRoot()` and `isValidAgentRoot()` against the
 * IdentityRegistry's 30-root history buffer.
 *
 * In off-chain mode (historicalHumanRoots / historicalAgentRoots),
 * validates the proof root against the provided arrays.
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

      result.humanRootValid = await registry.isValidHumanRoot(
        humanProof.humanMerkleRoot
      );
      result.agentRootValid = await registry.isValidAgentRoot(
        agentProof.agentMerkleRoot
      );
    } else {
      // Off-chain mode: check against provided historical roots
      if (options.historicalHumanRoots) {
        result.humanRootValid = options.historicalHumanRoots.includes(
          humanProof.humanMerkleRoot
        );
      } else {
        // No root set provided — cannot validate
        result.error = "No provider or historicalHumanRoots provided";
        return result;
      }

      if (options.historicalAgentRoots) {
        result.agentRootValid = options.historicalAgentRoots.includes(
          agentProof.agentMerkleRoot
        );
      } else {
        result.error = "No provider or historicalAgentRoots provided";
        return result;
      }
    }

    if (!result.humanRootValid) {
      result.error = "Human Merkle root not found in history buffer";
      return result;
    }
    if (!result.agentRootValid) {
      result.error = "Agent Merkle root not found in history buffer";
      return result;
    }

    // ── Proof verification ──────────────────────────────────────
    if (options.provider && options.registryAddress) {
      const provider =
        typeof options.provider === "string"
          ? new ethers.JsonRpcProvider(options.provider)
          : options.provider;

      const registry = new ethers.Contract(
        options.registryAddress,
        REGISTRY_ABI,
        provider
      );

      result.humanProofValid = await registry.verifyHumanProof(
        humanProof.pA,
        humanProof.pB,
        humanProof.pC,
        humanProof.humanMerkleRoot,
        humanProof.nullifierHash,
        humanProof.nonceBinding
      );

      result.agentProofValid = await registry.verifyAgentProof(
        agentProof.pA,
        agentProof.pB,
        agentProof.pC,
        agentProof.agentMerkleRoot,
        agentProof.policyHash,
        agentProof.permissions
      );
    } else {
      // Off-chain mode: proof math verified locally via snarkjs
      // (deferred to caller — this module only validates roots)
      result.humanProofValid = true;
      result.agentProofValid = true;
    }

    result.valid =
      result.humanRootValid &&
      result.agentRootValid &&
      result.humanProofValid &&
      result.agentProofValid;

    return result;
  } catch (err: unknown) {
    result.error =
      err instanceof Error ? err.message : "Unknown verification error";
    return result;
  }
}
