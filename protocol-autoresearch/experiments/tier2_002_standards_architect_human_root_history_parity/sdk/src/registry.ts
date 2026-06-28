/**
 * @module registry
 * @description TS SDK client for the Bolyra IdentityRegistry contract.
 *
 * Exposes `isKnownHumanRoot()` and `isKnownAgentRoot()` for off-chain
 * staleness pre-flight checks before submitting proofs on-chain.
 */

import { ethers } from "ethers";

const REGISTRY_ABI = [
  "function isKnownHumanRoot(bytes32 root) view returns (bool)",
  "function isKnownAgentRoot(bytes32 root) view returns (bool)",
  "function currentHumanRoot() view returns (bytes32)",
  "function currentAgentRoot() view returns (bytes32)",
  "function humanRootHistoryIndex() view returns (uint256)",
  "function agentRootHistoryIndex() view returns (uint256)",
  "function ROOT_HISTORY_SIZE() view returns (uint256)",
];

export interface RegistryClientOptions {
  /** Ethereum JSON-RPC provider URL or ethers Provider instance */
  provider: ethers.Provider | string;
  /** Deployed IdentityRegistry contract address */
  registryAddress: string;
}

export interface RootStatus {
  /** Whether the root exists in the ring buffer */
  isKnown: boolean;
  /** The current root of the tree */
  currentRoot: string;
  /** The monotonically increasing write index */
  historyIndex: bigint;
  /** Ring buffer capacity */
  historySize: bigint;
}

/**
 * Lightweight client for querying the IdentityRegistry's root history
 * buffers. Use this for off-chain pre-flight checks before submitting
 * proofs to avoid wasting gas on stale-root reverts.
 *
 * @example
 * ```ts
 * import { RegistryClient } from "@bolyra/sdk";
 *
 * const client = new RegistryClient({
 *   provider: "https://sepolia.base.org",
 *   registryAddress: "0x...",
 * });
 *
 * const status = await client.checkHumanRoot(myProof.humanMerkleRoot);
 * if (!status.isKnown) {
 *   console.warn("Human root is stale — regenerate proof");
 * }
 * ```
 */
export class RegistryClient {
  private readonly contract: ethers.Contract;

  constructor(options: RegistryClientOptions) {
    const provider =
      typeof options.provider === "string"
        ? new ethers.JsonRpcProvider(options.provider)
        : options.provider;

    this.contract = new ethers.Contract(
      options.registryAddress,
      REGISTRY_ABI,
      provider
    );
  }

  /**
   * Check whether a human Merkle root exists in the 30-slot ring buffer.
   *
   * @param root - The humanMerkleRoot from the proof's public signals.
   * @returns true if the root is still in the history buffer.
   */
  async isKnownHumanRoot(root: string): Promise<boolean> {
    return this.contract.isKnownHumanRoot(root);
  }

  /**
   * Check whether an agent Merkle root exists in the 30-slot ring buffer.
   *
   * @param root - The agentMerkleRoot from the proof's public signals.
   * @returns true if the root is still in the history buffer.
   */
  async isKnownAgentRoot(root: string): Promise<boolean> {
    return this.contract.isKnownAgentRoot(root);
  }

  /**
   * Full pre-flight check for a human root: queries the buffer and
   * returns metadata about the current tree state.
   */
  async checkHumanRoot(root: string): Promise<RootStatus> {
    const [isKnown, currentRoot, historyIndex, historySize] =
      await Promise.all([
        this.contract.isKnownHumanRoot(root),
        this.contract.currentHumanRoot(),
        this.contract.humanRootHistoryIndex(),
        this.contract.ROOT_HISTORY_SIZE(),
      ]);

    return { isKnown, currentRoot, historyIndex, historySize };
  }

  /**
   * Full pre-flight check for an agent root: queries the buffer and
   * returns metadata about the current tree state.
   */
  async checkAgentRoot(root: string): Promise<RootStatus> {
    const [isKnown, currentRoot, historyIndex, historySize] =
      await Promise.all([
        this.contract.isKnownAgentRoot(root),
        this.contract.currentAgentRoot(),
        this.contract.agentRootHistoryIndex(),
        this.contract.ROOT_HISTORY_SIZE(),
      ]);

    return { isKnown, currentRoot, historyIndex, historySize };
  }
}
