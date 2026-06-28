// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IIdentityRegistry
 * @notice Interface for the Bolyra on-chain identity registry.
 */
interface IIdentityRegistry {
    // ── Events ──────────────────────────────────────────────────────

    event HumanEnrolled(bytes32 indexed identityCommitment, bytes32 newRoot);
    event AgentEnrolled(bytes32 indexed agentCommitment, bytes32 newRoot);
    event HumanRootHistoryUpdated(bytes32 newRoot, uint256 historyIndex);
    event AgentRootHistoryUpdated(bytes32 newRoot, uint256 historyIndex);
    event HumanNullifierConsumed(bytes32 indexed nullifierHash);
    event AgentNullifierConsumed(bytes32 indexed nullifierHash);

    // ── Human enrollment ────────────────────────────────────────────

    function enrollHuman(
        bytes32 identityCommitment,
        bytes32 newRoot
    ) external;

    // ── Agent enrollment ────────────────────────────────────────────

    function enrollAgent(
        bytes32 agentCommitment,
        bytes32 newRoot
    ) external;

    // ── Proof verification ──────────────────────────────────────────

    function verifyHumanProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32 humanMerkleRoot,
        bytes32 nullifierHash,
        bytes32 nonceBinding
    ) external view returns (bool);

    function verifyAgentProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32 agentMerkleRoot,
        bytes32 policyHash,
        uint256 permissions
    ) external view returns (bool);

    // ── Root validity ───────────────────────────────────────────────

    /**
     * @notice Returns true if `root` exists in the 30-slot human root
     *         history ring buffer.
     */
    function isValidHumanRoot(bytes32 root) external view returns (bool);

    /**
     * @notice Returns true if `root` exists in the 30-slot agent root
     *         history ring buffer.
     */
    function isValidAgentRoot(bytes32 root) external view returns (bool);

    // ── Nullifier management ────────────────────────────────────────

    function consumeHumanNullifier(bytes32 nullifierHash) external;
    function consumeAgentNullifier(bytes32 nullifierHash) external;
}
