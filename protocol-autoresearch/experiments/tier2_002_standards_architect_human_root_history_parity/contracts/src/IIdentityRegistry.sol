// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IIdentityRegistry
 * @notice Interface for the Bolyra on-chain identity registry.
 *         Both human and agent trees maintain a 30-root ring buffer
 *         (ROOT_HISTORY_SIZE) so in-flight proofs survive concurrent
 *         enrollments.
 */
interface IIdentityRegistry {
    // ── Events ──────────────────────────────────────────────────────

    event HumanEnrolled(bytes32 indexed identityCommitment, bytes32 newRoot);
    event AgentEnrolled(bytes32 indexed agentCommitment, bytes32 newRoot);

    /// @notice Emitted when a new human root is pushed into the ring buffer.
    /// @param newRoot      The freshly computed Merkle root.
    /// @param historyIndex The monotonically increasing write index.
    event HumanRootHistoryUpdated(bytes32 newRoot, uint256 historyIndex);

    /// @notice Emitted when a new agent root is pushed into the ring buffer.
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

    // ── Root validity ───────────────────────────────────────────────

    /**
     * @notice Returns true if `root` exists in the 30-slot human root
     *         history ring buffer.
     * @dev    Verifiers MUST call this before accepting a human proof.
     *         A root that has been evicted from the buffer indicates
     *         that the proof is stale and MUST be rejected.
     */
    function isKnownHumanRoot(bytes32 root) external view returns (bool);

    /**
     * @notice Returns true if `root` exists in the 30-slot agent root
     *         history ring buffer.
     */
    function isKnownAgentRoot(bytes32 root) external view returns (bool);

    // ── Nullifier management ────────────────────────────────────────

    function consumeHumanNullifier(bytes32 nullifierHash) external;
    function consumeAgentNullifier(bytes32 nullifierHash) external;
}
