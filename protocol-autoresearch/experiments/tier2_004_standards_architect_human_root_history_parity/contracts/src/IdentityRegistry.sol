// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./IIdentityRegistry.sol";

/// @title  IdentityRegistry
/// @notice On-chain registry for Bolyra human and agent identities.
///         Maintains Merkle trees for both identity types with parallel
///         ROOT_HISTORY_SIZE ring buffers so that proofs generated against
///         recent-but-not-current roots remain valid.
/// @dev    Both humanTree and agentTree share the same buffer depth (30).
///         The buffer prevents in-flight proofs from going stale when
///         new enrollments land between proof generation and verification.
contract IdentityRegistry is IIdentityRegistry {
    // ---------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------

    /// @notice Number of historical roots retained per tree.
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    // ---------------------------------------------------------------
    // Human tree state
    // ---------------------------------------------------------------

    /// @notice Current human Merkle tree root.
    bytes32 public currentHumanRoot;

    /// @notice Total number of human enrollments.
    uint256 public humanEnrollmentCount;

    /// @notice Circular buffer of recent human tree roots.
    bytes32[30] public humanRootHistory;

    /// @notice Write index into humanRootHistory (monotonically increasing).
    uint256 public humanRootHistoryIndex;

    /// @notice Nullifier tracking for human proofs.
    mapping(bytes32 => bool) public humanNullifiers;

    // ---------------------------------------------------------------
    // Agent tree state
    // ---------------------------------------------------------------

    /// @notice Current agent Merkle tree root.
    bytes32 public currentAgentRoot;

    /// @notice Total number of agent registrations.
    uint256 public agentEnrollmentCount;

    /// @notice Circular buffer of recent agent tree roots.
    bytes32[30] public agentRootHistory;

    /// @notice Write index into agentRootHistory (monotonically increasing).
    uint256 public agentRootHistoryIndex;

    /// @notice Nullifier tracking for agent proofs.
    mapping(bytes32 => bool) public agentNullifiers;

    // ---------------------------------------------------------------
    // Owner
    // ---------------------------------------------------------------

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "IdentityRegistry: caller is not owner");
        _;
    }

    // ---------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------

    constructor() {
        owner = msg.sender;
    }

    // ---------------------------------------------------------------
    // Human enrollment
    // ---------------------------------------------------------------

    /// @notice Enroll a new human identity commitment into the tree.
    /// @param identityCommitment Poseidon hash of the user's secret.
    /// @param newRoot The new Merkle root after inserting the commitment.
    function enrollHuman(
        bytes32 identityCommitment,
        bytes32 newRoot
    ) external onlyOwner {
        require(newRoot != bytes32(0), "IdentityRegistry: zero root");

        currentHumanRoot = newRoot;

        // Push new root into circular buffer
        humanRootHistory[humanRootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
        humanRootHistoryIndex++;
        humanEnrollmentCount++;

        emit HumanEnrolled(identityCommitment, newRoot);
        emit HumanRootHistoryUpdated(newRoot, humanRootHistoryIndex - 1);
    }

    // ---------------------------------------------------------------
    // Agent enrollment
    // ---------------------------------------------------------------

    /// @notice Register a new agent credential into the tree.
    /// @param agentCommitment Hash of the agent's credential.
    /// @param newRoot The new Merkle root after inserting the credential.
    function enrollAgent(
        bytes32 agentCommitment,
        bytes32 newRoot
    ) external onlyOwner {
        require(newRoot != bytes32(0), "IdentityRegistry: zero root");

        currentAgentRoot = newRoot;

        agentRootHistory[agentRootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
        agentRootHistoryIndex++;
        agentEnrollmentCount++;

        emit AgentEnrolled(agentCommitment, newRoot);
        emit AgentRootHistoryUpdated(newRoot, agentRootHistoryIndex - 1);
    }

    // ---------------------------------------------------------------
    // Root validity — public view (implements IIdentityRegistry)
    // ---------------------------------------------------------------

    /// @inheritdoc IIdentityRegistry
    function isKnownHumanRoot(
        bytes32 root
    ) external view override returns (bool) {
        return _isKnownHumanRoot(root);
    }

    /// @inheritdoc IIdentityRegistry
    function isKnownAgentRoot(
        bytes32 root
    ) external view override returns (bool) {
        return _isKnownAgentRoot(root);
    }

    // ---------------------------------------------------------------
    // Nullifier consumption
    // ---------------------------------------------------------------

    function consumeHumanNullifier(
        bytes32 nullifierHash
    ) external onlyOwner {
        require(
            !humanNullifiers[nullifierHash],
            "IdentityRegistry: nullifier already consumed"
        );
        humanNullifiers[nullifierHash] = true;
        emit HumanNullifierConsumed(nullifierHash);
    }

    function consumeAgentNullifier(
        bytes32 nullifierHash
    ) external onlyOwner {
        require(
            !agentNullifiers[nullifierHash],
            "IdentityRegistry: nullifier already consumed"
        );
        agentNullifiers[nullifierHash] = true;
        emit AgentNullifierConsumed(nullifierHash);
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// @dev Iterate humanRootHistory looking for a matching root.
    function _isKnownHumanRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (humanRootHistory[i] == root) return true;
        }
        return false;
    }

    /// @dev Iterate agentRootHistory looking for a matching root.
    function _isKnownAgentRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (agentRootHistory[i] == root) return true;
        }
        return false;
    }
}
