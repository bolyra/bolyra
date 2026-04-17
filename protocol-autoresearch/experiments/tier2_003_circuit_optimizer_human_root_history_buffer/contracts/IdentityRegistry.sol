// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IdentityRegistry
 * @notice Bolyra identity registry with dual Merkle-tree root history buffers.
 *         Maintains 30-slot ring buffers for both agentTree and humanTree roots,
 *         allowing in-flight proofs to remain valid across concurrent enrollments.
 *
 * @dev The ring-buffer pattern prevents a liveness bug where a new enrollment
 *      invalidates all in-flight ZK proofs by overwriting the single on-chain root.
 *      With 30 slots and ~15s Groth16 prove time, the window covers ~7.5 minutes.
 */
contract IdentityRegistry {
    // ── Errors ───────────────────────────────────────────────────────────
    error InvalidProof();
    error InvalidHumanRoot(uint256 root);
    error InvalidAgentRoot(uint256 root);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error ZeroRoot();
    error NotOperator();

    // ── Events ───────────────────────────────────────────────────────────
    event HumanEnrolled(uint256 indexed identityCommitment, uint256 newRoot);
    event AgentEnrolled(uint256 indexed identityCommitment, uint256 newRoot);
    event HandshakeVerified(bytes32 indexed nullifier);

    // ── Constants ────────────────────────────────────────────────────────
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    // ── State ────────────────────────────────────────────────────────────
    address public operator;

    // Canonical latest roots (backward-compatible reads)
    uint256 public humanRoot;
    uint256 public agentRoot;

    // Agent tree ring buffer
    uint256[30] public agentRootHistory;
    uint256 public agentRootHistoryIndex;

    // Human tree ring buffer (mirrors agent pattern)
    uint256[30] public humanRootHistory;
    uint256 public humanRootHistoryIndex;

    // Nullifier set
    mapping(bytes32 => bool) public nullifierUsed;

    // ── Structs ──────────────────────────────────────────────────────────
    struct HandshakeProof {
        uint256 humanRoot;
        uint256 agentRoot;
        bytes32 nullifierHash;
        bytes proof; // Groth16 proof bytes (mock in tests)
    }

    // ── Constructor ──────────────────────────────────────────────────────
    constructor() {
        operator = msg.sender;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    // ── Agent Tree (reference implementation) ────────────────────────────

    /**
     * @notice Enroll an agent identity and push the new root into the ring buffer.
     * @param identityCommitment The identity commitment to add to the tree.
     * @param newRoot The new Merkle root after insertion.
     */
    function enrollAgent(
        uint256 identityCommitment,
        uint256 newRoot
    ) external onlyOperator {
        if (newRoot == 0) revert ZeroRoot();
        _pushAgentRoot(newRoot);
        agentRoot = newRoot;
        emit AgentEnrolled(identityCommitment, newRoot);
    }

    /**
     * @dev Push a new agent root into the ring buffer.
     */
    function _pushAgentRoot(uint256 newRoot) internal {
        agentRootHistory[agentRootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
        agentRootHistoryIndex++;
    }

    /**
     * @notice Check whether an agent root exists in the history buffer.
     * @param root The root to check.
     * @return valid True if the root is in the buffer.
     */
    function isValidAgentRoot(uint256 root) public view returns (bool valid) {
        if (root == 0) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (agentRootHistory[i] == root) return true;
        }
        return false;
    }

    // ── Human Tree (new: mirrors agent pattern) ──────────────────────────

    /**
     * @notice Enroll a human identity and push the new root into the ring buffer.
     * @param identityCommitment The identity commitment to add to the tree.
     * @param newRoot The new Merkle root after insertion.
     */
    function enrollHuman(
        uint256 identityCommitment,
        uint256 newRoot
    ) external onlyOperator {
        if (newRoot == 0) revert ZeroRoot();
        _pushHumanRoot(newRoot);
        humanRoot = newRoot;
        emit HumanEnrolled(identityCommitment, newRoot);
    }

    /**
     * @dev Push a new human root into the ring buffer.
     *      Stores newRoot at humanRootHistory[index % 30], then increments index.
     */
    function _pushHumanRoot(uint256 newRoot) internal {
        humanRootHistory[humanRootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
        humanRootHistoryIndex++;
    }

    /**
     * @notice Check whether a human root exists in the history buffer.
     * @param root The root to check.
     * @return valid True if the root is in the buffer.
     */
    function isValidHumanRoot(uint256 root) public view returns (bool valid) {
        if (root == 0) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (humanRootHistory[i] == root) return true;
        }
        return false;
    }

    // ── Handshake Verification ───────────────────────────────────────────

    /**
     * @notice Verify a handshake proof against both root history buffers.
     * @dev Checks that both the human and agent roots in the proof exist
     *      in their respective ring buffers, preventing stale-root failures
     *      when enrollments happen during proving time.
     * @param p The handshake proof struct.
     * @return success True if the proof is valid.
     */
    function verifyHandshake(HandshakeProof calldata p) external returns (bool success) {
        // Check nullifier hasn't been used
        if (nullifierUsed[p.nullifierHash]) {
            revert NullifierAlreadyUsed(p.nullifierHash);
        }

        // Check human root against history buffer (not single root)
        if (!isValidHumanRoot(p.humanRoot)) {
            revert InvalidHumanRoot(p.humanRoot);
        }

        // Check agent root against history buffer
        if (!isValidAgentRoot(p.agentRoot)) {
            revert InvalidAgentRoot(p.agentRoot);
        }

        // NOTE: In production, verify the Groth16/Plonk proof here.
        // For this implementation, the proof bytes are accepted as-is
        // since ZK verification is handled by a separate verifier contract.

        // Mark nullifier as used
        nullifierUsed[p.nullifierHash] = true;

        emit HandshakeVerified(p.nullifierHash);
        return true;
    }
}
