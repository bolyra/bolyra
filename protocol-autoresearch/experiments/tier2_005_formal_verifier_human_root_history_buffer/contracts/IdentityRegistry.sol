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
 *
 *      Both buffers use O(1) mapping lookups (rootExists) rather than linear scans
 *      for gas-efficient verification. The mapping is kept in sync with the ring
 *      buffer via explicit eviction of the overwritten slot on each push.
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
    event HumanRootAdded(uint256 indexed newRoot, uint256 slot);
    event AgentEnrolled(uint256 indexed identityCommitment, uint256 newRoot);
    event AgentRootAdded(uint256 indexed newRoot, uint256 slot);
    event HandshakeVerified(bytes32 indexed nullifier);

    // ── Constants ────────────────────────────────────────────────────────
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    // ── State ────────────────────────────────────────────────────────────
    address public operator;

    // Canonical latest roots (backward-compatible reads for off-chain indexing)
    uint256 public humanRoot;
    uint256 public agentRoot;

    // Agent tree ring buffer
    uint256[30] public agentRootHistory;
    uint256 public agentRootHistoryIndex;
    mapping(uint256 => bool) public agentRootExists;

    // Human tree ring buffer (mirrors agent pattern)
    uint256[30] public humanRootHistory;
    uint256 public humanRootHistoryIndex;
    mapping(uint256 => bool) public humanRootExists;

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

    // ── Agent Tree ──────────────────────────────────────────────────────

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
     *      Evicts the oldest root from the mapping, writes the new root,
     *      and marks it as valid in the mapping for O(1) lookup.
     */
    function _pushAgentRoot(uint256 newRoot) internal {
        uint256 slot = agentRootHistoryIndex % ROOT_HISTORY_SIZE;
        uint256 expiredRoot = agentRootHistory[slot];

        // Evict expired root from O(1) mapping (zero is never set true)
        if (expiredRoot != 0) {
            agentRootExists[expiredRoot] = false;
        }

        // Write new root into ring buffer and mapping
        agentRootHistory[slot] = newRoot;
        agentRootExists[newRoot] = true;
        agentRootHistoryIndex++;

        emit AgentRootAdded(newRoot, slot);
    }

    /**
     * @notice Check whether an agent root exists in the history buffer.
     * @param root The root to check.
     * @return valid True if the root is in the buffer.
     */
    function isValidAgentRoot(uint256 root) public view returns (bool valid) {
        if (root == 0) return false;
        return agentRootExists[root];
    }

    // ── Human Tree (mirrors agent pattern) ──────────────────────────────

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
     *      Evicts the oldest root from the mapping, writes the new root,
     *      and marks it as valid in the mapping for O(1) lookup.
     */
    function _pushHumanRoot(uint256 newRoot) internal {
        uint256 slot = humanRootHistoryIndex % ROOT_HISTORY_SIZE;
        uint256 expiredRoot = humanRootHistory[slot];

        // Evict expired root from O(1) mapping (zero is never set true)
        if (expiredRoot != 0) {
            humanRootExists[expiredRoot] = false;
        }

        // Write new root into ring buffer and mapping
        humanRootHistory[slot] = newRoot;
        humanRootExists[newRoot] = true;
        humanRootHistoryIndex++;

        emit HumanRootAdded(newRoot, slot);
    }

    /**
     * @notice Check whether a human root exists in the history buffer.
     * @param root The root to check.
     * @return valid True if the root is in the buffer.
     */
    function isValidHumanRoot(uint256 root) public view returns (bool valid) {
        if (root == 0) return false;
        return humanRootExists[root];
    }

    // ── Handshake Verification ───────────────────────────────────────────

    /**
     * @notice Verify a handshake proof against both root history buffers.
     * @dev Checks that both the human and agent roots in the proof exist
     *      in their respective ring buffers via O(1) mapping lookups,
     *      preventing stale-root failures when enrollments happen during
     *      proving time.
     * @param p The handshake proof struct.
     * @return success True if the proof is valid.
     */
    function verifyHandshake(HandshakeProof calldata p) external returns (bool success) {
        if (nullifierUsed[p.nullifierHash]) {
            revert NullifierAlreadyUsed(p.nullifierHash);
        }

        if (!isValidHumanRoot(p.humanRoot)) {
            revert InvalidHumanRoot(p.humanRoot);
        }

        if (!isValidAgentRoot(p.agentRoot)) {
            revert InvalidAgentRoot(p.agentRoot);
        }

        // NOTE: In production, verify the Groth16/Plonk proof here.
        // ZK verification is handled by a separate verifier contract.

        nullifierUsed[p.nullifierHash] = true;

        emit HandshakeVerified(p.nullifierHash);
        return true;
    }
}
