// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title BolyraSessionAnchor
 * @notice Minimal anchoring contract for off-chain session token checkpoints.
 *         Stores a mapping of sessionRoot → block.timestamp for periodic
 *         tamper-evident audit trails. No ZK verification — anchoring only.
 */
contract BolyraSessionAnchor {
    /// @notice Emitted when a new checkpoint is recorded.
    event CheckpointRecorded(
        bytes32 indexed sessionRoot,
        uint64 indexed epoch,
        uint256 timestamp
    );

    /// @notice Maps (sessionRoot, epoch) → block.timestamp. Non-zero means recorded.
    mapping(bytes32 => mapping(uint64 => uint256)) public checkpoints;

    /**
     * @notice Record a batch checkpoint for a set of active sessions.
     * @param sessionRoot keccak256 of sorted session nonces.
     * @param epoch Application-defined epoch counter (e.g., checkpoint sequence number).
     * @dev Reverts if a checkpoint for this (sessionRoot, epoch) pair already exists.
     */
    function batchCheckpoint(bytes32 sessionRoot, uint64 epoch) external {
        require(
            checkpoints[sessionRoot][epoch] == 0,
            "BolyraSessionAnchor: checkpoint already recorded for this root and epoch"
        );

        checkpoints[sessionRoot][epoch] = block.timestamp;

        emit CheckpointRecorded(sessionRoot, epoch, block.timestamp);
    }

    /**
     * @notice Look up the timestamp for a previously recorded checkpoint.
     * @param sessionRoot The session root that was checkpointed.
     * @param epoch The epoch of the checkpoint.
     * @return timestamp The block.timestamp when the checkpoint was recorded, or 0 if not found.
     */
    function getCheckpoint(bytes32 sessionRoot, uint64 epoch) external view returns (uint256) {
        return checkpoints[sessionRoot][epoch];
    }
}
