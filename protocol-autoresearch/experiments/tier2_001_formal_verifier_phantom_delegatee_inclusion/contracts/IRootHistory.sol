// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IRootHistory
 * @notice Shared interface for root history validation.
 *         Implemented by IdentityRegistry; consumed by DelegationRegistry
 *         and any other contract that needs to validate Merkle roots against
 *         the on-chain ring buffer.
 */
interface IRootHistory {
    /// @notice Check whether an agent tree root exists in the history buffer.
    /// @param root The root to validate.
    /// @return valid True if the root is currently in the buffer.
    function isValidAgentRoot(uint256 root) external view returns (bool valid);

    /// @notice Check whether a human tree root exists in the history buffer.
    /// @param root The root to validate.
    /// @return valid True if the root is currently in the buffer.
    function isValidHumanRoot(uint256 root) external view returns (bool valid);
}
