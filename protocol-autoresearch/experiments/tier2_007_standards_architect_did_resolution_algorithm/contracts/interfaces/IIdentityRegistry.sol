// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IIdentityRegistry
/// @notice Minimal read interface for the Bolyra IdentityRegistry.
/// @dev Exposes the view functions required by the did:bolyra resolution algorithm.
/// See spec/did-resolution-algorithm.md for the query pattern.
interface IIdentityRegistry {
    /// @notice Enrollment record for a human identity commitment.
    struct EnrollmentStatus {
        bool enrolled;
        uint256[2] publicKey; // BabyJubJub (x, y)
        uint256 blockNumber;  // Block at which enrollment was confirmed
    }

    /// @notice Credential record for an AI agent identity.
    struct AgentCredential {
        bytes32 agentId;
        bytes32 modelHash;
        uint256[2] operatorPubKey; // BabyJubJub (x, y)
        uint8 permissions;         // 8-bit cumulative encoding
        uint256 expiry;            // Unix timestamp; 0 = no expiry
    }

    /// @notice Returns the enrollment status for a human identity commitment.
    /// @param commitment The Poseidon hash identity commitment.
    /// @return status The enrollment record. `enrolled` is false if the commitment
    ///         has never been registered.
    function getEnrollmentStatus(bytes32 commitment)
        external
        view
        returns (EnrollmentStatus memory status);

    /// @notice Returns the current Merkle root of the identity tree.
    /// @return root The current Semaphore v4 Merkle tree root.
    function getMerkleRoot() external view returns (uint256 root);

    /// @notice Checks whether an identity commitment has been revoked.
    /// @param commitment The identity commitment to check.
    /// @return revoked True if the identity has been revoked via nullifier publication.
    function isRevoked(bytes32 commitment) external view returns (bool revoked);

    /// @notice Returns the agent credential associated with a commitment.
    /// @param commitment The keccak256(agentId) commitment.
    /// @return credential The agent credential record. `agentId` is bytes32(0)
    ///         if no agent is registered at this commitment.
    function getAgentCredential(bytes32 commitment)
        external
        view
        returns (AgentCredential memory credential);
}
