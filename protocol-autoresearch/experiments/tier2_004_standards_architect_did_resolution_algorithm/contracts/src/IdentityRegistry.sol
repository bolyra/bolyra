// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IdentityRegistry
/// @notice On-chain registry for Bolyra identity commitments (human and agent).
/// @dev Stores registration records keyed by Poseidon commitment. Supports
///      DID resolution via the getRegistration() view function.
contract IdentityRegistry {
    enum KeyType {
        Human,  // 0 — Semaphore v4 identity commitment
        Agent   // 1 — EdDSA Baby Jubjub credential commitment
    }

    struct Registration {
        KeyType keyType;
        bytes publicKey;      // 64 bytes (x || y) for agents; empty for humans
        bytes32 merkleRoot;   // Semaphore tree root at registration time
        uint256 timestamp;    // block.timestamp of registration
        bool active;          // false after revocation
    }

    /// @notice Emitted when a new identity commitment is registered.
    /// @param commitment The Poseidon commitment (indexed for log filtering)
    /// @param keyType     0 = human, 1 = agent
    /// @param publicKey   Baby Jubjub public key bytes (empty for humans)
    /// @param merkleRoot  Merkle root at registration time
    event RegistrationRecorded(
        bytes32 indexed commitment,
        KeyType keyType,
        bytes publicKey,
        bytes32 merkleRoot
    );

    /// @notice Emitted when an identity commitment is revoked.
    /// @param commitment The Poseidon commitment (indexed for log filtering)
    event RegistrationRevoked(
        bytes32 indexed commitment
    );

    mapping(bytes32 => Registration) private _registrations;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "IdentityRegistry: caller is not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register a new identity commitment.
    /// @param commitment  The Poseidon commitment to register
    /// @param keyType     Subject type (Human or Agent)
    /// @param publicKey   Baby Jubjub pubkey bytes for agents; empty for humans
    /// @param merkleRoot  Current Semaphore tree root
    function register(
        bytes32 commitment,
        KeyType keyType,
        bytes calldata publicKey,
        bytes32 merkleRoot
    ) external onlyOwner {
        require(
            _registrations[commitment].timestamp == 0,
            "IdentityRegistry: already registered"
        );
        if (keyType == KeyType.Agent) {
            require(publicKey.length == 64, "IdentityRegistry: agent key must be 64 bytes");
        }

        _registrations[commitment] = Registration({
            keyType: keyType,
            publicKey: publicKey,
            merkleRoot: merkleRoot,
            timestamp: block.timestamp,
            active: true
        });

        emit RegistrationRecorded(commitment, keyType, publicKey, merkleRoot);
    }

    /// @notice Revoke (deactivate) an existing registration.
    /// @param commitment The Poseidon commitment to revoke
    function revoke(bytes32 commitment) external onlyOwner {
        require(
            _registrations[commitment].timestamp != 0,
            "IdentityRegistry: not registered"
        );
        require(
            _registrations[commitment].active,
            "IdentityRegistry: already revoked"
        );

        _registrations[commitment].active = false;

        emit RegistrationRevoked(commitment);
    }

    /// @notice Query a registration record for DID resolution.
    /// @param commitment The Poseidon commitment to look up
    /// @return keyType    Subject type enum
    /// @return publicKey  Baby Jubjub pubkey bytes (empty for humans)
    /// @return merkleRoot Merkle root at registration time
    /// @return timestamp  Block timestamp of registration (0 if not found)
    /// @return active     Whether the registration is still active
    function getRegistration(bytes32 commitment)
        external
        view
        returns (
            KeyType keyType,
            bytes memory publicKey,
            bytes32 merkleRoot,
            uint256 timestamp,
            bool active
        )
    {
        Registration storage reg = _registrations[commitment];
        return (
            reg.keyType,
            reg.publicKey,
            reg.merkleRoot,
            reg.timestamp,
            reg.active
        );
    }
}
