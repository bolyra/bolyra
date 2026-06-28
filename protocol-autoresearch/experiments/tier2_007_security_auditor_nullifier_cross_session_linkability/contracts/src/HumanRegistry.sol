// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./IHumanVerifier.sol";

/**
 * @title HumanRegistry
 * @notice On-chain registry for Bolyra human uniqueness proofs.
 *
 * Two-nullifier architecture (v3.0.0):
 *   - sessionNullifier (per-session, unlinkable): prevents replay of the same proof.
 *   - externalNullifierCommitment (stable, per-identity): enables sybil gating
 *     and revocation without revealing the raw nullifier.
 *
 * Verifiers see sessionNullifier (unique each time) and cannot link sessions.
 * The registry stores externalNullifierCommitment for uniqueness/revocation.
 */
contract HumanRegistry {
    /// @notice The on-chain verifier contract for HumanUniqueness proofs.
    IHumanVerifier public immutable verifier;

    /// @notice Accepted Merkle roots for identity trees.
    mapping(uint256 => bool) public acceptedRoots;

    /// @notice Session nullifiers already consumed (replay prevention).
    mapping(uint256 => bool) public sessionNullifiers;

    /// @notice Registered external nullifier commitments (sybil gating).
    mapping(uint256 => bool) public registeredCommitments;

    /// @notice Revoked external nullifier commitments.
    mapping(uint256 => bool) public revokedCommitments;

    /// @notice Admin address for root management.
    address public admin;

    // ── Events ───────────────────────────────────────────────────────
    event RootAdded(uint256 indexed root);
    event RootRemoved(uint256 indexed root);
    event HandshakeVerified(
        uint256 indexed sessionNullifier,
        uint256 indexed externalNullifierCommitment,
        uint256 scope
    );
    event CommitmentRevoked(uint256 indexed externalNullifierCommitment);

    // ── Errors ───────────────────────────────────────────────────────
    error InvalidProof();
    error RootNotAccepted();
    error SessionNullifierAlreadyUsed();
    error CommitmentRevoked_();
    error NotAdmin();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(address _verifier) {
        verifier = IHumanVerifier(_verifier);
        admin = msg.sender;
    }

    // ── Root management ──────────────────────────────────────────────

    function addRoot(uint256 root) external onlyAdmin {
        acceptedRoots[root] = true;
        emit RootAdded(root);
    }

    function removeRoot(uint256 root) external onlyAdmin {
        acceptedRoots[root] = false;
        emit RootRemoved(root);
    }

    // ── Proof verification ───────────────────────────────────────────

    /**
     * @notice Verify a HumanUniqueness proof and register the session.
     * @param proof The Groth16/PLONK proof bytes.
     * @param identityTreeRoot The Merkle root of the identity tree.
     * @param sessionNullifier The per-session nullifier (unique each handshake).
     * @param scope The application scope identifier.
     * @param externalNullifierCommitment The stable identity commitment for sybil gating.
     */
    function verifyAndRegister(
        bytes calldata proof,
        uint256 identityTreeRoot,
        uint256 sessionNullifier,
        uint256 scope,
        uint256 externalNullifierCommitment
    ) external {
        // 1. Check root is accepted
        if (!acceptedRoots[identityTreeRoot]) revert RootNotAccepted();

        // 2. Check session nullifier has not been used (replay prevention)
        if (sessionNullifiers[sessionNullifier]) revert SessionNullifierAlreadyUsed();

        // 3. Check commitment is not revoked
        if (revokedCommitments[externalNullifierCommitment]) revert CommitmentRevoked_();

        // 4. Verify the ZK proof against public signals
        //    Public signals order: [identityTreeRoot, nullifierHash, scope, externalNullifierCommitment]
        uint256[4] memory publicSignals = [
            identityTreeRoot,
            sessionNullifier,
            scope,
            externalNullifierCommitment
        ];

        bool valid = verifier.verifyProof(proof, publicSignals);
        if (!valid) revert InvalidProof();

        // 5. Mark session nullifier as consumed
        sessionNullifiers[sessionNullifier] = true;

        // 6. Register commitment (idempotent — same identity can handshake again)
        registeredCommitments[externalNullifierCommitment] = true;

        emit HandshakeVerified(sessionNullifier, externalNullifierCommitment, scope);
    }

    // ── Revocation ───────────────────────────────────────────────────

    /**
     * @notice Revoke an external nullifier commitment.
     * @dev Only admin can revoke. Future: governance or ZK-proven self-revocation.
     * @param commitment The externalNullifierCommitment to revoke.
     */
    function revokeCommitment(uint256 commitment) external onlyAdmin {
        revokedCommitments[commitment] = true;
        emit CommitmentRevoked(commitment);
    }

    // ── View helpers ─────────────────────────────────────────────────

    function isSessionUsed(uint256 sessionNullifier) external view returns (bool) {
        return sessionNullifiers[sessionNullifier];
    }

    function isCommitmentRegistered(uint256 commitment) external view returns (bool) {
        return registeredCommitments[commitment];
    }

    function isCommitmentRevoked(uint256 commitment) external view returns (bool) {
        return revokedCommitments[commitment];
    }
}
