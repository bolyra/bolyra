// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IdentityRegistry
 * @notice On-chain registry for Bolyra mutual ZKP handshakes.
 *
 * Maintains dual Merkle-tree history buffers (human + agent roots, 30 deep),
 * tracks nullifier and nonce consumption, and delegates proof verification
 * to external Groth16/PLONK verifier contracts.
 *
 * Custom errors are designed for SDK-side interpolation — each carries the
 * parameters needed to construct a BolyraError with a useful hint.
 */

import {IGroth16Verifier} from "./interfaces/IGroth16Verifier.sol";

contract IdentityRegistry {
    /* -------------------------------------------------------------- */
    /*  Custom Errors                                                  */
    /* -------------------------------------------------------------- */

    /// @notice The provided Merkle root is behind the on-chain head.
    /// @param providedBlock Block number at which the root was valid.
    /// @param latestBlock   Current head block number.
    error StaleRoot(uint256 providedBlock, uint256 latestBlock);

    /// @notice The nullifier has already been spent in a prior handshake.
    /// @param nullifier The spent nullifier hash.
    error NullifierSpent(bytes32 nullifier);

    /// @notice The delegated scope bits do not satisfy the required scope.
    /// @param required Bitmask the verifier expects.
    /// @param provided Bitmask the proof carries.
    error ScopeMismatch(uint8 required, uint8 provided);

    /// @notice The ZK proof failed on-chain verification.
    error InvalidProof();

    /// @notice The session nonce has already been consumed.
    /// @param nonce The reused nonce.
    error NonceAlreadyUsed(bytes32 nonce);

    /// @notice The agent credential has expired.
    /// @param expiry The credential's expiry timestamp.
    error CredentialExpired(uint256 expiry);

    /// @notice Caller is not authorized for this operation.
    error Unauthorized();

    /// @notice The provided Merkle root is not in the history buffer.
    /// @param root The unknown root.
    error RootNotFound(bytes32 root);

    /* -------------------------------------------------------------- */
    /*  Constants                                                      */
    /* -------------------------------------------------------------- */

    uint256 public constant ROOT_HISTORY_SIZE = 30;

    /* -------------------------------------------------------------- */
    /*  State                                                          */
    /* -------------------------------------------------------------- */

    address public owner;

    IGroth16Verifier public humanVerifier;
    IGroth16Verifier public agentVerifier;
    IGroth16Verifier public delegationVerifier;

    // Merkle root history buffers (ring buffers of size ROOT_HISTORY_SIZE)
    bytes32[30] public humanRootHistory;
    uint256 public humanRootIndex;
    bytes32[30] public agentRootHistory;
    uint256 public agentRootIndex;

    // Nullifier and nonce tracking
    mapping(bytes32 => bool) public nullifierSpent;
    mapping(bytes32 => bool) public nonceUsed;

    /* -------------------------------------------------------------- */
    /*  Events                                                        */
    /* -------------------------------------------------------------- */

    event HandshakeVerified(
        bytes32 indexed humanNullifier,
        bytes32 indexed agentNullifier,
        bytes32 sessionNonce
    );

    event RootUpdated(bool indexed isHuman, bytes32 newRoot);

    /* -------------------------------------------------------------- */
    /*  Constructor                                                    */
    /* -------------------------------------------------------------- */

    constructor(
        address _humanVerifier,
        address _agentVerifier,
        address _delegationVerifier
    ) {
        owner = msg.sender;
        humanVerifier = IGroth16Verifier(_humanVerifier);
        agentVerifier = IGroth16Verifier(_agentVerifier);
        delegationVerifier = IGroth16Verifier(_delegationVerifier);
    }

    /* -------------------------------------------------------------- */
    /*  Modifiers                                                      */
    /* -------------------------------------------------------------- */

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /* -------------------------------------------------------------- */
    /*  Root Management                                                */
    /* -------------------------------------------------------------- */

    function updateHumanRoot(bytes32 newRoot) external onlyOwner {
        humanRootIndex = (humanRootIndex + 1) % ROOT_HISTORY_SIZE;
        humanRootHistory[humanRootIndex] = newRoot;
        emit RootUpdated(true, newRoot);
    }

    function updateAgentRoot(bytes32 newRoot) external onlyOwner {
        agentRootIndex = (agentRootIndex + 1) % ROOT_HISTORY_SIZE;
        agentRootHistory[agentRootIndex] = newRoot;
        emit RootUpdated(false, newRoot);
    }

    function latestHumanRoot() external view returns (bytes32) {
        return humanRootHistory[humanRootIndex];
    }

    function latestAgentRoot() external view returns (bytes32) {
        return agentRootHistory[agentRootIndex];
    }

    function isKnownHumanRoot(bytes32 root) public view returns (bool) {
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (humanRootHistory[i] == root) return true;
        }
        return false;
    }

    function isKnownAgentRoot(bytes32 root) public view returns (bool) {
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (agentRootHistory[i] == root) return true;
        }
        return false;
    }

    /* -------------------------------------------------------------- */
    /*  Handshake Verification                                         */
    /* -------------------------------------------------------------- */

    /**
     * @notice Verify a mutual ZKP handshake atomically.
     * @param humanProof   Groth16 proof for HumanUniqueness circuit.
     * @param humanSignals Public signals: [humanMerkleRoot, nullifierHash, nonceBinding].
     * @param agentProof   Groth16 proof for AgentPolicy circuit.
     * @param agentSignals Public signals: [agentMerkleRoot, agentNullifier, scopeCommitment, nonceBinding].
     * @param sessionNonce Fresh nonce binding both proofs.
     */
    function verifyHandshake(
        uint256[8] calldata humanProof,
        uint256[3] calldata humanSignals,
        uint256[8] calldata agentProof,
        uint256[4] calldata agentSignals,
        bytes32 sessionNonce
    ) external {
        // 1. Nonce freshness
        if (nonceUsed[sessionNonce]) revert NonceAlreadyUsed(sessionNonce);
        nonceUsed[sessionNonce] = true;

        // 2. Root membership
        bytes32 humanRoot = bytes32(humanSignals[0]);
        if (!isKnownHumanRoot(humanRoot)) revert RootNotFound(humanRoot);

        bytes32 agentRoot = bytes32(agentSignals[0]);
        if (!isKnownAgentRoot(agentRoot)) revert RootNotFound(agentRoot);

        // 3. Nullifier uniqueness
        bytes32 humanNullifier = bytes32(humanSignals[1]);
        if (nullifierSpent[humanNullifier]) revert NullifierSpent(humanNullifier);
        nullifierSpent[humanNullifier] = true;

        bytes32 agentNullifier = bytes32(agentSignals[1]);
        if (nullifierSpent[agentNullifier]) revert NullifierSpent(agentNullifier);
        nullifierSpent[agentNullifier] = true;

        // 4. Proof verification
        bool humanValid = humanVerifier.verifyProof(
            [humanProof[0], humanProof[1]],
            [[humanProof[2], humanProof[3]], [humanProof[4], humanProof[5]]],
            [humanProof[6], humanProof[7]],
            [humanSignals[0], humanSignals[1], humanSignals[2]]
        );
        if (!humanValid) revert InvalidProof();

        bool agentValid = agentVerifier.verifyProof(
            [agentProof[0], agentProof[1]],
            [[agentProof[2], agentProof[3]], [agentProof[4], agentProof[5]]],
            [agentProof[6], agentProof[7]],
            [agentSignals[0], agentSignals[1], agentSignals[2], agentSignals[3]]
        );
        if (!agentValid) revert InvalidProof();

        emit HandshakeVerified(humanNullifier, agentNullifier, sessionNonce);
    }
}
