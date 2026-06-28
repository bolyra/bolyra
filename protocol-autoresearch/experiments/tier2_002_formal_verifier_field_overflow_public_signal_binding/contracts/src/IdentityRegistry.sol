// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./IIdentityRegistry.sol";
import "./FieldBoundLib.sol";

/// @title  IdentityRegistry
/// @notice On-chain registry for Bolyra human and agent identities.
///         Maintains Merkle trees for both identity types with parallel
///         ROOT_HISTORY_SIZE ring buffers so that proofs generated against
///         recent-but-not-current roots remain valid.
/// @dev    All public signals that will be forwarded to snarkjs-generated
///         verifiers are validated against the BN254 scalar field modulus
///         via FieldBoundLib.assertInField() BEFORE any other logic.
contract IdentityRegistry is IIdentityRegistry {
    using FieldBoundLib for uint256;

    // ---------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------

    /// @notice BN254 scalar field modulus re-exported for external readers.
    uint256 public constant FIELD_MODULUS = FieldBoundLib.FIELD_MODULUS;

    /// @notice Number of historical roots retained per tree.
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    // ---------------------------------------------------------------
    // Verifier interfaces
    // ---------------------------------------------------------------

    IHumanUniquenessVerifier public immutable humanVerifier;
    IAgentPolicyVerifier    public immutable agentVerifier;
    IDelegationVerifier     public immutable delegationVerifier;

    // ---------------------------------------------------------------
    // Human tree state
    // ---------------------------------------------------------------

    bytes32 public currentHumanRoot;
    uint256 public humanEnrollmentCount;
    bytes32[30] public humanRootHistory;
    uint256 public humanRootHistoryIndex;
    mapping(bytes32 => bool) public humanNullifiers;

    // ---------------------------------------------------------------
    // Agent tree state
    // ---------------------------------------------------------------

    bytes32 public currentAgentRoot;
    uint256 public agentEnrollmentCount;
    bytes32[30] public agentRootHistory;
    uint256 public agentRootHistoryIndex;
    mapping(bytes32 => bool) public agentNullifiers;

    // ---------------------------------------------------------------
    // Nonce tracking
    // ---------------------------------------------------------------

    /// @notice Tracks consumed session nonces to prevent replay.
    mapping(uint256 => bool) public usedNonces;

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

    constructor(
        address _humanVerifier,
        address _agentVerifier,
        address _delegationVerifier
    ) {
        owner = msg.sender;
        humanVerifier     = IHumanUniquenessVerifier(_humanVerifier);
        agentVerifier     = IAgentPolicyVerifier(_agentVerifier);
        delegationVerifier = IDelegationVerifier(_delegationVerifier);
    }

    // ---------------------------------------------------------------
    // Human enrollment
    // ---------------------------------------------------------------

    function enrollHuman(
        bytes32 identityCommitment,
        bytes32 newRoot
    ) external onlyOwner {
        require(newRoot != bytes32(0), "IdentityRegistry: zero root");
        currentHumanRoot = newRoot;
        humanRootHistory[humanRootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
        humanRootHistoryIndex++;
        humanEnrollmentCount++;
        emit HumanEnrolled(identityCommitment, newRoot);
        emit HumanRootHistoryUpdated(newRoot, humanRootHistoryIndex - 1);
    }

    // ---------------------------------------------------------------
    // Agent enrollment
    // ---------------------------------------------------------------

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
    // Handshake verification (human + agent)
    // ---------------------------------------------------------------

    /// @notice Verify a mutual ZKP handshake between a human and an agent.
    /// @dev    Field-bound checks run FIRST — before nonce dedup, root
    ///         lookup, or verifier calls — to close the modular-wrap
    ///         attack vector.
    /// @param humanProof      Groth16 proof elements for HumanUniqueness.
    /// @param humanPubSignals Public signals for HumanUniqueness:
    ///        [0] nullifierHash, [1] nonceBinding, [2] humanMerkleRoot,
    ///        [3] externalNullifier, [4] sessionNonce
    /// @param agentProof      Groth16 proof elements for AgentPolicy.
    /// @param agentPubSignals Public signals for AgentPolicy:
    ///        [0] credentialHash, [1] nonceBinding, [2] agentMerkleRoot,
    ///        [3] currentTimestamp, [4] requiredPermissions, [5] sessionNonce
    function verifyHandshake(
        uint256[8] calldata humanProof,
        uint256[5] calldata humanPubSignals,
        uint256[8] calldata agentProof,
        uint256[6] calldata agentPubSignals
    ) external returns (bool) {
        // --- Field bound checks (human signals) ---
        for (uint256 i = 0; i < 5; i++) {
            humanPubSignals[i].assertInField();
        }
        // --- Field bound checks (agent signals) ---
        for (uint256 i = 0; i < 6; i++) {
            agentPubSignals[i].assertInField();
        }

        // --- Session nonce dedup ---
        uint256 sessionNonce = humanPubSignals[4];
        require(
            humanPubSignals[4] == agentPubSignals[5],
            "IdentityRegistry: nonce mismatch"
        );
        require(!usedNonces[sessionNonce], "IdentityRegistry: nonce reused");
        usedNonces[sessionNonce] = true;

        // --- Nullifier dedup ---
        bytes32 nullHash = bytes32(humanPubSignals[0]);
        require(
            !humanNullifiers[nullHash],
            "IdentityRegistry: nullifier already consumed"
        );
        humanNullifiers[nullHash] = true;

        // --- Root validity ---
        require(
            _isKnownHumanRoot(bytes32(humanPubSignals[2])),
            "IdentityRegistry: unknown human root"
        );
        require(
            _isKnownAgentRoot(bytes32(agentPubSignals[2])),
            "IdentityRegistry: unknown agent root"
        );

        // --- Verifier calls ---
        bool humanValid = humanVerifier.verifyProof(
            [humanProof[0], humanProof[1]],
            [[humanProof[2], humanProof[3]], [humanProof[4], humanProof[5]]],
            [humanProof[6], humanProof[7]],
            humanPubSignals
        );
        require(humanValid, "IdentityRegistry: human proof invalid");

        bool agentValid = agentVerifier.verifyProof(
            [agentProof[0], agentProof[1]],
            [[agentProof[2], agentProof[3]], [agentProof[4], agentProof[5]]],
            [agentProof[6], agentProof[7]],
            agentPubSignals
        );
        require(agentValid, "IdentityRegistry: agent proof invalid");

        emit HumanNullifierConsumed(nullHash);
        return true;
    }

    // ---------------------------------------------------------------
    // Delegation verification
    // ---------------------------------------------------------------

    /// @notice Verify a delegation proof.
    /// @param proof           Groth16 proof elements.
    /// @param pubSignals      Public signals for Delegation:
    ///        [0] delegationHash, [1] narrowedPermissions, [2] nonceBinding,
    ///        [3] delegationMerkleRoot, [4] currentTimestamp, [5] sessionNonce
    function verifyDelegation(
        uint256[8] calldata proof,
        uint256[6] calldata pubSignals
    ) external returns (bool) {
        // --- Field bound checks ---
        for (uint256 i = 0; i < 6; i++) {
            pubSignals[i].assertInField();
        }

        // --- Session nonce dedup ---
        uint256 sessionNonce = pubSignals[5];
        require(!usedNonces[sessionNonce], "IdentityRegistry: nonce reused");
        usedNonces[sessionNonce] = true;

        // --- Verifier call ---
        bool valid = delegationVerifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            pubSignals
        );
        require(valid, "IdentityRegistry: delegation proof invalid");

        return true;
    }

    // ---------------------------------------------------------------
    // Nullifier consumption (standalone)
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
    // Root validity — public view
    // ---------------------------------------------------------------

    function isKnownHumanRoot(
        bytes32 root
    ) external view override returns (bool) {
        return _isKnownHumanRoot(root);
    }

    function isKnownAgentRoot(
        bytes32 root
    ) external view override returns (bool) {
        return _isKnownAgentRoot(root);
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    function _isKnownHumanRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (humanRootHistory[i] == root) return true;
        }
        return false;
    }

    function _isKnownAgentRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (agentRootHistory[i] == root) return true;
        }
        return false;
    }
}

// ---------------------------------------------------------------
// Verifier interfaces (generated by snarkjs)
// ---------------------------------------------------------------

interface IHumanUniquenessVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[5] calldata _pubSignals
    ) external view returns (bool);
}

interface IAgentPolicyVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}

interface IDelegationVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}
