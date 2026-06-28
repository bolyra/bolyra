// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./interfaces/IIdentityRegistry.sol";
import "./verifiers/HumanUniquenessVerifier.sol";
import "./verifiers/AgentPolicyVerifier.sol";
import "./verifiers/DelegationVerifier.sol";

/**
 * @title IdentityRegistry
 * @notice On-chain registry for Bolyra human and agent identities.
 *         Maintains Merkle trees for both identity types with 30-root
 *         history buffers to tolerate concurrent enrollment races.
 */
contract IdentityRegistry is IIdentityRegistry {
    // ── Human tree ──────────────────────────────────────────────────
    uint256 public humanTreeDepth;
    bytes32 public currentHumanRoot;
    mapping(bytes32 => bool) public humanNullifiers;
    uint256 public humanEnrollmentCount;

    /// @notice Ring buffer storing the last 30 human Merkle roots.
    bytes32[30] public humanRootHistory;
    /// @notice Write pointer into humanRootHistory (monotonically increasing).
    uint256 public humanRootHistoryIndex;

    // ── Agent tree ──────────────────────────────────────────────────
    uint256 public agentTreeDepth;
    bytes32 public currentAgentRoot;
    mapping(bytes32 => bool) public agentNullifiers;
    uint256 public agentEnrollmentCount;

    bytes32[30] public agentRootHistory;
    uint256 public agentRootHistoryIndex;

    // ── Verifier contracts ──────────────────────────────────────────
    HumanUniquenessVerifier public immutable humanVerifier;
    AgentPolicyVerifier public immutable agentVerifier;
    DelegationVerifier public immutable delegationVerifier;

    // ── Owner ───────────────────────────────────────────────────────
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "IdentityRegistry: caller is not owner");
        _;
    }

    constructor(
        address _humanVerifier,
        address _agentVerifier,
        address _delegationVerifier,
        uint256 _humanTreeDepth,
        uint256 _agentTreeDepth
    ) {
        owner = msg.sender;
        humanVerifier = HumanUniquenessVerifier(_humanVerifier);
        agentVerifier = AgentPolicyVerifier(_agentVerifier);
        delegationVerifier = DelegationVerifier(_delegationVerifier);
        humanTreeDepth = _humanTreeDepth;
        agentTreeDepth = _agentTreeDepth;
    }

    // ── Human enrollment ────────────────────────────────────────────

    function enrollHuman(
        bytes32 identityCommitment,
        bytes32 newRoot
    ) external onlyOwner {
        require(newRoot != bytes32(0), "IdentityRegistry: zero root");

        currentHumanRoot = newRoot;

        // Push into ring buffer
        humanRootHistory[humanRootHistoryIndex % 30] = newRoot;
        humanRootHistoryIndex++;
        humanEnrollmentCount++;

        emit HumanEnrolled(identityCommitment, newRoot);
        emit HumanRootHistoryUpdated(newRoot, humanRootHistoryIndex - 1);
    }

    // ── Agent enrollment ────────────────────────────────────────────

    function enrollAgent(
        bytes32 agentCommitment,
        bytes32 newRoot
    ) external onlyOwner {
        require(newRoot != bytes32(0), "IdentityRegistry: zero root");

        currentAgentRoot = newRoot;

        agentRootHistory[agentRootHistoryIndex % 30] = newRoot;
        agentRootHistoryIndex++;
        agentEnrollmentCount++;

        emit AgentEnrolled(agentCommitment, newRoot);
        emit AgentRootHistoryUpdated(newRoot, agentRootHistoryIndex - 1);
    }

    // ── Human proof verification ────────────────────────────────────

    function verifyHumanProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32 humanMerkleRoot,
        bytes32 nullifierHash,
        bytes32 nonceBinding
    ) external view override returns (bool) {
        require(
            _isValidHumanRoot(humanMerkleRoot),
            "IdentityRegistry: unknown human root"
        );
        require(
            !humanNullifiers[nullifierHash],
            "IdentityRegistry: nullifier already used"
        );

        uint256[3] memory pubSignals;
        pubSignals[0] = uint256(humanMerkleRoot);
        pubSignals[1] = uint256(nullifierHash);
        pubSignals[2] = uint256(nonceBinding);

        return humanVerifier.verifyProof(pA, pB, pC, pubSignals);
    }

    // ── Agent proof verification ────────────────────────────────────

    function verifyAgentProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32 agentMerkleRoot,
        bytes32 policyHash,
        uint256 permissions
    ) external view override returns (bool) {
        require(
            _isValidAgentRoot(agentMerkleRoot),
            "IdentityRegistry: unknown agent root"
        );

        uint256[3] memory pubSignals;
        pubSignals[0] = uint256(agentMerkleRoot);
        pubSignals[1] = uint256(policyHash);
        pubSignals[2] = permissions;

        return agentVerifier.verifyProof(pA, pB, pC, pubSignals);
    }

    // ── Root validity helpers ───────────────────────────────────────

    /**
     * @notice Check whether `root` appears in the 30-slot human root
     *         history ring buffer.
     */
    function _isValidHumanRoot(
        bytes32 root
    ) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < 30; i++) {
            if (humanRootHistory[i] == root) return true;
        }
        return false;
    }

    /**
     * @notice Check whether `root` appears in the 30-slot agent root
     *         history ring buffer.
     */
    function _isValidAgentRoot(
        bytes32 root
    ) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < 30; i++) {
            if (agentRootHistory[i] == root) return true;
        }
        return false;
    }

    // ── Public view wrappers ────────────────────────────────────────

    /// @inheritdoc IIdentityRegistry
    function isValidHumanRoot(
        bytes32 root
    ) external view override returns (bool) {
        return _isValidHumanRoot(root);
    }

    /// @inheritdoc IIdentityRegistry
    function isValidAgentRoot(
        bytes32 root
    ) external view override returns (bool) {
        return _isValidAgentRoot(root);
    }

    // ── Nullifier consumption (called after successful verify) ──────

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
}
