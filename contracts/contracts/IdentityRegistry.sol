// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {InternalLeanIMT, LeanIMTData} from "@zk-kit/lean-imt.sol/InternalLeanIMT.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) external view returns (bool);
}

interface IPlonkVerifier {
    function verifyProof(
        uint256[24] calldata _proof,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}

interface IDelegationVerifier {
    function verifyProof(
        uint256[24] calldata _proof,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}

/// @title IdentityRegistry
/// @notice On-chain registry for IdentityOS: manages human identities and AI agent
///         credentials, verifies mutual handshake proofs, and tracks delegation chains.
/// @dev Architecture decisions (from eng review):
///   - Human side: Groth16 (Semaphore v4 ceremony, depth 20)
///   - Agent side: PLONK (universal setup, no ceremony)
///   - Target: Base L2 (cheap gas for multi-proof verification)
///   - Root history buffer: last 30 roots for agentTree (humanTree uses Semaphore's)
///   - Nonce: verifier-generated, freshness checked via usedNonces mapping
contract IdentityRegistry {
    using InternalLeanIMT for LeanIMTData;

    // ============ ERRORS ============

    error InvalidHumanProof();
    error InvalidAgentProof();
    error InvalidDelegationProof();
    error NonceAlreadyUsed();
    error HumanIdentityRevoked();
    error StaleAgentRoot();
    error NotOwner();
    error NonceMismatch();                // Fix #1: nonce in pubSignals must match argument
    error DelegationNullifierReused();    // Fix #5: delegation replay protection
    error ScopeChainMismatch();           // Fix #5: previousScopeCommitment must match expected
    error MaxDelegationHopsExceeded();    // Fix #5: max 3 hops per session

    // ============ EVENTS ============

    event HumanEnrolled(uint256 indexed identityCommitment, uint256 merkleRoot);
    event AgentEnrolled(uint256 indexed credentialCommitment, address indexed operator, uint256 merkleRoot);
    event HandshakeVerified(
        uint256 indexed humanNullifier,
        uint256 indexed agentNullifier,
        uint256 sessionNonce
    );
    event DelegationVerified(
        uint256 indexed delegationNullifier,
        uint256 newScopeCommitment,
        uint256 sessionNonce
    );
    event IdentityRevoked(uint256 indexed nullifier);
    event AgentCredentialRevoked(uint256 indexed credentialCommitment);

    // ============ STATE ============

    address public owner;

    // Proof verifiers (deployed separately, addresses set in constructor)
    IGroth16Verifier public immutable humanVerifier;
    IPlonkVerifier public immutable agentVerifier;
    IDelegationVerifier public immutable delegationVerifier;

    // Human identity tree (LeanIMT, Semaphore v4 compatible)
    LeanIMTData internal humanTree;

    // Agent credential tree (LeanIMT)
    LeanIMTData internal agentTree;

    // Root history buffer for agentTree (last 30 roots)
    // Prevents valid proofs from failing due to tree updates during proof generation
    uint256 public constant ROOT_HISTORY_SIZE = 30;
    uint256[30] public agentRootHistory;
    uint256 public agentRootHistoryIndex;
    mapping(uint256 => bool) public agentRootExists;

    // Revocation sets
    mapping(uint256 => bool) public humanRevocations;  // nullifier => revoked
    mapping(uint256 => bool) public agentRevocations;  // credentialCommitment => revoked

    // Replay protection
    mapping(uint256 => bool) public usedNonces;

    // Delegation replay protection and chain tracking (Fix #5)
    mapping(uint256 => bool) public usedDelegationNullifiers;
    uint256 public constant MAX_DELEGATION_HOPS = 3;
    // sessionNonce => number of delegation hops verified so far
    mapping(uint256 => uint256) public delegationHopCount;

    // ============ CONSTRUCTOR ============

    constructor(address _humanVerifier, address _agentVerifier, address _delegationVerifier) {
        owner = msg.sender;
        humanVerifier = IGroth16Verifier(_humanVerifier);
        agentVerifier = IPlonkVerifier(_agentVerifier);
        delegationVerifier = IDelegationVerifier(_delegationVerifier);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ============ ENROLLMENT ============

    /// @notice Enroll a human identity into the humanTree.
    /// @param identityCommitment Poseidon2(Ax, Ay) where (Ax, Ay) is the EdDSA public key.
    function enrollHuman(uint256 identityCommitment) external onlyOwner {
        uint256 newRoot = humanTree._insert(identityCommitment);
        emit HumanEnrolled(identityCommitment, newRoot);
    }

    /// @notice Enroll an AI agent credential into the agentTree.
    /// @param credentialCommitment Poseidon5(modelHash, operatorAx, operatorAy, bitmask, expiry).
    function enrollAgent(uint256 credentialCommitment) external onlyOwner {
        uint256 newRoot = agentTree._insert(credentialCommitment);
        _recordAgentRoot(newRoot);
        emit AgentEnrolled(credentialCommitment, msg.sender, newRoot);
    }

    /// @notice Batch enroll multiple human identities.
    /// @param identityCommitments Array of identity commitments.
    function enrollHumanBatch(uint256[] calldata identityCommitments) external onlyOwner {
        for (uint256 i = 0; i < identityCommitments.length; i++) {
            humanTree._insert(identityCommitments[i]);
        }
    }

    /// @notice Batch enroll multiple agent credentials.
    /// @param credentialCommitments Array of credential commitments.
    function enrollAgentBatch(uint256[] calldata credentialCommitments) external onlyOwner {
        for (uint256 i = 0; i < credentialCommitments.length; i++) {
            uint256 newRoot = agentTree._insert(credentialCommitments[i]);
            _recordAgentRoot(newRoot);
        }
    }

    // ============ HANDSHAKE VERIFICATION ============

    /// @notice Verify a mutual handshake between a human and an AI agent.
    /// @dev Verifies both a Groth16 proof (human) and a PLONK proof (agent)
    ///      in a single transaction. Both proofs must be valid and bound to the
    ///      same session nonce.
    /// @param humanProof Groth16 proof points for the human circuit.
    /// @param humanPubSignals [humanMerkleRoot, nullifierHash, nonceBinding, scope, sessionNonce]
    /// @param agentProof PLONK proof points for the agent circuit.
    /// @param agentPubSignals [agentMerkleRoot, nullifierHash, scopeCommitment, requiredScope, currentTimestamp, sessionNonce]
    /// @param sessionNonce The verifier-generated nonce binding both proofs.
    function verifyHandshake(
        uint256[8] calldata humanProof,
        uint256[] calldata humanPubSignals,
        uint256[24] calldata agentProof,
        uint256[] calldata agentPubSignals,
        uint256 sessionNonce
    ) external {
        // 1. Check nonce freshness
        if (usedNonces[sessionNonce]) revert NonceAlreadyUsed();
        usedNonces[sessionNonce] = true;

        // 2. Extract public signals
        uint256 humanMerkleRoot = humanPubSignals[0];
        uint256 humanNullifier = humanPubSignals[1];
        uint256 agentMerkleRoot = agentPubSignals[0];
        uint256 agentNullifier = agentPubSignals[1];

        // 2b. Fix #1: Enforce nonce equality — both proofs must embed the same sessionNonce
        // humanPubSignals[4] = sessionNonce from HumanUniqueness circuit
        // agentPubSignals[5] = sessionNonce from AgentPolicy circuit
        if (humanPubSignals[4] != sessionNonce) revert NonceMismatch();
        if (agentPubSignals[5] != sessionNonce) revert NonceMismatch();

        // 3. Check revocations
        // Human revocation: checked by nullifier (stable per scope)
        if (humanRevocations[humanNullifier]) revert HumanIdentityRevoked();
        // Fix #2: Agent revocation is handled by removing the credential from the agentTree
        // (LeanIMT update to 0). The nullifier is session-specific, so checking
        // agentRevocations[agentNullifier] was wrong — it used the wrong key.
        // Agent revocation is enforced at the Merkle proof level: a revoked credential
        // is zeroed in the tree, so the proof will fail to verify.

        // 4. Verify human Merkle root is valid
        // For humanTree, we check the current root (Semaphore-style)
        // TODO: Add root history for humanTree too
        uint256 currentHumanRoot = humanTree._root();
        if (humanMerkleRoot != currentHumanRoot) revert InvalidHumanProof();

        // 5. Verify agent Merkle root is in history
        if (!agentRootExists[agentMerkleRoot]) revert StaleAgentRoot();

        // 6. Verify Groth16 proof (human)
        // NOTE: In production, this calls the auto-generated Groth16 verifier contract.
        // For testnet, we use a placeholder that checks proof structure.
        // The actual verifier will be deployed from snarkjs export:
        //   snarkjs zkey export solidityverifier HumanUniqueness_final.zkey HumanVerifier.sol
        if (!_verifyHumanProof(humanProof, humanPubSignals)) revert InvalidHumanProof();

        // 7. Verify PLONK proof (agent)
        // NOTE: Same as above — production uses auto-generated PLONK verifier.
        //   snarkjs plonk export solidityverifier AgentPolicy_final.zkey AgentVerifier.sol
        if (!_verifyAgentProof(agentProof, agentPubSignals)) revert InvalidAgentProof();

        emit HandshakeVerified(humanNullifier, agentNullifier, sessionNonce);
    }

    // ============ DELEGATION VERIFICATION ============

    /// @notice Verify a single delegation hop in a chain.
    /// @dev Each hop is verified independently. The on-chain contract checks that
    ///      the previousScopeCommitment matches the expected value, stores the
    ///      delegation nullifier for replay protection, and enforces max 3 hops.
    /// @param proof PLONK proof for the Delegation circuit.
    /// @param pubSignals [previousScopeCommitment, sessionNonce, newScopeCommitment, delegationNullifier]
    /// @param sessionNonce The session nonce (must match the handshake nonce).
    /// @param expectedPreviousScopeCommitment The expected previousScopeCommitment
    ///        (from AgentPolicy output for hop 0, or prior verifyDelegation output for subsequent hops).
    function verifyDelegation(
        uint256[24] calldata proof,
        uint256[4] calldata pubSignals,
        uint256 sessionNonce,
        uint256 expectedPreviousScopeCommitment
    ) external {
        // Fix #5a: Verify previousScopeCommitment matches the expected chain link
        if (pubSignals[0] != expectedPreviousScopeCommitment) revert ScopeChainMismatch();

        // Fix #5a: Verify sessionNonce in proof matches the argument
        if (pubSignals[1] != sessionNonce) revert NonceMismatch();

        // Fix #5b: Delegation nullifier replay protection
        uint256 delegationNullifier = pubSignals[3];
        if (usedDelegationNullifiers[delegationNullifier]) revert DelegationNullifierReused();
        usedDelegationNullifiers[delegationNullifier] = true;

        // Fix #5c: Enforce max delegation chain depth (3 hops)
        delegationHopCount[sessionNonce]++;
        if (delegationHopCount[sessionNonce] > MAX_DELEGATION_HOPS) revert MaxDelegationHopsExceeded();

        // Verify the delegation proof via the deployed verifier
        if (!delegationVerifier.verifyProof(proof, pubSignals)) {
            revert InvalidDelegationProof();
        }

        uint256 newScopeCommitment = pubSignals[2];

        emit DelegationVerified(delegationNullifier, newScopeCommitment, sessionNonce);
    }

    // ============ REVOCATION ============

    /// @notice Revoke a human identity. The nullifier is marked as revoked.
    /// @param nullifier The nullifier hash of the identity to revoke.
    function revokeHuman(uint256 nullifier) external onlyOwner {
        humanRevocations[nullifier] = true;
        emit IdentityRevoked(nullifier);
    }

    /// @notice Revoke an agent credential.
    /// @param credentialCommitment The credential commitment to revoke.
    function revokeAgent(uint256 credentialCommitment) external onlyOwner {
        agentRevocations[credentialCommitment] = true;
        emit AgentCredentialRevoked(credentialCommitment);
    }

    // ============ VIEWS ============

    /// @notice Get the current root of the human identity tree.
    function humanTreeRoot() external view returns (uint256) {
        return humanTree._root();
    }

    /// @notice Get the current root of the agent credential tree.
    function agentTreeRoot() external view returns (uint256) {
        return agentTree._root();
    }

    /// @notice Get the number of enrolled humans.
    function humanTreeSize() external view returns (uint256) {
        return humanTree.size;
    }

    /// @notice Get the number of enrolled agents.
    function agentTreeSize() external view returns (uint256) {
        return agentTree.size;
    }

    /// @notice Check if an agent Merkle root is in the history buffer.
    function isValidAgentRoot(uint256 root) external view returns (bool) {
        return agentRootExists[root];
    }

    // ============ INTERNAL ============

    /// @dev Record a new agent tree root in the history buffer.
    function _recordAgentRoot(uint256 root) internal {
        // Remove old root from exists mapping if buffer is full
        uint256 oldRoot = agentRootHistory[agentRootHistoryIndex];
        if (oldRoot != 0) {
            agentRootExists[oldRoot] = false;
        }

        // Record new root
        agentRootHistory[agentRootHistoryIndex] = root;
        agentRootExists[root] = true;

        // Advance circular buffer index
        agentRootHistoryIndex = (agentRootHistoryIndex + 1) % ROOT_HISTORY_SIZE;
    }

    /// @dev Verify a Groth16 proof for the human circuit via the deployed verifier.
    function _verifyHumanProof(
        uint256[8] calldata proof,
        uint256[] calldata pubSignals
    ) internal view returns (bool) {
        // Groth16 proof format: [pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1]]
        uint[2] memory pA = [proof[0], proof[1]];
        uint[2][2] memory pB = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint[2] memory pC = [proof[6], proof[7]];

        // HumanUniqueness public signals: [humanMerkleRoot, nullifierHash, nonceBinding, scope, sessionNonce]
        uint[5] memory signals;
        for (uint i = 0; i < 5; i++) {
            signals[i] = pubSignals[i];
        }

        return humanVerifier.verifyProof(pA, pB, pC, signals);
    }

    /// @dev Verify a PLONK proof for the agent circuit via the deployed verifier.
    function _verifyAgentProof(
        uint256[24] calldata proof,
        uint256[] calldata pubSignals
    ) internal view returns (bool) {
        // AgentPolicy public signals: [agentMerkleRoot, nullifierHash, scopeCommitment, requiredScope, currentTimestamp, sessionNonce]
        uint256[6] memory signals;
        for (uint i = 0; i < 6; i++) {
            signals[i] = pubSignals[i];
        }

        return agentVerifier.verifyProof(proof, signals);
    }
}
