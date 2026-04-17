// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRootHistory} from "./IRootHistory.sol";

/**
 * @title DelegationRegistry
 * @notice On-chain registry for Bolyra delegation proofs.
 *         Validates that the agentTreeRoot used in the ZK proof is known
 *         to the IdentityRegistry's root history buffer, preventing
 *         phantom delegatee attacks.
 *
 * @dev The registry stores delegation records and prevents replay via
 *      nullifier tracking. The DelegationVerifier contract handles the
 *      actual Groth16 proof verification.
 */
contract DelegationRegistry {
    // ── Errors ───────────────────────────────────────────────────────────
    error UnknownAgentRoot(uint256 root);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error ZeroRoot();
    error NotOperator();

    // ── Events ───────────────────────────────────────────────────────────
    event DelegationSubmitted(
        bytes32 indexed nullifierHash,
        uint256 indexed agentTreeRoot,
        uint256 scopeCommitment
    );

    // ── Structs ──────────────────────────────────────────────────────────
    struct DelegationProof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256 agentTreeRoot;
        uint256 scopeCommitment;
        bytes32 nullifierHash;
    }

    // ── State ────────────────────────────────────────────────────────────
    address public operator;
    IRootHistory public rootHistory;
    address public verifier;

    /// @notice Tracks used nullifiers to prevent replay attacks.
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Tracks submitted delegations by nullifier for lookups.
    mapping(bytes32 => uint256) public delegationScopeCommitments;

    // ── Constructor ──────────────────────────────────────────────────────
    constructor(address _rootHistory, address _verifier) {
        operator = msg.sender;
        rootHistory = IRootHistory(_rootHistory);
        verifier = _verifier;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    // ── Core Logic ───────────────────────────────────────────────────────

    /**
     * @notice Submit a delegation proof for on-chain registration.
     * @param proof The delegation proof struct containing Groth16 proof
     *              elements and public inputs.
     *
     * @dev Validation steps:
     *   1. agentTreeRoot must be non-zero
     *   2. agentTreeRoot must exist in the IdentityRegistry's root history buffer
     *   3. nullifierHash must not have been used before
     *   4. Groth16 proof must verify (delegated to DelegationVerifier)
     *
     * The agentTreeRoot check is the critical fix for the phantom delegatee
     * vulnerability (CVE-BOLYRA-2026-001). Without it, an attacker could
     * submit a proof with a fabricated delegateeCredCommitment that is not
     * in any valid agent tree.
     */
    function submitDelegation(DelegationProof calldata proof) external {
        // 1. Zero-root guard
        if (proof.agentTreeRoot == 0) revert ZeroRoot();

        // 2. Validate agentTreeRoot against the shared root history buffer.
        //    This ensures the delegatee's credential commitment was actually
        //    enrolled in the agent tree at some recent point in time.
        if (!rootHistory.isValidAgentRoot(proof.agentTreeRoot)) {
            revert UnknownAgentRoot(proof.agentTreeRoot);
        }

        // 3. Nullifier replay protection
        if (nullifierUsed[proof.nullifierHash]) {
            revert NullifierAlreadyUsed(proof.nullifierHash);
        }

        // 4. Verify Groth16 proof (via external verifier contract)
        //    Public inputs: [agentTreeRoot, scopeCommitment, nullifierHash]
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])",
                proof.a,
                proof.b,
                proof.c,
                [proof.agentTreeRoot, proof.scopeCommitment, uint256(proof.nullifierHash)]
            )
        );
        if (!success || (result.length > 0 && !abi.decode(result, (bool)))) {
            revert InvalidProof();
        }

        // 5. Record delegation
        nullifierUsed[proof.nullifierHash] = true;
        delegationScopeCommitments[proof.nullifierHash] = proof.scopeCommitment;

        emit DelegationSubmitted(
            proof.nullifierHash,
            proof.agentTreeRoot,
            proof.scopeCommitment
        );
    }

    // ── Views ────────────────────────────────────────────────────────────

    /**
     * @notice Check if a delegation exists for a given nullifier.
     * @param nullifier The nullifier hash to check.
     * @return exists True if a delegation has been submitted with this nullifier.
     */
    function isDelegationSubmitted(bytes32 nullifier) external view returns (bool exists) {
        return nullifierUsed[nullifier];
    }

    /**
     * @notice Get the scope commitment for a submitted delegation.
     * @param nullifier The nullifier hash of the delegation.
     * @return scopeCommitment The scope commitment (0 if not found).
     */
    function getScopeCommitment(bytes32 nullifier) external view returns (uint256 scopeCommitment) {
        return delegationScopeCommitments[nullifier];
    }
}
