// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./HumanUniquenessVerifier.sol";
import "./AgentPolicyVerifier.sol";

/// @title  BolyraVerifier
/// @notice On-chain handshake verifier that binds both HumanUniqueness and
///         AgentPolicy proofs to the current chain via block.chainid.
/// @dev    After the chainId-binding circuit upgrade, both proofs expose
///         chainId as a public signal. This contract asserts that both
///         match block.chainid before forwarding to the snarkjs-generated
///         Groth16 verifiers.
contract BolyraVerifier {
    IHumanUniquenessVerifier public immutable humanVerifier;
    IAgentPolicyVerifier public immutable agentVerifier;

    error ChainIdMismatch(uint256 expected, uint256 got);
    error HumanProofInvalid();
    error AgentProofInvalid();

    constructor(
        address _humanVerifier,
        address _agentVerifier
    ) {
        humanVerifier = IHumanUniquenessVerifier(_humanVerifier);
        agentVerifier = IAgentPolicyVerifier(_agentVerifier);
    }

    /// @notice Verify a mutual handshake between a human and an agent.
    /// @param humanProof   Groth16 proof for HumanUniqueness circuit.
    /// @param humanPubSignals Public signals for HumanUniqueness:
    ///        [0] = nullifierHash
    ///        [1] = nonceBinding
    ///        [2] = humanMerkleRoot
    ///        [3] = externalNullifier
    ///        [4] = sessionNonce
    ///        [5] = chainId
    /// @param agentProof   Groth16 proof for AgentPolicy circuit.
    /// @param agentPubSignals Public signals for AgentPolicy:
    ///        [0] = credentialHash
    ///        [1] = nonceBinding
    ///        [2] = agentMerkleRoot
    ///        [3] = currentTimestamp
    ///        [4] = requiredPermissions
    ///        [5] = sessionNonce
    ///        [6] = chainId
    function verifyHandshake(
        uint256[8] calldata humanProof,
        uint256[6] calldata humanPubSignals,
        uint256[8] calldata agentProof,
        uint256[7] calldata agentPubSignals
    ) external view returns (bool) {
        // --- Chain ID enforcement ---
        uint256 humanChainId = humanPubSignals[5];
        uint256 agentChainId = agentPubSignals[6];

        if (humanChainId != block.chainid) {
            revert ChainIdMismatch(block.chainid, humanChainId);
        }
        if (agentChainId != block.chainid) {
            revert ChainIdMismatch(block.chainid, agentChainId);
        }

        // --- Snarkjs verifier calls ---
        bool humanValid = humanVerifier.verifyProof(
            [humanProof[0], humanProof[1]],
            [[humanProof[2], humanProof[3]], [humanProof[4], humanProof[5]]],
            [humanProof[6], humanProof[7]],
            humanPubSignals
        );
        if (!humanValid) revert HumanProofInvalid();

        bool agentValid = agentVerifier.verifyProof(
            [agentProof[0], agentProof[1]],
            [[agentProof[2], agentProof[3]], [agentProof[4], agentProof[5]]],
            [agentProof[6], agentProof[7]],
            agentPubSignals
        );
        if (!agentValid) revert AgentProofInvalid();

        return true;
    }
}

interface IHumanUniquenessVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[6] calldata _pubSignals
    ) external view returns (bool);
}

interface IAgentPolicyVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[7] calldata _pubSignals
    ) external view returns (bool);
}
