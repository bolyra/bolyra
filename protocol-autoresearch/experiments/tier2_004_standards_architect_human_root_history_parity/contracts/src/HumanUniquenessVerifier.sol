// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title  HumanUniquenessVerifier (stub)
/// @notice Always-true stub for testing. In production this is the
///         snarkjs-generated Groth16 verifier for HumanUniqueness.circom.
contract HumanUniquenessVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external pure returns (bool) {
        return true;
    }
}
