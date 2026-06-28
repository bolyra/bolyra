// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IHumanVerifier
 * @notice Interface for the HumanUniqueness ZK proof verifier.
 *
 * Public signals (v3.0.0, two-nullifier architecture):
 *   [0] identityTreeRoot              - Merkle root of the human identity tree
 *   [1] nullifierHash                 - per-session nullifier (replay prevention)
 *   [2] scope                         - application scope identifier
 *   [3] externalNullifierCommitment   - stable commitment (sybil/revocation gating)
 */
interface IHumanVerifier {
    /**
     * @notice Verify a Groth16 or PLONK proof for HumanUniqueness.
     * @param proof The serialized proof bytes.
     * @param publicSignals The four public signals:
     *        [identityTreeRoot, nullifierHash, scope, externalNullifierCommitment]
     * @return valid True if the proof is valid.
     */
    function verifyProof(
        bytes calldata proof,
        uint256[4] memory publicSignals
    ) external view returns (bool valid);
}
