// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DelegationVerifier
 * @notice Groth16 verifier for the Delegation circuit v2.
 *
 * WARNING: This is a PLACEHOLDER verifier for development and testing.
 * In production, this file MUST be regenerated from the actual trusted
 * setup ceremony output using:
 *
 *   snarkjs groth16 setup delegation.r1cs pot16_final.ptau delegation_0000.zkey
 *   snarkjs zkey contribute delegation_0000.zkey delegation_final.zkey
 *   snarkjs zkey export solidityverifier delegation_final.zkey DelegationVerifier.sol
 *
 * The verifyProof function signature matches snarkjs output format.
 *
 * Public inputs (in order):
 *   [0] agentTreeRoot
 *   [1] scopeCommitment
 *   [2] nullifierHash
 */
contract DelegationVerifier {
    // ── Errors ───────────────────────────────────────────────────────────
    error InvalidProof();

    // ── Verification key points (PLACEHOLDER — replace after ceremony) ──
    // In production these are the elliptic curve points from the trusted setup.
    // The placeholder accepts proofs where a[0] != 0 for testing purposes.

    uint256 constant NUM_PUBLIC_INPUTS = 3;

    /**
     * @notice Verify a Groth16 proof for the Delegation circuit.
     * @param a Proof element A (2 field elements)
     * @param b Proof element B (2x2 field elements)
     * @param c Proof element C (2 field elements)
     * @param publicInputs The 3 public inputs: [agentTreeRoot, scopeCommitment, nullifierHash]
     * @return valid True if the proof is valid
     *
     * @dev PLACEHOLDER: In production, this performs the full pairing check.
     *      For testing, it checks basic structure and returns true for non-zero proofs.
     */
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata publicInputs
    ) external view returns (bool valid) {
        // Basic sanity: proof must not be all-zeros
        if (a[0] == 0 && a[1] == 0) revert InvalidProof();
        if (c[0] == 0 && c[1] == 0) revert InvalidProof();

        // In production, this is replaced by the full Groth16 pairing check:
        //   e(A, B) == e(alpha, beta) * e(sum(pub_i * vk_i), gamma) * e(C, delta)
        // The snarkjs-generated verifier handles this automatically.

        // Placeholder: all non-zero proofs are "valid" for integration testing
        return true;
    }
}
