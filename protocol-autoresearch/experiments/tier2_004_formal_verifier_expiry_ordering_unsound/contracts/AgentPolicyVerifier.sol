// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AgentPolicyVerifier
 * @notice Groth16 verifier for the AgentPolicy circuit v1.
 *
 * WARNING: This is a PLACEHOLDER verifier for development and testing.
 * In production, this file MUST be regenerated from the actual trusted
 * setup ceremony output using:
 *
 *   snarkjs groth16 setup AgentPolicy.r1cs pot16_final.ptau agentpolicy_0000.zkey
 *   snarkjs zkey contribute agentpolicy_0000.zkey agentpolicy_final.zkey
 *   snarkjs zkey export solidityverifier agentpolicy_final.zkey AgentPolicyVerifier.sol
 *
 * Public inputs (in order):
 *   [0] agentTreeRoot
 *   [1] nullifierHash
 *   [2] currentTimestamp
 *   [3] expiryTimestamp
 *
 * IMPORTANT: Expiry is now enforced IN-CIRCUIT via LessThan(64).
 * The verifier contract does NOT need to re-check currentTimestamp < expiryTimestamp
 * because the proof itself is invalid if this ordering is violated.
 *
 * The contract SHOULD still verify:
 *   - currentTimestamp is within an acceptable freshness window
 *     (e.g., block.timestamp - 300 <= currentTimestamp <= block.timestamp)
 *   - agentTreeRoot is in the root history buffer
 *   - nullifierHash has not been spent
 */
contract AgentPolicyVerifier {
    // ── Errors ───────────────────────────────────────────────────────────
    error InvalidProof();
    error TimestampTooOld();
    error TimestampInFuture();
    error UnknownRoot();
    error NullifierAlreadySpent();

    uint256 constant NUM_PUBLIC_INPUTS = 4;
    uint256 constant FRESHNESS_WINDOW = 300; // 5 minutes

    // ── State ─────────────────────────────────────────────────────────────
    mapping(uint256 => bool) public spentNullifiers;

    // Root history interface (to be injected via constructor in production)
    // For now, accept any non-zero root in placeholder mode.

    /**
     * @notice Verify a Groth16 proof for the AgentPolicy circuit.
     * @param a Proof element A (2 field elements)
     * @param b Proof element B (2x2 field elements)
     * @param c Proof element C (2 field elements)
     * @param publicInputs [agentTreeRoot, nullifierHash, currentTimestamp, expiryTimestamp]
     * @return valid True if the proof is valid
     *
     * @dev Expiry ordering (currentTimestamp < expiryTimestamp) is enforced
     *      by the circuit's LessThan(64) constraint. A valid proof guarantees
     *      this invariant. The contract only needs to check timestamp freshness
     *      relative to block.timestamp.
     *
     * @dev PLACEHOLDER: In production, this performs the full pairing check.
     */
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata publicInputs
    ) external returns (bool valid) {
        // Basic sanity: proof must not be all-zeros
        if (a[0] == 0 && a[1] == 0) revert InvalidProof();
        if (c[0] == 0 && c[1] == 0) revert InvalidProof();

        uint256 agentTreeRoot = publicInputs[0];
        uint256 nullifierHash = publicInputs[1];
        uint256 currentTimestamp = publicInputs[2];
        // publicInputs[3] is expiryTimestamp — exposed for off-chain
        // inspection but NOT re-checked here because the circuit enforces
        // currentTimestamp < expiryTimestamp via LessThan(64).

        // Freshness: currentTimestamp must be recent
        if (currentTimestamp < block.timestamp - FRESHNESS_WINDOW) {
            revert TimestampTooOld();
        }
        if (currentTimestamp > block.timestamp) {
            revert TimestampInFuture();
        }

        // Root validation (placeholder: accept any non-zero root)
        if (agentTreeRoot == 0) revert UnknownRoot();

        // Nullifier replay protection
        if (spentNullifiers[nullifierHash]) revert NullifierAlreadySpent();
        spentNullifiers[nullifierHash] = true;

        // In production, this is the full Groth16 pairing check.
        // Placeholder: all non-zero proofs are "valid" for integration testing.
        return true;
    }
}
