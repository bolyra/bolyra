pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/**
 * @title BinaryMerkleRoot
 * @notice Computes the Merkle root of a binary tree given a leaf and
 *         an authentication path (sibling hashes + direction bits).
 * @param MAX_DEPTH Maximum depth of the Merkle tree (number of levels).
 *
 * Inputs:
 *   - leaf:           the leaf value (field element)
 *   - pathElements[MAX_DEPTH]: sibling hashes along the authentication path
 *   - pathIndices[MAX_DEPTH]:  direction bits (0 = left child, 1 = right child)
 *
 * Output:
 *   - root: the computed Merkle root
 *
 * Hash function: Poseidon(2) — matching the hash used for identity commitments
 * in the Bolyra protocol (delegateeCredCommitment, humanCommitment, etc.).
 */
template BinaryMerkleRoot(MAX_DEPTH) {
    signal input leaf;
    signal input pathElements[MAX_DEPTH];
    signal input pathIndices[MAX_DEPTH];
    signal output root;

    // Intermediate hashes climbing from leaf to root
    component hashers[MAX_DEPTH];
    component mux[MAX_DEPTH]; // implicit via signal arithmetic

    signal hashes[MAX_DEPTH + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < MAX_DEPTH; i++) {
        // Constrain pathIndices to be binary
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = Poseidon(2);

        // If pathIndices[i] == 0, current node is left child:
        //   hash(current, sibling)
        // If pathIndices[i] == 1, current node is right child:
        //   hash(sibling, current)
        hashers[i].inputs[0] <== hashes[i] + pathIndices[i] * (pathElements[i] - hashes[i]);
        hashers[i].inputs[1] <== pathElements[i] + pathIndices[i] * (hashes[i] - pathElements[i]);

        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[MAX_DEPTH];
}
