pragma circom 2.1.6;

include "../lib/binary_merkle_root.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 * @title Delegation
 * @version 2.0.0
 * @notice Delegation circuit for the Bolyra identity protocol.
 *
 * This circuit proves that:
 *   1. The delegator knows the preimage of delegatorCredCommitment.
 *   2. The delegateeCredCommitment EXISTS in the agent Merkle tree
 *      (prevents phantom delegatee attack — CVE-BOLYRA-2026-001).
 *   3. The scopeCommitment is correctly derived from delegator + delegatee + scope.
 *
 * Public inputs:
 *   - agentTreeRoot:            Merkle root of the agent identity tree
 *   - scopeCommitment:          commitment binding delegator, delegatee, and scope
 *   - nullifierHash:            prevents double-delegation for same scope
 *
 * Private inputs:
 *   - delegatorSecret:          delegator's secret key
 *   - delegatorNonce:           delegator's nonce for commitment
 *   - delegateeCredCommitment:  delegatee's credential commitment (leaf in agent tree)
 *   - scope:                    delegation scope identifier
 *   - merklePathElements[20]:   Merkle proof siblings
 *   - merklePathIndices[20]:    Merkle proof direction bits
 *
 * Estimated constraints: ~42,000 (Poseidon hashes dominate)
 */
template Delegation() {
    // ── Public inputs ─────────────────────────────────────────────────
    signal input agentTreeRoot;
    signal input scopeCommitment;
    signal input nullifierHash;

    // ── Private inputs ────────────────────────────────────────────────
    signal input delegatorSecret;
    signal input delegatorNonce;
    signal input delegateeCredCommitment;
    signal input scope;
    signal input merklePathElements[20];
    signal input merklePathIndices[20];

    // ── 1. Compute delegator credential commitment ────────────────────
    //    delegatorCredCommitment = Poseidon(delegatorSecret, delegatorNonce)
    component delegatorCommitmentHasher = Poseidon(2);
    delegatorCommitmentHasher.inputs[0] <== delegatorSecret;
    delegatorCommitmentHasher.inputs[1] <== delegatorNonce;
    signal delegatorCredCommitment;
    delegatorCredCommitment <== delegatorCommitmentHasher.out;

    // ── 2. Verify delegatee inclusion in agent tree ───────────────────
    //    This is the critical fix: the delegatee's credential commitment
    //    MUST exist as a leaf in the agent Merkle tree. Without this check,
    //    an attacker could fabricate any delegateeCredCommitment and receive
    //    a valid scopeCommitment (phantom delegatee vulnerability).
    component merkleCheck = BinaryMerkleRoot(20);
    merkleCheck.leaf <== delegateeCredCommitment;
    for (var i = 0; i < 20; i++) {
        merkleCheck.pathElements[i] <== merklePathElements[i];
        merkleCheck.pathIndices[i] <== merklePathIndices[i];
    }
    // Constrain: computed root MUST equal the public agentTreeRoot
    merkleCheck.root === agentTreeRoot;

    // ── 3. Compute scope commitment ───────────────────────────────────
    //    scopeCommitment = Poseidon(delegatorCredCommitment, delegateeCredCommitment, scope)
    component scopeHasher = Poseidon(3);
    scopeHasher.inputs[0] <== delegatorCredCommitment;
    scopeHasher.inputs[1] <== delegateeCredCommitment;
    scopeHasher.inputs[2] <== scope;
    scopeHasher.out === scopeCommitment;

    // ── 4. Compute nullifier ──────────────────────────────────────────
    //    nullifier = Poseidon(delegatorSecret, scope)
    //    Prevents double-delegation for the same scope by the same delegator.
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== delegatorSecret;
    nullifierHasher.inputs[1] <== scope;
    nullifierHasher.out === nullifierHash;
}

component main {public [agentTreeRoot, scopeCommitment, nullifierHash]} = Delegation();
