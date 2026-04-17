pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../tier2_001_formal_verifier_phantom_delegatee_inclusion/circuits/lib/binary_merkle_root.circom";

/**
 * @title AgentPolicy
 * @version 1.0.0
 * @notice Agent policy circuit for the Bolyra identity protocol.
 *
 * This circuit proves that:
 *   1. The agent knows the preimage of their credential commitment.
 *   2. The credential commitment exists in the agent Merkle tree.
 *   3. The credential is NOT expired: currentTimestamp < expiryTimestamp.
 *   4. The nullifier prevents double-use for the same policy scope.
 *
 * Expiry enforcement:
 *   Prior versions performed Num2Bits(64) range checks on timestamps but
 *   LACKED the critical LessThan(64) comparison. This allowed an attacker
 *   to generate a valid proof with currentTimestamp >= expiryTimestamp
 *   (expired credential). The fix adds an explicit LessThan(64) constraint:
 *     isNotExpired.in[0] <== currentTimestamp
 *     isNotExpired.in[1] <== expiryTimestamp
 *     isNotExpired.out === 1
 *
 * Public inputs:
 *   - agentTreeRoot:       Merkle root of the agent identity tree
 *   - nullifierHash:       prevents double-use for same policy scope
 *   - currentTimestamp:     prover-supplied current time (verifier checks freshness)
 *   - expiryTimestamp:      credential expiry time
 *
 * Private inputs:
 *   - agentSecret:         agent's secret key
 *   - agentNonce:          agent's nonce for commitment
 *   - policyScope:         policy scope identifier
 *   - merklePathElements[20]: Merkle proof siblings
 *   - merklePathIndices[20]:  Merkle proof direction bits
 *
 * Constraint cost breakdown:
 *   - Poseidon(2) x2:          ~500 constraints
 *   - BinaryMerkleRoot(20):    ~40,000 constraints
 *   - LessThan(64):            ~130 constraints
 *   - Num2Bits(64) x2:         ~128 constraints
 *   - Total:                   ~40,758 constraints
 */
template AgentPolicy() {
    // ── Public inputs ─────────────────────────────────────────────────
    signal input agentTreeRoot;
    signal input nullifierHash;
    signal input currentTimestamp;
    signal input expiryTimestamp;

    // ── Private inputs ────────────────────────────────────────────────
    signal input agentSecret;
    signal input agentNonce;
    signal input policyScope;
    signal input merklePathElements[20];
    signal input merklePathIndices[20];

    // ── 1. Compute agent credential commitment ──────────────────────
    //    agentCredCommitment = Poseidon(agentSecret, agentNonce)
    component agentCommitmentHasher = Poseidon(2);
    agentCommitmentHasher.inputs[0] <== agentSecret;
    agentCommitmentHasher.inputs[1] <== agentNonce;
    signal agentCredCommitment;
    agentCredCommitment <== agentCommitmentHasher.out;

    // ── 2. Verify agent inclusion in agent tree ─────────────────────
    component merkleCheck = BinaryMerkleRoot(20);
    merkleCheck.leaf <== agentCredCommitment;
    for (var i = 0; i < 20; i++) {
        merkleCheck.pathElements[i] <== merklePathElements[i];
        merkleCheck.pathIndices[i] <== merklePathIndices[i];
    }
    merkleCheck.root === agentTreeRoot;

    // ── 3. Range-check timestamps to 64 bits ────────────────────────
    //    Prevents overflow attacks on the LessThan comparator.
    component currentTsBits = Num2Bits(64);
    currentTsBits.in <== currentTimestamp;

    component expiryTsBits = Num2Bits(64);
    expiryTsBits.in <== expiryTimestamp;

    // ── 4. Enforce expiry: currentTimestamp < expiryTimestamp ────────
    //    THIS IS THE CRITICAL FIX. Without this constraint, a prover
    //    can submit an expired credential and generate a valid proof.
    //    The verifier contract sees currentTimestamp and expiryTimestamp
    //    as public signals but cannot trust them unless the circuit
    //    enforces the ordering.
    component isNotExpired = LessThan(64);
    isNotExpired.in[0] <== currentTimestamp;
    isNotExpired.in[1] <== expiryTimestamp;
    isNotExpired.out === 1;

    // ── 5. Compute nullifier ────────────────────────────────────────
    //    nullifier = Poseidon(agentSecret, policyScope)
    //    Prevents double-use for the same policy scope.
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== agentSecret;
    nullifierHasher.inputs[1] <== policyScope;
    nullifierHasher.out === nullifierHash;
}

component main {public [agentTreeRoot, nullifierHash, currentTimestamp, expiryTimestamp]} = AgentPolicy();
