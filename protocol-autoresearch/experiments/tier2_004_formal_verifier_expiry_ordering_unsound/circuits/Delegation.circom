pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../tier2_001_formal_verifier_phantom_delegatee_inclusion/circuits/lib/binary_merkle_root.circom";

/**
 * @title Delegation (with expiry ordering)
 * @version 3.0.0
 * @notice Delegation circuit for the Bolyra identity protocol.
 *
 * Extends Delegation v2 (phantom delegatee fix) with in-circuit
 * expiry ordering enforcement:
 *   - delegateeExpiry <= delegatorExpiry (LessEqThan(64))
 *   - currentTimestamp < delegateeExpiry   (LessThan(64))
 *
 * Without these constraints, the contract must independently verify
 * expiry ordering, creating a gap where a proof can be generated with
 * an expired or over-extended delegation and submitted before the
 * contract-side check executes.
 *
 * Public inputs:
 *   - agentTreeRoot:            Merkle root of the agent identity tree
 *   - scopeCommitment:          commitment binding delegator, delegatee, and scope
 *   - nullifierHash:            prevents double-delegation for same scope
 *   - currentTimestamp:          prover-supplied current time
 *   - delegatorExpiry:           delegator credential expiry
 *   - delegateeExpiry:           delegatee credential expiry
 *
 * Private inputs:
 *   - delegatorSecret:          delegator's secret key
 *   - delegatorNonce:           delegator's nonce for commitment
 *   - delegateeCredCommitment:  delegatee's credential commitment
 *   - scope:                    delegation scope identifier
 *   - merklePathElements[20]:   Merkle proof siblings
 *   - merklePathIndices[20]:    Merkle proof direction bits
 *
 * Additional constraint cost: ~260 (two LessThan/LessEqThan(64) + Num2Bits)
 * Total estimated constraints: ~42,260
 */
template DelegationWithExpiry() {
    // ── Public inputs ─────────────────────────────────────────────────
    signal input agentTreeRoot;
    signal input scopeCommitment;
    signal input nullifierHash;
    signal input currentTimestamp;
    signal input delegatorExpiry;
    signal input delegateeExpiry;

    // ── Private inputs ────────────────────────────────────────────────
    signal input delegatorSecret;
    signal input delegatorNonce;
    signal input delegateeCredCommitment;
    signal input scope;
    signal input merklePathElements[20];
    signal input merklePathIndices[20];

    // ── 1. Compute delegator credential commitment ────────────────────
    component delegatorCommitmentHasher = Poseidon(2);
    delegatorCommitmentHasher.inputs[0] <== delegatorSecret;
    delegatorCommitmentHasher.inputs[1] <== delegatorNonce;
    signal delegatorCredCommitment;
    delegatorCredCommitment <== delegatorCommitmentHasher.out;

    // ── 2. Verify delegatee inclusion in agent tree ───────────────────
    component merkleCheck = BinaryMerkleRoot(20);
    merkleCheck.leaf <== delegateeCredCommitment;
    for (var i = 0; i < 20; i++) {
        merkleCheck.pathElements[i] <== merklePathElements[i];
        merkleCheck.pathIndices[i] <== merklePathIndices[i];
    }
    merkleCheck.root === agentTreeRoot;

    // ── 3. Compute scope commitment ───────────────────────────────────
    component scopeHasher = Poseidon(3);
    scopeHasher.inputs[0] <== delegatorCredCommitment;
    scopeHasher.inputs[1] <== delegateeCredCommitment;
    scopeHasher.inputs[2] <== scope;
    scopeHasher.out === scopeCommitment;

    // ── 4. Compute nullifier ──────────────────────────────────────────
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== delegatorSecret;
    nullifierHasher.inputs[1] <== scope;
    nullifierHasher.out === nullifierHash;

    // ── 5. Range-check all timestamps to 64 bits ──────────────────────
    component currentTsBits = Num2Bits(64);
    currentTsBits.in <== currentTimestamp;

    component delegatorExpiryBits = Num2Bits(64);
    delegatorExpiryBits.in <== delegatorExpiry;

    component delegateeExpiryBits = Num2Bits(64);
    delegateeExpiryBits.in <== delegateeExpiry;

    // ── 6. Enforce delegatee expiry <= delegator expiry ───────────────
    //    A delegatee cannot have a longer-lived credential than the
    //    delegator who granted it. Without this in-circuit constraint,
    //    an attacker could extend their delegation beyond the
    //    delegator's authority window.
    component delegExpValid = LessEqThan(64);
    delegExpValid.in[0] <== delegateeExpiry;
    delegExpValid.in[1] <== delegatorExpiry;
    delegExpValid.out === 1;

    // ── 7. Enforce currentTimestamp < delegateeExpiry ──────────────────
    //    The delegation must not be expired at the time of proof generation.
    component isNotExpired = LessThan(64);
    isNotExpired.in[0] <== currentTimestamp;
    isNotExpired.in[1] <== delegateeExpiry;
    isNotExpired.out === 1;
}

component main {public [agentTreeRoot, scopeCommitment, nullifierHash, currentTimestamp, delegatorExpiry, delegateeExpiry]} = DelegationWithExpiry();
