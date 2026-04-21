pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../tier2_001_formal_verifier_phantom_delegatee_inclusion/circuits/lib/binary_merkle_root.circom";

/**
 * @title AgentPolicy
 * @version 2.0.0 (domain-separated nullifier)
 * @notice Agent policy circuit for the Bolyra identity protocol.
 *
 * This circuit proves that:
 *   1. The agent knows the preimage of their credential commitment.
 *   2. The credential commitment exists in the agent Merkle tree.
 *   3. The credential is NOT expired: currentTimestamp < expiryTimestamp.
 *   4. The nullifier is domain-separated: Poseidon([DOMAIN_AGENT, agentSecret, policyScope])
 *      with DOMAIN_AGENT = 2, preventing cross-circuit nullifier collisions.
 *
 * Domain separation rationale:
 *   Prior to v2.0.0, nullifier = Poseidon(agentSecret, policyScope) — arity 2.
 *   This shared the same structure as HumanUniqueness and Delegation nullifiers.
 *   Adding DOMAIN_AGENT = 2 as the first Poseidon input ensures the preimage
 *   is structurally distinct from HumanUniqueness (tag=1) and Delegation (tag=3).
 *
 * Nullifier construction:
 *   nullifier = Poseidon([2, agentSecret, policyScope])   (arity 3)
 *
 * Public inputs:
 *   - agentTreeRoot:       Merkle root of the agent identity tree
 *   - nullifierHash:       domain-separated nullifier output
 *   - currentTimestamp:    prover-supplied current time
 *   - expiryTimestamp:     credential expiry time
 *
 * Private inputs:
 *   - agentSecret:         agent's secret key
 *   - agentNonce:          agent's nonce for commitment
 *   - policyScope:         policy scope identifier
 *   - merklePathElements[20]: Merkle proof siblings
 *   - merklePathIndices[20]:  Merkle proof direction bits
 *
 * Constraint cost:
 *   - Poseidon(2) x1 (commitment):  ~250 constraints
 *   - Poseidon(3) x1 (nullifier):   ~350 constraints
 *   - BinaryMerkleRoot(20):         ~40,000 constraints
 *   - LessThan(64):                 ~130 constraints
 *   - Num2Bits(64) x2:              ~128 constraints
 *   - Domain tag assertion:         1 constraint
 *   - Total:                        ~40,859 constraints
 */
template AgentPolicy() {
    // ── Domain tag constant ──────────────────────────────────────────
    var DOMAIN_AGENT = 2;

    // ── Public inputs ────────────────────────────────────────────────
    signal input agentTreeRoot;
    signal input nullifierHash;
    signal input currentTimestamp;
    signal input expiryTimestamp;

    // ── Private inputs ───────────────────────────────────────────────
    signal input agentSecret;
    signal input agentNonce;
    signal input policyScope;
    signal input merklePathElements[20];
    signal input merklePathIndices[20];

    // ── 1. Compute agent credential commitment ───────────────────────
    //    agentCredCommitment = Poseidon(agentSecret, agentNonce)
    component agentCommitmentHasher = Poseidon(2);
    agentCommitmentHasher.inputs[0] <== agentSecret;
    agentCommitmentHasher.inputs[1] <== agentNonce;
    signal agentCredCommitment;
    agentCredCommitment <== agentCommitmentHasher.out;

    // ── 2. Verify agent inclusion in agent tree ──────────────────────
    component merkleCheck = BinaryMerkleRoot(20);
    merkleCheck.leaf <== agentCredCommitment;
    for (var i = 0; i < 20; i++) {
        merkleCheck.pathElements[i] <== merklePathElements[i];
        merkleCheck.pathIndices[i] <== merklePathIndices[i];
    }
    merkleCheck.root === agentTreeRoot;

    // ── 3. Range-check timestamps to 64 bits ─────────────────────────
    component currentTsBits = Num2Bits(64);
    currentTsBits.in <== currentTimestamp;

    component expiryTsBits = Num2Bits(64);
    expiryTsBits.in <== expiryTimestamp;

    // ── 4. Enforce expiry: currentTimestamp < expiryTimestamp ─────────
    component isNotExpired = LessThan(64);
    isNotExpired.in[0] <== currentTimestamp;
    isNotExpired.in[1] <== expiryTimestamp;
    isNotExpired.out === 1;

    // ── 5. Compute domain-separated nullifier ────────────────────────
    //    nullifier = Poseidon([DOMAIN_AGENT, agentSecret, policyScope])  (arity 3)
    //
    //    DOMAIN_AGENT = 2 distinguishes this from HumanUniqueness (tag=1)
    //    and Delegation (tag=3). Even with identical agentSecret and
    //    policyScope values, the nullifier output will differ.
    signal domainTag;
    domainTag <== DOMAIN_AGENT;

    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== domainTag;
    nullifierHasher.inputs[1] <== agentSecret;
    nullifierHasher.inputs[2] <== policyScope;
    nullifierHasher.out === nullifierHash;
}

component main {public [agentTreeRoot, nullifierHash, currentTimestamp, expiryTimestamp]} = AgentPolicy();
