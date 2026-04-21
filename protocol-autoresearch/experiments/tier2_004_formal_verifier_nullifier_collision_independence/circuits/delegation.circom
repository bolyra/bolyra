pragma circom 2.1.6;

include "../tier2_001_formal_verifier_phantom_delegatee_inclusion/circuits/lib/binary_merkle_root.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 * @title Delegation
 * @version 2.0.0 (domain-separated nullifier)
 * @notice Delegation circuit for the Bolyra identity protocol.
 *
 * This circuit proves that:
 *   1. The delegator knows the preimage of delegatorCredCommitment.
 *   2. The delegateeCredCommitment EXISTS in the agent Merkle tree
 *      (prevents phantom delegatee attack — CVE-BOLYRA-2026-001).
 *   3. The scopeCommitment is correctly derived from delegator + delegatee + scope.
 *   4. The nullifier is domain-separated:
 *      Poseidon([DOMAIN_DELEG, delegatorSecret, delegateeCredCommitment, scope])
 *      with DOMAIN_DELEG = 3, preventing cross-circuit nullifier collisions.
 *
 * Domain separation rationale:
 *   Prior to v2.0.0, nullifier = Poseidon(delegatorSecret, scope) — arity 2.
 *   Adding DOMAIN_DELEG = 3 and including delegateeCredCommitment in the
 *   nullifier input gives this circuit a unique arity-4 Poseidon preimage
 *   that cannot collide with HumanUniqueness (tag=1, arity 3) or
 *   AgentPolicy (tag=2, arity 3).
 *
 * Nullifier construction:
 *   nullifier = Poseidon([3, delegatorSecret, delegateeCredCommitment, scope])  (arity 4)
 *
 * Public inputs:
 *   - agentTreeRoot:            Merkle root of the agent identity tree
 *   - scopeCommitment:          commitment binding delegator, delegatee, and scope
 *   - nullifierHash:            domain-separated delegation nullifier
 *
 * Private inputs:
 *   - delegatorSecret:          delegator's secret key
 *   - delegatorNonce:           delegator's nonce for commitment
 *   - delegateeCredCommitment:  delegatee's credential commitment (leaf in agent tree)
 *   - scope:                    delegation scope identifier
 *   - merklePathElements[20]:   Merkle proof siblings
 *   - merklePathIndices[20]:    Merkle proof direction bits
 *
 * Constraint cost:
 *   - Poseidon(2) x1 (commitment):  ~250 constraints
 *   - Poseidon(3) x1 (scope):       ~350 constraints
 *   - Poseidon(4) x1 (nullifier):   ~450 constraints
 *   - BinaryMerkleRoot(20):         ~40,000 constraints
 *   - Domain tag assertion:         1 constraint
 *   - Total:                        ~41,051 constraints
 */
template Delegation() {
    // ── Domain tag constant ──────────────────────────────────────────
    var DOMAIN_DELEG = 3;

    // ── Public inputs ────────────────────────────────────────────────
    signal input agentTreeRoot;
    signal input scopeCommitment;
    signal input nullifierHash;

    // ── Private inputs ───────────────────────────────────────────────
    signal input delegatorSecret;
    signal input delegatorNonce;
    signal input delegateeCredCommitment;
    signal input scope;
    signal input merklePathElements[20];
    signal input merklePathIndices[20];

    // ── 1. Compute delegator credential commitment ───────────────────
    //    delegatorCredCommitment = Poseidon(delegatorSecret, delegatorNonce)
    component delegatorCommitmentHasher = Poseidon(2);
    delegatorCommitmentHasher.inputs[0] <== delegatorSecret;
    delegatorCommitmentHasher.inputs[1] <== delegatorNonce;
    signal delegatorCredCommitment;
    delegatorCredCommitment <== delegatorCommitmentHasher.out;

    // ── 2. Verify delegatee inclusion in agent tree ──────────────────
    component merkleCheck = BinaryMerkleRoot(20);
    merkleCheck.leaf <== delegateeCredCommitment;
    for (var i = 0; i < 20; i++) {
        merkleCheck.pathElements[i] <== merklePathElements[i];
        merkleCheck.pathIndices[i] <== merklePathIndices[i];
    }
    merkleCheck.root === agentTreeRoot;

    // ── 3. Compute scope commitment ──────────────────────────────────
    //    scopeCommitment = Poseidon(delegatorCredCommitment, delegateeCredCommitment, scope)
    component scopeHasher = Poseidon(3);
    scopeHasher.inputs[0] <== delegatorCredCommitment;
    scopeHasher.inputs[1] <== delegateeCredCommitment;
    scopeHasher.inputs[2] <== scope;
    scopeHasher.out === scopeCommitment;

    // ── 4. Compute domain-separated nullifier ────────────────────────
    //    nullifier = Poseidon([DOMAIN_DELEG, delegatorSecret, delegateeCredCommitment, scope])
    //    (arity 4)
    //
    //    DOMAIN_DELEG = 3 plus the 4-arity input vector guarantees this
    //    preimage is structurally impossible to produce from HumanUniqueness
    //    (tag=1, arity 3) or AgentPolicy (tag=2, arity 3).
    //
    //    Including delegateeCredCommitment binds the nullifier to the
    //    specific delegatee, preventing nullifier reuse across different
    //    delegatees for the same scope.
    signal domainTag;
    domainTag <== DOMAIN_DELEG;

    component nullifierHasher = Poseidon(4);
    nullifierHasher.inputs[0] <== domainTag;
    nullifierHasher.inputs[1] <== delegatorSecret;
    nullifierHasher.inputs[2] <== delegateeCredCommitment;
    nullifierHasher.inputs[3] <== scope;
    nullifierHasher.out === nullifierHash;
}

component main {public [agentTreeRoot, scopeCommitment, nullifierHash]} = Delegation();
