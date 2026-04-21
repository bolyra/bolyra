pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../tier2_001_formal_verifier_phantom_delegatee_inclusion/circuits/lib/binary_merkle_root.circom";

/**
 * @title HumanUniqueness
 * @version 2.0.0 (domain-separated nullifier)
 * @notice Human uniqueness circuit for the Bolyra identity protocol.
 *
 * This circuit proves that:
 *   1. The human prover knows the preimage of their identity commitment.
 *   2. The identity commitment exists in the identity Merkle tree.
 *   3. The nullifier is domain-separated: Poseidon([DOMAIN_HUMAN, scope, secret])
 *      with DOMAIN_HUMAN = 1, preventing cross-circuit nullifier collisions.
 *
 * Domain separation rationale:
 *   Prior to v2.0.0, the nullifier was Poseidon(scope, secret) — arity 2.
 *   AgentPolicy and Delegation used the same arity and input semantics,
 *   meaning identical (secret, scope) values across circuits produced
 *   identical nullifiers. By prepending a circuit-specific domain tag,
 *   the Poseidon preimage for each circuit is structurally distinct.
 *
 * Nullifier construction:
 *   nullifier = Poseidon([1, scope, secret])   (arity 3)
 *
 * Public inputs:
 *   - identityTreeRoot:   Merkle root of the human identity tree
 *   - nullifierHash:      domain-separated nullifier output
 *   - scope:              application scope identifier
 *
 * Private inputs:
 *   - secret:             human prover's secret key
 *   - identityNonce:      nonce for identity commitment
 *   - merklePathElements[20]: Merkle proof siblings
 *   - merklePathIndices[20]:  Merkle proof direction bits
 *
 * Constraint cost:
 *   - Poseidon(2) x1 (commitment):  ~250 constraints
 *   - Poseidon(3) x1 (nullifier):   ~350 constraints
 *   - BinaryMerkleRoot(20):         ~40,000 constraints
 *   - Domain tag assertion:         1 constraint
 *   - Total:                        ~40,601 constraints
 */
template HumanUniqueness() {
    // ── Domain tag constant ──────────────────────────────────────────
    // DOMAIN_HUMAN = 1 distinguishes this circuit's nullifier domain
    // from AgentPolicy (DOMAIN_AGENT = 2) and Delegation (DOMAIN_DELEG = 3).
    var DOMAIN_HUMAN = 1;

    // ── Public inputs ────────────────────────────────────────────────
    signal input identityTreeRoot;
    signal input nullifierHash;
    signal input scope;

    // ── Private inputs ───────────────────────────────────────────────
    signal input secret;
    signal input identityNonce;
    signal input merklePathElements[20];
    signal input merklePathIndices[20];

    // ── 1. Compute identity commitment ───────────────────────────────
    //    identityCommitment = Poseidon(secret, identityNonce)
    component identityCommitmentHasher = Poseidon(2);
    identityCommitmentHasher.inputs[0] <== secret;
    identityCommitmentHasher.inputs[1] <== identityNonce;
    signal identityCommitment;
    identityCommitment <== identityCommitmentHasher.out;

    // ── 2. Verify identity inclusion in identity tree ────────────────
    component merkleCheck = BinaryMerkleRoot(20);
    merkleCheck.leaf <== identityCommitment;
    for (var i = 0; i < 20; i++) {
        merkleCheck.pathElements[i] <== merklePathElements[i];
        merkleCheck.pathIndices[i] <== merklePathIndices[i];
    }
    merkleCheck.root === identityTreeRoot;

    // ── 3. Compute domain-separated nullifier ────────────────────────
    //    nullifier = Poseidon([DOMAIN_HUMAN, scope, secret])  (arity 3)
    //
    //    The domain tag occupies input[0], guaranteeing that this
    //    Poseidon preimage can never equal the preimage used by
    //    AgentPolicy (tag=2, arity 3) or Delegation (tag=3, arity 4).
    signal domainTag;
    domainTag <== DOMAIN_HUMAN;

    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== domainTag;
    nullifierHasher.inputs[1] <== scope;
    nullifierHasher.inputs[2] <== secret;
    nullifierHasher.out === nullifierHash;
}

component main {public [identityTreeRoot, nullifierHash, scope]} = HumanUniqueness();
