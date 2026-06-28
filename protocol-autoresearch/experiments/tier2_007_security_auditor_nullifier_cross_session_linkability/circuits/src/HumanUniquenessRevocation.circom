pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/**
 * @title HumanUniquenessRevocation
 * @version 1.0.0
 * @notice Auxiliary circuit for Bolyra identity revocation.
 *
 * This circuit proves knowledge of the externalNullifier preimage
 * (DOMAIN_HUMAN, scope, secret) without revealing it. It outputs
 * the externalNullifierCommitment = Poseidon₁(externalNullifier)
 * which the on-chain registry uses for sybil/revocation gating.
 *
 * Use case:
 *   When a human identity must be revoked (e.g., key compromise),
 *   the prover demonstrates they own the identity by proving knowledge
 *   of secret, then the registry marks the commitment as revoked.
 *
 * Public inputs:
 *   - scope:                         application scope identifier
 *   - externalNullifierCommitment:   commitment to revoke
 *
 * Private inputs:
 *   - secret:             human prover's secret key
 *
 * Constraint cost:
 *   - Poseidon(3) x1 (external nullifier):         ~350 constraints
 *   - Poseidon(1) x1 (commitment):                 ~150 constraints
 *   - Domain tag assertion:                        1 constraint
 *   - Total:                                       ~501 constraints
 */
template HumanUniquenessRevocation() {
    var DOMAIN_HUMAN = 1;

    // ── Public inputs ────────────────────────────────────────────────
    signal input scope;
    signal input externalNullifierCommitment;

    // ── Private inputs ───────────────────────────────────────────────
    signal input secret;

    // ── 1. Compute external nullifier ────────────────────────────────
    signal domainTag;
    domainTag <== DOMAIN_HUMAN;

    component externalNullifierHasher = Poseidon(3);
    externalNullifierHasher.inputs[0] <== domainTag;
    externalNullifierHasher.inputs[1] <== scope;
    externalNullifierHasher.inputs[2] <== secret;

    // ── 2. Compute and constrain commitment ──────────────────────────
    component commitHasher = Poseidon(1);
    commitHasher.inputs[0] <== externalNullifierHasher.out;
    commitHasher.out === externalNullifierCommitment;
}

component main {public [scope, externalNullifierCommitment]} = HumanUniquenessRevocation();
