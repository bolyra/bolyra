pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "./lib/binary_merkle_root.circom";

/**
 * @title HumanUniqueness
 * @version 3.0.0 (per-session unlinkable nullifier)
 * @notice Human uniqueness circuit for the Bolyra identity protocol.
 *
 * This circuit proves that:
 *   1. The human prover knows the preimage of their identity commitment.
 *   2. The identity commitment exists in the identity Merkle tree.
 *   3. The session nullifier is unique per session (unlinkable across verifiers).
 *   4. The external nullifier commitment is stable per identity (sybil gating).
 *
 * Two-nullifier architecture:
 *
 *   Session nullifier (public, per-session, unlinkable):
 *     nullifierHash = Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
 *
 *   External nullifier (private intermediate):
 *     externalNullifier = Poseidon₃(DOMAIN_HUMAN, scope, secret)
 *
 *   External nullifier commitment (public, stable, for on-chain sybil gating):
 *     externalNullifierCommitment = Poseidon₁(externalNullifier)
 *
 * Privacy rationale:
 *   Prior to v3.0.0, nullifierHash = Poseidon₃(DOMAIN_HUMAN, scope, secret)
 *   was constant across sessions, allowing colluding verifiers to link all
 *   activity to the same pseudonymous identity. By including sessionNonce
 *   in the session nullifier, each handshake produces a unique value.
 *   Sybil resistance is maintained via externalNullifierCommitment, which
 *   is a one-way commitment that the on-chain registry uses for
 *   revocation/uniqueness without revealing the raw nullifier to verifiers.
 *
 * Public inputs:
 *   - identityTreeRoot:              Merkle root of the human identity tree
 *   - nullifierHash:                 per-session nullifier (replay prevention)
 *   - scope:                         application scope identifier
 *   - externalNullifierCommitment:   stable commitment (sybil/revocation gating)
 *
 * Private inputs:
 *   - secret:             human prover's secret key
 *   - identityNonce:      nonce for identity commitment
 *   - sessionNonce:       per-session nonce for nullifier unlinkability
 *   - merklePathElements[20]: Merkle proof siblings
 *   - merklePathIndices[20]:  Merkle proof direction bits
 *
 * Constraint cost:
 *   - Poseidon(2) x1 (commitment):                ~250 constraints
 *   - Poseidon(4) x1 (session nullifier):          ~450 constraints
 *   - Poseidon(3) x1 (external nullifier):         ~350 constraints
 *   - Poseidon(1) x1 (external nullifier commit):  ~150 constraints
 *   - BinaryMerkleRoot(20):                       ~40,000 constraints
 *   - Domain tag assertion:                       1 constraint
 *   - Total:                                      ~41,201 constraints
 */
template HumanUniqueness() {
    // ── Domain tag constant ──────────────────────────────────────────
    // DOMAIN_HUMAN = 1 distinguishes this circuit's nullifier domain
    // from AgentPolicy (DOMAIN_AGENT = 2) and Delegation (DOMAIN_DELEG = 3).
    // These tags are frozen constants — see FORMAL-PROPERTIES.md §P-DS-1.
    var DOMAIN_HUMAN = 1;

    // ── Public inputs ────────────────────────────────────────────────
    signal input identityTreeRoot;
    signal input nullifierHash;
    signal input scope;
    signal input externalNullifierCommitment;

    // ── Private inputs ───────────────────────────────────────────────
    signal input secret;
    signal input identityNonce;
    signal input sessionNonce;
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

    // ── 3. Compute per-session nullifier (unlinkable) ───────────────
    //    nullifier = Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
    //
    //    Including sessionNonce ensures each handshake produces a unique
    //    nullifier, preventing cross-verifier linkability.
    signal domainTag;
    domainTag <== DOMAIN_HUMAN;

    component sessionNullifierHasher = Poseidon(4);
    sessionNullifierHasher.inputs[0] <== domainTag;
    sessionNullifierHasher.inputs[1] <== scope;
    sessionNullifierHasher.inputs[2] <== secret;
    sessionNullifierHasher.inputs[3] <== sessionNonce;
    sessionNullifierHasher.out === nullifierHash;

    // ── 4. Compute external nullifier (private, stable per identity) ─
    //    externalNullifier = Poseidon₃(DOMAIN_HUMAN, scope, secret)
    //
    //    This is the v2.0.0 nullifier, kept as a private intermediate.
    //    It is NOT exposed as a public output.
    component externalNullifierHasher = Poseidon(3);
    externalNullifierHasher.inputs[0] <== domainTag;
    externalNullifierHasher.inputs[1] <== scope;
    externalNullifierHasher.inputs[2] <== secret;

    // ── 5. Compute external nullifier commitment (public, on-chain) ──
    //    commitment = Poseidon₁(externalNullifier)
    //
    //    This one-way commitment is revealed publicly for on-chain sybil
    //    gating and revocation, but does not reveal the raw nullifier.
    //    Verifiers see the commitment but cannot link sessions.
    component extNullCommitHasher = Poseidon(1);
    extNullCommitHasher.inputs[0] <== externalNullifierHasher.out;
    extNullCommitHasher.out === externalNullifierCommitment;
}

component main {public [identityTreeRoot, nullifierHash, scope, externalNullifierCommitment]} = HumanUniqueness();
