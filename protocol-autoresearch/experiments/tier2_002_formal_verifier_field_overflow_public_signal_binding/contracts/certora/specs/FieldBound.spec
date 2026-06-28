/*
 * FieldBound.spec — Certora CVL rules for BN254 field-bound enforcement
 *
 * Rule 1 (publicSignalsInField):
 *   For any reachable state, every public signal argument that reaches a
 *   verifier's verifyProof() call is strictly less than FIELD_MODULUS.
 *
 * Rule 2 (nonceNonBypassable):
 *   No pair (n, n + r) can both be accepted as distinct session nonces,
 *   proving that usedNonces cannot be bypassed via modular wrapping.
 */

methods {
    // IdentityRegistry external entry points
    function verifyHandshake(
        uint256[8],
        uint256[5],
        uint256[8],
        uint256[6]
    ) external returns (bool);

    function verifyDelegation(
        uint256[8],
        uint256[6]
    ) external returns (bool);

    // FieldBoundLib constant
    function FIELD_MODULUS() external returns (uint256) envfree;

    // Nonce mapping
    function usedNonces(uint256) external returns (bool) envfree;
}

// Ghost variable tracking the field modulus
definition FIELD_MOD() returns uint256 =
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

/*
 * Rule 1: publicSignalsInField
 *
 * Any call to verifyHandshake that does NOT revert implies all public
 * signals were < FIELD_MODULUS.  We express this as: if a signal is
 * >= FIELD_MODULUS, the call MUST revert.
 */
rule publicSignalsInField_human(env e) {
    uint256[8] humanProof;
    uint256[5] humanPub;
    uint256[8] agentProof;
    uint256[6] agentPub;

    // Pick any human signal slot
    uint256 idx;
    require idx < 5;
    require humanPub[idx] >= FIELD_MOD();

    verifyHandshake@withrevert(e, humanProof, humanPub, agentProof, agentPub);

    assert lastReverted,
        "verifyHandshake must revert when any human public signal >= FIELD_MODULUS";
}

rule publicSignalsInField_agent(env e) {
    uint256[8] humanProof;
    uint256[5] humanPub;
    uint256[8] agentProof;
    uint256[6] agentPub;

    // Pick any agent signal slot
    uint256 idx;
    require idx < 6;
    require agentPub[idx] >= FIELD_MOD();

    // Human signals are valid so we isolate the agent check
    require humanPub[0] < FIELD_MOD();
    require humanPub[1] < FIELD_MOD();
    require humanPub[2] < FIELD_MOD();
    require humanPub[3] < FIELD_MOD();
    require humanPub[4] < FIELD_MOD();

    verifyHandshake@withrevert(e, humanProof, humanPub, agentProof, agentPub);

    assert lastReverted,
        "verifyHandshake must revert when any agent public signal >= FIELD_MODULUS";
}

rule publicSignalsInField_delegation(env e) {
    uint256[8] proof;
    uint256[6] pub;

    uint256 idx;
    require idx < 6;
    require pub[idx] >= FIELD_MOD();

    verifyDelegation@withrevert(e, proof, pub);

    assert lastReverted,
        "verifyDelegation must revert when any public signal >= FIELD_MODULUS";
}

/*
 * Rule 2: nonceNonBypassable
 *
 * After a successful verifyHandshake with nonce n, attempting
 * verifyHandshake with nonce n + r must revert (either from field
 * bound or from nonce reuse — but it must NOT succeed).
 */
rule nonceNonBypassable(env e1, env e2) {
    uint256[8] humanProof1; uint256[5] humanPub1;
    uint256[8] agentProof1; uint256[6] agentPub1;
    uint256[8] humanProof2; uint256[5] humanPub2;
    uint256[8] agentProof2; uint256[6] agentPub2;

    // Both attempts use the same nonce mod r
    uint256 n;
    require n < FIELD_MOD();

    // First call uses nonce n
    require humanPub1[4] == n;
    require agentPub1[5] == n;

    // All signals in field for first call
    require humanPub1[0] < FIELD_MOD();
    require humanPub1[1] < FIELD_MOD();
    require humanPub1[2] < FIELD_MOD();
    require humanPub1[3] < FIELD_MOD();
    require agentPub1[0] < FIELD_MOD();
    require agentPub1[1] < FIELD_MOD();
    require agentPub1[2] < FIELD_MOD();
    require agentPub1[3] < FIELD_MOD();
    require agentPub1[4] < FIELD_MOD();

    // First call succeeds
    verifyHandshake(e1, humanProof1, humanPub1, agentProof1, agentPub1);

    // Second call uses nonce n + r (wraps to same circuit value)
    require humanPub2[4] == require_uint256(n + FIELD_MOD());
    require agentPub2[5] == require_uint256(n + FIELD_MOD());

    verifyHandshake@withrevert(e2, humanProof2, humanPub2, agentProof2, agentPub2);

    assert lastReverted,
        "A nonce that wraps around FIELD_MODULUS must be rejected";
}
