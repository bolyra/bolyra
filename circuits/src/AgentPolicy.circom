pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";

// AgentPolicy: Proves an AI agent has valid credentials and meets a required policy.
//
// Architecture (from eng review):
//   - PLONK proving system (universal setup, no ceremony)
//   - Range checks on all uint64 fields (Num2Bits(64))
//   - Bits-only scope; threshold semantics in app layer
//   - Cumulative bit encoding: bit 4 implies bits 2+3, bit 3 implies bit 2
//   - Nonce binding for replay protection
//
// Constraint budget target: <80k constraints
//   - EdDSA verify: ~30k
//   - Merkle inclusion (depth 20): ~10k
//   - Range checks (2x Num2Bits(64)): ~128
//   - Bitmask logic + Poseidon hashes: ~5k
//   - Total estimate: ~45-50k
//
template AgentPolicy(MAX_DEPTH) {
    // ============ PRIVATE INPUTS ============

    // Agent credential fields
    signal input modelHash;               // hash of model identifier
    signal input operatorPubkeyAx;        // operator EdDSA public key (x coordinate)
    signal input operatorPubkeyAy;        // operator EdDSA public key (y coordinate)
    signal input permissionBitmask;       // 64-bit permission bitfield
    signal input expiryTimestamp;          // credential expiration (unix timestamp)

    // Operator signature over credential (EdDSA)
    signal input sigR8x;                  // signature R point x
    signal input sigR8y;                  // signature R point y
    signal input sigS;                    // signature scalar

    // Merkle proof for agentTree membership
    signal input merkleProofLength;       // actual depth of proof
    signal input merkleProofIndex;        // leaf index
    signal input merkleProofSiblings[MAX_DEPTH]; // sibling hashes

    // ============ PUBLIC INPUTS ============

    signal input requiredScopeMask;       // policy: which permission bits are required
    signal input currentTimestamp;        // current time (from verifier/relayer)
    signal input sessionNonce;            // verifier-generated nonce for replay protection

    // ============ PUBLIC OUTPUTS ============

    signal output agentMerkleRoot;        // computed Merkle root (verified on-chain)
    signal output nullifierHash;          // unique per agent per nonce (replay detection)
    signal output scopeCommitment;        // hash(permissionBitmask) for delegation chain linking

    // ============ STEP 1: Range checks on uint64 fields ============
    // Prevents field overflow attacks where values > 2^64 pass circuit
    // but overflow on the Solidity side.

    component bitmaskRange = Num2Bits(64);
    bitmaskRange.in <== permissionBitmask;

    component expiryRange = Num2Bits(64);
    expiryRange.in <== expiryTimestamp;

    component timestampRange = Num2Bits(64);
    timestampRange.in <== currentTimestamp;

    // ============ STEP 2: Credential commitment ============
    // credentialCommitment = Poseidon4(modelHash, operatorPubkeyAx, permissionBitmask, expiryTimestamp)
    // This is the leaf value stored in agentTree.

    component credentialHash = Poseidon(4);
    credentialHash.inputs[0] <== modelHash;
    credentialHash.inputs[1] <== operatorPubkeyAx;
    credentialHash.inputs[2] <== permissionBitmask;
    credentialHash.inputs[3] <== expiryTimestamp;

    signal credentialCommitment;
    credentialCommitment <== credentialHash.out;

    // ============ STEP 3: EdDSA signature verification ============
    // Operator signs the credential commitment with their EdDSA key.
    // This proves the operator authorized this agent's credentials.

    component sigVerify = EdDSAPoseidonVerifier();
    sigVerify.enabled <== 1;
    sigVerify.Ax <== operatorPubkeyAx;
    sigVerify.Ay <== operatorPubkeyAy;
    sigVerify.S <== sigS;
    sigVerify.R8x <== sigR8x;
    sigVerify.R8y <== sigR8y;
    sigVerify.M <== credentialCommitment;

    // ============ STEP 4: Merkle tree membership ============
    // Prove credentialCommitment is in the agentTree.
    // Uses the same BinaryMerkleRoot as Semaphore v4 for compatibility.

    component merkleRoot = BinaryMerkleRoot(MAX_DEPTH);
    merkleRoot.leaf <== credentialCommitment;
    merkleRoot.depth <== merkleProofLength;
    merkleRoot.index <== merkleProofIndex;
    for (var i = 0; i < MAX_DEPTH; i++) {
        merkleRoot.siblings[i] <== merkleProofSiblings[i];
    }

    agentMerkleRoot <== merkleRoot.out;

    // ============ STEP 5: Permission scope check ============
    // Verify that permissionBitmask includes all bits required by requiredScopeMask.
    // Check: (requiredScopeMask & ~permissionBitmask) == 0
    // i.e., no required bit is missing from the agent's permissions.
    //
    // We compute this bit-by-bit using the already-decomposed bitmask.

    component requiredBits = Num2Bits(64);
    requiredBits.in <== requiredScopeMask;

    // For each bit: if required[i] == 1, then permission[i] must be 1.
    // Equivalently: required[i] * (1 - permission[i]) == 0 for all i.
    signal scopeViolation[64];
    for (var i = 0; i < 64; i++) {
        scopeViolation[i] <== requiredBits.out[i] * (1 - bitmaskRange.out[i]);
        scopeViolation[i] === 0;
    }

    // ============ STEP 6: Expiry check ============
    // Verify that expiryTimestamp > currentTimestamp (credential not expired).
    // Using LessThan(64) from circomlib: checks if currentTimestamp < expiryTimestamp.

    component notExpired = LessThan(64);
    notExpired.in[0] <== currentTimestamp;
    notExpired.in[1] <== expiryTimestamp;
    notExpired.out === 1;

    // ============ STEP 7: Nullifier for replay protection ============
    // nullifier = Poseidon2(credentialCommitment, sessionNonce)
    // Unique per agent per session. Checked against usedNonces on-chain.

    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== credentialCommitment;
    nullifier.inputs[1] <== sessionNonce;
    nullifierHash <== nullifier.out;

    // ============ STEP 8: Scope commitment for delegation chain ============
    // scopeCommitment = Poseidon1(permissionBitmask)
    // Published as public output. Next hop in delegation chain takes this
    // as public input to verify scope narrowing without revealing actual bits.

    component scopeHash = Poseidon(1);
    scopeHash.inputs[0] <== permissionBitmask;
    scopeCommitment <== scopeHash.out;
}

// Default compilation: depth 20 (~1M agents)
component main {public [requiredScopeMask, currentTimestamp, sessionNonce]} = AgentPolicy(20);
