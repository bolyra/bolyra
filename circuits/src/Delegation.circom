pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";

// Delegation: Proves a valid scope-narrowing delegation from delegator to delegatee.
//
// Privacy model (from eng review, outside voice finding #6):
//   Scope bits are PRIVATE. Only hash(scope, credentialCommitment) is PUBLIC.
//   Each hop publishes scopeCommitment = Poseidon(scope, credCommitment) as a public output.
//   The next hop takes the previous scopeCommitment as a public input and
//   proves its scope is a subset — without revealing either party's bits.
//
// How subset proof works without revealing bits:
//   The circuit takes BOTH scopes as private inputs (delegator + delegatee).
//   It verifies:
//     a) hash(delegatorScope, delegatorCredCommitment) == previousScopeCommitment (identity-bound chain link)
//     b) delegateeScope & ~delegatorScope == 0 (subset check)
//     c) hash(delegateeScope, delegateeCredCommitment) is output as the new scopeCommitment
//   The delegator's actual bits and identity never leave the circuit.
//
// Cumulative bit encoding invariant (from eng review):
//   bit 4 (unlimited financial) MUST have bits 2+3 set
//   bit 3 ($10k financial) MUST have bit 2 set
//   Enforced on the delegatee's scope at delegation time.
//
// Architecture:
//   - PLONK proving system (universal setup)
//   - Max chain depth: 3 (enforced by on-chain contract, not circuit)
//   - Each hop is one independent proof (iterative, not recursive)
//
template Delegation(MAX_DEPTH) {
    // ============ PRIVATE INPUTS ============

    // Delegator's scope (the entity granting permission)
    signal input delegatorScope;          // 64-bit permission bitmask

    // Delegatee's scope (the entity receiving permission)
    signal input delegateeScope;          // 64-bit, must be subset of delegator

    // Delegatee's expiry
    signal input delegateeExpiry;         // must be <= delegatorExpiry

    // Delegator's expiry (to enforce narrowing)
    signal input delegatorExpiry;

    // Delegator signs the delegation token
    // Token = Poseidon4(delegatorScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)
    signal input delegatorPubkeyAx;
    signal input delegatorPubkeyAy;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;

    // Delegator's credential commitment (binds scope to delegator's identity)
    signal input delegatorCredCommitment;

    // Delegatee's credential commitment (identifies WHO is receiving)
    signal input delegateeCredCommitment;

    // Delegatee Merkle proof: proves delegateeCredCommitment is enrolled in agentTree
    // (CIP-1: fixes phantom delegatee attack — previously unchecked)
    signal input delegateeMerkleProofLength;
    signal input delegateeMerkleProofIndex;
    signal input delegateeMerkleProofSiblings[MAX_DEPTH];

    // ============ PUBLIC INPUTS ============

    // The previous hop's scope commitment — links this hop to the chain
    // For hop 0 (direct from human/agent), this is the scope commitment
    // from the AgentPolicy circuit's public output.
    signal input previousScopeCommitment;

    // Session nonce (same as handshake, for replay protection)
    signal input sessionNonce;

    // ============ PUBLIC OUTPUTS ============

    // New scope commitment for the next hop (or for the verifier)
    signal output newScopeCommitment;

    // Delegation nullifier (unique per delegation per nonce)
    signal output delegationNullifier;

    // Delegatee Merkle root (CIP-1: verified on-chain against agentRootExists)
    signal output delegateeMerkleRoot;

    // ============ STEP 1: Range checks ============

    component delegatorScopeBits = Num2Bits(64);
    delegatorScopeBits.in <== delegatorScope;

    component delegateeScopeBits = Num2Bits(64);
    delegateeScopeBits.in <== delegateeScope;

    component delegateeExpiryRange = Num2Bits(64);
    delegateeExpiryRange.in <== delegateeExpiry;

    component delegatorExpiryRange = Num2Bits(64);
    delegatorExpiryRange.in <== delegatorExpiry;

    // ============ STEP 2: Verify delegator scope commitment matches previous hop ============
    // Identity-bound: Poseidon(delegatorScope, delegatorCredCommitment) must match
    // the previous hop's output. This prevents impersonation by actors with the same scope.

    component delegatorScopeHash = Poseidon(2);
    delegatorScopeHash.inputs[0] <== delegatorScope;
    delegatorScopeHash.inputs[1] <== delegatorCredCommitment;

    // This is the critical chain-linking constraint:
    // The delegator's actual scope + identity must hash to what the previous hop published.
    delegatorScopeHash.out === previousScopeCommitment;

    // ============ STEP 3: Scope subset check ============
    // delegateeScope & ~delegatorScope == 0
    // For each bit: if delegatee has it set, delegator must also have it set.

    signal scopeViolation[64];
    for (var i = 0; i < 64; i++) {
        scopeViolation[i] <== delegateeScopeBits.out[i] * (1 - delegatorScopeBits.out[i]);
        scopeViolation[i] === 0;
    }

    // ============ STEP 4: Cumulative bit encoding invariant ============
    // bit 4 → bits 2 and 3 must be set
    // bit 3 → bit 2 must be set
    //
    // Enforced on delegatee scope (delegator scope was already validated
    // when they were enrolled or received their delegation).

    // If bit 4 is set, bit 3 must be set: bit4 * (1 - bit3) == 0
    signal bit4_requires_bit3;
    bit4_requires_bit3 <== delegateeScopeBits.out[4] * (1 - delegateeScopeBits.out[3]);
    bit4_requires_bit3 === 0;

    // If bit 4 is set, bit 2 must be set: bit4 * (1 - bit2) == 0
    signal bit4_requires_bit2;
    bit4_requires_bit2 <== delegateeScopeBits.out[4] * (1 - delegateeScopeBits.out[2]);
    bit4_requires_bit2 === 0;

    // If bit 3 is set, bit 2 must be set: bit3 * (1 - bit2) == 0
    signal bit3_requires_bit2;
    bit3_requires_bit2 <== delegateeScopeBits.out[3] * (1 - delegateeScopeBits.out[2]);
    bit3_requires_bit2 === 0;

    // ============ STEP 5: Expiry narrowing ============
    // delegateeExpiry <= delegatorExpiry

    component expiryCheck = LessEqThan(64);
    expiryCheck.in[0] <== delegateeExpiry;
    expiryCheck.in[1] <== delegatorExpiry;
    expiryCheck.out === 1;

    // ============ STEP 6: Delegation token and signature verification ============
    // Delegator signs: Poseidon4(previousScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)
    // This binds the delegation to a specific delegatee with specific permissions.

    component tokenHash = Poseidon(4);
    tokenHash.inputs[0] <== previousScopeCommitment;
    tokenHash.inputs[1] <== delegateeCredCommitment;
    tokenHash.inputs[2] <== delegateeScope;
    tokenHash.inputs[3] <== delegateeExpiry;

    component sigVerify = EdDSAPoseidonVerifier();
    sigVerify.enabled <== 1;
    sigVerify.Ax <== delegatorPubkeyAx;
    sigVerify.Ay <== delegatorPubkeyAy;
    sigVerify.S <== sigS;
    sigVerify.R8x <== sigR8x;
    sigVerify.R8y <== sigR8y;
    sigVerify.M <== tokenHash.out;

    // ============ STEP 6b: Delegatee Merkle inclusion proof (CIP-1) ============
    // Proves delegateeCredCommitment is a leaf in the agentTree.
    // The computed root is a public output so the on-chain verifier can check it
    // against agentRootExists, preventing phantom delegatees.

    component delegateeMerkle = BinaryMerkleRoot(MAX_DEPTH);
    delegateeMerkle.leaf <== delegateeCredCommitment;
    delegateeMerkle.depth <== delegateeMerkleProofLength;
    delegateeMerkle.index <== delegateeMerkleProofIndex;
    for (var i = 0; i < MAX_DEPTH; i++) {
        delegateeMerkle.siblings[i] <== delegateeMerkleProofSiblings[i];
    }

    // ============ STEP 7: Outputs ============

    // New scope commitment for the chain (identity-bound)
    component delegateeScopeHash = Poseidon(2);
    delegateeScopeHash.inputs[0] <== delegateeScope;
    delegateeScopeHash.inputs[1] <== delegateeCredCommitment;
    newScopeCommitment <== delegateeScopeHash.out;

    // Delegation nullifier: unique per delegation per session
    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== tokenHash.out;
    nullifier.inputs[1] <== sessionNonce;
    delegationNullifier <== nullifier.out;

    // CIP-1: delegatee Merkle root output
    delegateeMerkleRoot <== delegateeMerkle.out;
}

component main {public [previousScopeCommitment, sessionNonce]} = Delegation(20);
