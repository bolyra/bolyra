pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";

// ModelInstanceBinding: Cryptographically binds a tool-call message to a
// specific (model, operator, permission) tuple, with provider attestation.
//
// This is the C7 construction from differentiation-autoresearch/winners/C7/,
// post-codex-review hardening (2026-05-09).
// It extends AgentPolicy with:
//   - In-circuit verification of a provider EdDSA signature over
//     credentialCommitment (= Poseidon5(modelHash, opPkAx, opPkAy,
//     permissionBitmask, expiryTimestamp)). The provider attestation
//     therefore binds not only model + operator but also the permissions
//     and expiry the operator is authorized to issue. Earlier versions
//     bound only Poseidon3(modelHash, opPkAx, opPkAy), which let the
//     operator self-grant expanded permissions or extend expiry without
//     provider knowledge (codex challenge HIGH, 2026-05-09).
//   - Provider key Merkle inclusion against an on-chain providerRegistryRoot
//     (depth 8, supports up to 256 enrolled providers).
//   - providerKeyCommitment = Poseidon2(providerPubkeyAx, providerPubkeyAy)
//     exposed as a public output. The verifier learns WHICH enrolled
//     provider signed, not just "some provider in the tree". This closes
//     the provider-anonymity attack from codex challenge CRITICAL.
//   - Per-message binding via messageHash output.
//   - modelOperatorFingerprint = Poseidon3(modelHash, operatorPubkeyAx,
//     permissionBitmask) as a public binding tuple.
//
// Honesty boundary (see spec/model-hash-preimage.md §2):
//   modelHash is a DECLARED identifier, not a runtime measurement. This
//   circuit proves authorization-time binding only. Inference-time model
//   substitution defense requires hardware attestation (TEE) and is OUT
//   OF SCOPE — closing that gap is a "Bolyra + TEE" companion track.
//
// Constraint budget (~23,100; -450 vs pre-hardening: removed Poseidon3 depAuth):
//   - Range checks (Num2Bits(64) x 3): 192
//   - Poseidon5 (credentialCommitment): 600
//   - Poseidon2 (providerKeyCommitment): 300
//   - BinaryMerkleRoot(8): 2,400
//   - EdDSAPoseidonVerifier (provider, over credentialCommitment): 6,000
//   - EdDSAPoseidonVerifier (operator, over credentialCommitment): 6,000
//   - BinaryMerkleRoot(20): 6,000
//   - Bitwise scope check (64 bits): 128
//   - Cumulative encoding (3 constraints): 3
//   - LessThan(64): 128
//   - Poseidon1 (messageHash): 240
//   - Poseidon2 (nullifier): 300
//   - Poseidon3 (scopeCommitment): 450
//   - Poseidon3 (modelOperatorFingerprint): 450
//
// Architecture:
//   - Groth16 (snarkjs) — interim, reusing pot16.ptau. PLONK universal setup
//     remains the production target; tracked in CEREMONY.md.
//   - 10 public signals (6 outputs + 4 public inputs incl. providerRegistryRoot)

template ModelInstanceBinding(AGENT_DEPTH, PROVIDER_DEPTH) {
    // ============ PRIVATE INPUTS ============

    // Agent credential fields
    signal input modelHash;                       // declared model identifier (see model-hash-preimage.md)
    signal input operatorPubkeyAx;                // operator EdDSA public key x
    signal input operatorPubkeyAy;                // operator EdDSA public key y
    signal input permissionBitmask;               // 64-bit permission bitfield
    signal input expiryTimestamp;                 // credential expiration (unix)

    // Operator EdDSA signature over credentialCommitment
    signal input operatorSigR8x;
    signal input operatorSigR8y;
    signal input operatorSigS;

    // Provider EdDSA public key (Anthropic / OpenAI / etc.) — never revealed
    signal input providerPubkeyAx;
    signal input providerPubkeyAy;

    // Provider EdDSA signature over deploymentAuthorization
    signal input providerSigR8x;
    signal input providerSigR8y;
    signal input providerSigS;

    // Tool-call payload digest (caller pre-hashes off-circuit, e.g.
    // SHA256(payload) reduced mod p). Field-element domain.
    signal input messagePlaintext;

    // Agent Merkle proof — proves credentialCommitment is enrolled
    signal input merkleProofLength;
    signal input merkleProofIndex;
    signal input merkleProofSiblings[AGENT_DEPTH];

    // Provider Merkle proof — proves providerKeyCommitment is enrolled
    signal input providerMerkleProofLength;
    signal input providerMerkleProofIndex;
    signal input providerMerkleProofSiblings[PROVIDER_DEPTH];

    // ============ PUBLIC INPUTS ============

    signal input requiredScopeMask;               // policy: required permission bits
    signal input currentTimestamp;                // verifier-supplied time
    signal input sessionNonce;                    // verifier-generated nonce
    signal input providerRegistryRoot;            // on-chain provider key root

    // ============ PUBLIC OUTPUTS ============

    signal output agentMerkleRoot;                // computed credential tree root
    signal output nullifierHash;                  // Poseidon2(credCommitment, sessionNonce)
    signal output scopeCommitment;                // Poseidon3(permBitmask, credCommitment, expiry)
    signal output messageHash;                    // Poseidon1(messagePlaintext)
    signal output modelOperatorFingerprint;       // Poseidon3(modelHash, opPkAx, permBitmask)
    signal output providerKeyCommitment;          // Poseidon2(provPkAx, provPkAy)

    // ============ STEP 1: Range checks on uint64 fields ============
    // Mirror AgentPolicy.circom: prevent field overflow attacks where
    // values > 2^64 pass the circuit but overflow Solidity uint64.

    component bitmaskRange = Num2Bits(64);
    bitmaskRange.in <== permissionBitmask;

    component expiryRange = Num2Bits(64);
    expiryRange.in <== expiryTimestamp;

    component timestampRange = Num2Bits(64);
    timestampRange.in <== currentTimestamp;

    // ============ STEP 2: Credential commitment ============
    // credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy,
    //                                  permissionBitmask, expiryTimestamp)
    // Identical shape to AgentPolicy for tree compatibility. Used as the
    // EdDSA message for BOTH operator AND provider attestations below.

    component credentialHash = Poseidon(5);
    credentialHash.inputs[0] <== modelHash;
    credentialHash.inputs[1] <== operatorPubkeyAx;
    credentialHash.inputs[2] <== operatorPubkeyAy;
    credentialHash.inputs[3] <== permissionBitmask;
    credentialHash.inputs[4] <== expiryTimestamp;

    signal credentialCommitment;
    credentialCommitment <== credentialHash.out;

    // ============ STEP 3: Provider attestation ============
    // (a) providerKeyCommitment = Poseidon2(provPkAx, provPkAy) — exposed as
    //     PUBLIC OUTPUT so the verifier learns WHICH enrolled provider
    //     signed (closes provider-anonymity attack from codex challenge).
    // (b) Merkle inclusion: provider key is enrolled in providerRegistryRoot.
    // (c) Provider EdDSA signature over credentialCommitment. Binds the
    //     provider's authorization to the FULL credential, including
    //     permissionBitmask and expiryTimestamp — not just (model, operator).
    //
    // The provider's actual public key (Ax, Ay) is still a private input.
    // The verifier learns providerKeyCommitment (a hash of it) plus that
    // it's enrolled in the registry — sufficient to identify the issuing
    // provider while keeping the raw key off-chain.

    component providerKeyHash = Poseidon(2);
    providerKeyHash.inputs[0] <== providerPubkeyAx;
    providerKeyHash.inputs[1] <== providerPubkeyAy;
    providerKeyCommitment <== providerKeyHash.out;

    component providerMerkle = BinaryMerkleRoot(PROVIDER_DEPTH);
    providerMerkle.leaf <== providerKeyCommitment;
    providerMerkle.depth <== providerMerkleProofLength;
    providerMerkle.index <== providerMerkleProofIndex;
    for (var i = 0; i < PROVIDER_DEPTH; i++) {
        providerMerkle.siblings[i] <== providerMerkleProofSiblings[i];
    }
    providerMerkle.out === providerRegistryRoot;

    component providerSigVerify = EdDSAPoseidonVerifier();
    providerSigVerify.enabled <== 1;
    providerSigVerify.Ax <== providerPubkeyAx;
    providerSigVerify.Ay <== providerPubkeyAy;
    providerSigVerify.S <== providerSigS;
    providerSigVerify.R8x <== providerSigR8x;
    providerSigVerify.R8y <== providerSigR8y;
    providerSigVerify.M <== credentialCommitment;

    // ============ STEP 4: Operator EdDSA signature ============
    // Operator signs the credential commitment. Provider also signs the
    // same credentialCommitment in Step 3, so any mismatch in (model,
    // operator, permissions, expiry) between the two attestations is
    // detected — both sigs must verify against an identical Poseidon5
    // preimage. Cross-operator attestation reuse and operator-side
    // permission inflation are therefore impossible (see C7 attacks.md,
    // MODEL-BIND-FORGE v2 §3, plus codex challenge HIGH 2026-05-09).

    component operatorSigVerify = EdDSAPoseidonVerifier();
    operatorSigVerify.enabled <== 1;
    operatorSigVerify.Ax <== operatorPubkeyAx;
    operatorSigVerify.Ay <== operatorPubkeyAy;
    operatorSigVerify.S <== operatorSigS;
    operatorSigVerify.R8x <== operatorSigR8x;
    operatorSigVerify.R8y <== operatorSigR8y;
    operatorSigVerify.M <== credentialCommitment;

    // ============ STEP 5: Agent Merkle membership ============

    component agentMerkle = BinaryMerkleRoot(AGENT_DEPTH);
    agentMerkle.leaf <== credentialCommitment;
    agentMerkle.depth <== merkleProofLength;
    agentMerkle.index <== merkleProofIndex;
    for (var i = 0; i < AGENT_DEPTH; i++) {
        agentMerkle.siblings[i] <== merkleProofSiblings[i];
    }
    agentMerkleRoot <== agentMerkle.out;

    // ============ STEP 6: Permission scope satisfaction ============
    // For each bit i: requiredBits[i] * (1 - permBits[i]) === 0

    component requiredBits = Num2Bits(64);
    requiredBits.in <== requiredScopeMask;

    signal scopeViolation[64];
    for (var i = 0; i < 64; i++) {
        scopeViolation[i] <== requiredBits.out[i] * (1 - bitmaskRange.out[i]);
        scopeViolation[i] === 0;
    }

    // ============ STEP 7: Cumulative bit encoding invariant ============
    // bit 4 (FINANCIAL_UNLIMITED) implies bits 2 (FINANCIAL_SMALL) + 3 (FINANCIAL_MEDIUM)
    // bit 3 (FINANCIAL_MEDIUM) implies bit 2

    signal bit4_requires_bit3;
    bit4_requires_bit3 <== bitmaskRange.out[4] * (1 - bitmaskRange.out[3]);
    bit4_requires_bit3 === 0;

    signal bit4_requires_bit2;
    bit4_requires_bit2 <== bitmaskRange.out[4] * (1 - bitmaskRange.out[2]);
    bit4_requires_bit2 === 0;

    signal bit3_requires_bit2;
    bit3_requires_bit2 <== bitmaskRange.out[3] * (1 - bitmaskRange.out[2]);
    bit3_requires_bit2 === 0;

    // ============ STEP 8: Expiry liveness check ============
    // currentTimestamp < expiryTimestamp

    component notExpired = LessThan(64);
    notExpired.in[0] <== currentTimestamp;
    notExpired.in[1] <== expiryTimestamp;
    notExpired.out === 1;

    // ============ STEP 9: Message binding ============
    // messageHash = Poseidon1(messagePlaintext)
    // Caller pre-hashes the tool-call payload off-circuit (e.g. SHA256 mod p)
    // and supplies the digest as messagePlaintext. This circuit applies a
    // Poseidon round to produce a domain-separated, field-canonical hash
    // exposed as a public output.

    component messageHashCircuit = Poseidon(1);
    messageHashCircuit.inputs[0] <== messagePlaintext;
    messageHash <== messageHashCircuit.out;

    // ============ STEP 10: Nullifier (replay protection) ============
    // nullifierHash = Poseidon2(credentialCommitment, sessionNonce)
    // Matches AgentPolicy convention so on-chain nullifier mappings
    // are namespace-compatible.

    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== credentialCommitment;
    nullifier.inputs[1] <== sessionNonce;
    nullifierHash <== nullifier.out;

    // ============ STEP 11: Scope commitment (delegation chain seed) ============
    // scopeCommitment = Poseidon3(permBitmask, credentialCommitment, expiry)
    // Matches AgentPolicy + Delegation chain-linking shape (UC3.2 fix).

    component scopeHash = Poseidon(3);
    scopeHash.inputs[0] <== permissionBitmask;
    scopeHash.inputs[1] <== credentialCommitment;
    scopeHash.inputs[2] <== expiryTimestamp;
    scopeCommitment <== scopeHash.out;

    // ============ STEP 12: Model-operator fingerprint (public binding) ============
    // modelOperatorFingerprint = Poseidon3(modelHash, opPkAx, permBitmask)
    // The auditable handle: an examiner can verify that a class of
    // (model × operator × permission) acted on data, without learning
    // session-specific signatures or call counts.
    //
    // Note: only operatorPubkeyAx is committed (not Ay). On Baby Jubjub,
    // (Ax, Ay) lies on a fixed curve, so Ax determines Ay up to sign.
    // Including only Ax is sufficient for the operator-class linkability
    // intended by this fingerprint while keeping the constraint to Poseidon3.

    component fingerprintHash = Poseidon(3);
    fingerprintHash.inputs[0] <== modelHash;
    fingerprintHash.inputs[1] <== operatorPubkeyAx;
    fingerprintHash.inputs[2] <== permissionBitmask;
    modelOperatorFingerprint <== fingerprintHash.out;
}

// Default compilation: agent depth 20 (~1M agents), provider depth 8 (256 providers).
component main {public [requiredScopeMask, currentTimestamp, sessionNonce, providerRegistryRoot]} = ModelInstanceBinding(20, 8);
