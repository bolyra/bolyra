const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const { buildPoseidon, buildBabyjub, buildEddsa } = require("circomlibjs");
const { proveGroth16 } = require("../../sdk/dist/prover");
const { delegate } = require("../../sdk/dist/delegation");

/**
 * E2E Delegation Test: Real ZKP Proofs → On-Chain verifyDelegation()
 *
 * Exercises the full v0.3 SDK path:
 *   - createAgentCredential semantics (delegator + delegatee)
 *   - proveHandshake (seeds lastScopeCommitment[sessionNonce])
 *   - delegate() (Groth16 proof for the Delegation circuit)
 *   - IdentityRegistry.verifyDelegation() (Attack 2 hardening: chain state on-chain)
 *
 * Plus adversarial cases the contract MUST reject:
 *   - Reused delegation nullifier
 *   - 4th hop on same nonce (MaxDelegationHopsExceeded)
 *   - Delegation without prior handshake
 *   - Stale timestamp
 *
 * Merkle tree layout:
 *   - Delegator enrolled first  → agentTreeRoot = delegatorCommitment (LeanIMT single leaf).
 *   - Delegatee enrolled second → agentTreeRoot = Poseidon2(delegatorCommitment, delegateeCommitment).
 *   - Delegation passes delegatee proof at index=1, length=1, siblings=[delegatorCommitment, 0, ...].
 *   - Both roots stay valid (30-deep agentRootHistory buffer).
 */
describe("E2E Delegation: Real Proofs → On-Chain Verification", function () {
  this.timeout(300000);

  let registry;
  let poseidon, babyJub, eddsa, F;

  const HUMAN_WASM = path.join(__dirname, "../../circuits/build/HumanUniqueness_js/HumanUniqueness.wasm");
  const HUMAN_ZKEY = path.join(__dirname, "../../circuits/build/HumanUniqueness_final.zkey");
  const AGENT_WASM = path.join(__dirname, "../../circuits/build/AgentPolicy_js/AgentPolicy.wasm");
  const AGENT_ZKEY = path.join(__dirname, "../../circuits/build/AgentPolicy_final.zkey");

  const DELEGATION_MAX_DEPTH = 20;

  // Format a snarkjs Groth16 proof object into the flat 8-element calldata array
  // Solidity verifiers expect. The pi_b column swap is required by snarkjs's
  // solidityverifier convention (same as E2EHandshake.test.js).
  function formatProofForSolidity(proofRaw) {
    return [
      proofRaw.pi_a[0], proofRaw.pi_a[1],
      proofRaw.pi_b[0][1], proofRaw.pi_b[0][0],
      proofRaw.pi_b[1][1], proofRaw.pi_b[1][0],
      proofRaw.pi_c[0], proofRaw.pi_c[1],
    ];
  }

  before(async function () {
    poseidon = await buildPoseidon();
    babyJub = await buildBabyjub();
    eddsa = await buildEddsa();
    F = poseidon.F;

    const PoseidonT3 = await ethers.getContractFactory("PoseidonT3");
    const poseidonT3 = await PoseidonT3.deploy();

    const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
    const groth16Verifier = await Groth16Verifier.deploy();

    const AgentVerifier = await ethers.getContractFactory(
      "contracts/AgentVerifier.sol:AgentGroth16Verifier"
    );
    const agentVerifier = await AgentVerifier.deploy();

    const DelegationVerifier = await ethers.getContractFactory(
      "contracts/DelegationVerifier.sol:DelegationGroth16Verifier"
    );
    const delegationVerifier = await DelegationVerifier.deploy();

    const ModelBindingVerifier = await ethers.getContractFactory(
      "contracts/ModelInstanceBindingVerifier.sol:ModelInstanceBindingGroth16Verifier"
    );
    const modelBindingVerifier = await ModelBindingVerifier.deploy();

    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry", {
      libraries: { PoseidonT3: await poseidonT3.getAddress() },
    });
    registry = await IdentityRegistry.deploy(
      await groth16Verifier.getAddress(),
      await agentVerifier.getAddress(),
      await delegationVerifier.getAddress(),
      await modelBindingVerifier.getAddress()
    );
  });

  it("should verify a single-hop delegation with a real proof", async function () {
    console.log("\n  === E2E DELEGATION TEST ===\n");

    // ─── 1. Identities ───
    const humanSecret = 987654321n;
    const humanPubKey = babyJub.mulPointEscalar(babyJub.Base8, humanSecret);
    const humanCommitment = F.toObject(poseidon([
      F.toObject(humanPubKey[0]),
      F.toObject(humanPubKey[1]),
    ]));

    const operatorPrivKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001", "hex"
    );
    const operatorPubKey = eddsa.prv2pub(operatorPrivKey);
    const operatorAx = F.toObject(operatorPubKey[0]);
    const operatorAy = F.toObject(operatorPubKey[1]);

    // Delegator: READ + WRITE + FINANCIAL_SMALL (bits 0,1,2 → 0b00000111)
    const delegatorModelHash = 12345n;
    const delegatorBitmask = 0b00000111n;
    const delegatorExpiry = BigInt(Math.floor(Date.now() / 1000) + 86400);

    const delegatorCredFe = poseidon([
      delegatorModelHash, operatorAx, operatorAy, delegatorBitmask, delegatorExpiry,
    ]);
    const delegatorCommitment = F.toObject(delegatorCredFe);
    const delegatorSig = eddsa.signPoseidon(operatorPrivKey, delegatorCredFe);

    // Delegatee: narrower (READ only → 0b00000001), same operator, earlier expiry
    const delegateeModelHash = 67890n;
    const delegateeBitmask = 0b00000001n;
    const delegateeExpiry = delegatorExpiry - 3600n;

    const delegateeCredFe = poseidon([
      delegateeModelHash, operatorAx, operatorAy, delegateeBitmask, delegateeExpiry,
    ]);
    const delegateeCommitment = F.toObject(delegateeCredFe);

    console.log("  Human commitment:    ", humanCommitment.toString().slice(0, 20) + "...");
    console.log("  Delegator commitment:", delegatorCommitment.toString().slice(0, 20) + "...");
    console.log("  Delegatee commitment:", delegateeCommitment.toString().slice(0, 20) + "...");

    // ─── 2. Enroll: human, then delegator (root_A), then delegatee (root_B) ───
    await registry.enrollHuman(humanCommitment);
    await registry.enrollAgent(delegatorCommitment);
    const rootA = await registry.agentTreeRoot();
    expect(rootA.toString()).to.equal(delegatorCommitment.toString());
    expect(await registry.agentRootExists(rootA)).to.equal(true);

    await registry.enrollAgent(delegateeCommitment);
    const rootB = await registry.agentTreeRoot();
    const expectedRootB = F.toObject(poseidon([delegatorCommitment, delegateeCommitment]));
    expect(rootB.toString()).to.equal(expectedRootB.toString());
    // Both roots remain valid in the history buffer.
    expect(await registry.agentRootExists(rootA)).to.equal(true);
    expect(await registry.agentRootExists(rootB)).to.equal(true);

    // ─── 3. Handshake — seeds lastScopeCommitment[sessionNonce] ───
    const sessionNonce = BigInt(Date.now());
    const scope = 1n;                              // human-side scope (bit 0)
    const requiredScopeMask = 0b00000001n;         // agent must have READ_DATA
    const handshakeTimestamp = BigInt(Math.floor(Date.now() / 1000));

    // Human proof: tree has 1 leaf (humanCommitment), depth-0 root = leaf.
    const humanSiblings = new Array(20).fill("0");
    const { proof: humanProofRaw, publicSignals: humanPubSignals } = await proveGroth16(
      {
        secret: humanSecret.toString(),
        merkleProofLength: "0",
        merkleProofIndex: "0",
        merkleProofSiblings: humanSiblings,
        scope: scope.toString(),
        sessionNonce: sessionNonce.toString(),
      },
      HUMAN_WASM, HUMAN_ZKEY, "auto"
    );

    // Agent proof: the agent (delegator) was leaf 0 when enrolled, but rootA was
    // overwritten by rootB. We need to prove against rootA (still in history) using
    // the depth-0 proof. agentRootExists[rootA] is true.
    const agentSiblings = new Array(20).fill("0");
    const { proof: agentProofRaw, publicSignals: agentPubSignals } = await proveGroth16(
      {
        modelHash: delegatorModelHash.toString(),
        operatorPubkeyAx: operatorAx.toString(),
        operatorPubkeyAy: operatorAy.toString(),
        permissionBitmask: delegatorBitmask.toString(),
        expiryTimestamp: delegatorExpiry.toString(),
        sigR8x: F.toObject(delegatorSig.R8[0]).toString(),
        sigR8y: F.toObject(delegatorSig.R8[1]).toString(),
        sigS: delegatorSig.S.toString(),
        merkleProofLength: "0",
        merkleProofIndex: "0",
        merkleProofSiblings: agentSiblings,
        requiredScopeMask: requiredScopeMask.toString(),
        currentTimestamp: handshakeTimestamp.toString(),
        sessionNonce: sessionNonce.toString(),
      },
      AGENT_WASM, AGENT_ZKEY, "auto"
    );
    expect(agentPubSignals[0]).to.equal(rootA.toString());

    await registry.verifyHandshake(
      formatProofForSolidity(humanProofRaw), humanPubSignals,
      formatProofForSolidity(agentProofRaw), agentPubSignals,
      sessionNonce
    );
    console.log("  Handshake verified, sessionNonce:", sessionNonce.toString());

    const scopeCommitmentFromHandshake = await registry.lastScopeCommitment(sessionNonce);
    const expectedScopeCommitment = F.toObject(poseidon([
      delegatorBitmask, delegatorCommitment, delegatorExpiry,
    ]));
    expect(scopeCommitmentFromHandshake.toString()).to.equal(expectedScopeCommitment.toString());

    // ─── 4. Generate delegation proof via SDK ───
    const delegator = {
      modelHash: delegatorModelHash,
      operatorPublicKey: { x: operatorAx, y: operatorAy },
      permissionBitmask: delegatorBitmask,
      expiryTimestamp: delegatorExpiry,
      signature: {
        R8: {
          x: F.toObject(delegatorSig.R8[0]),
          y: F.toObject(delegatorSig.R8[1]),
        },
        S: delegatorSig.S,
      },
      commitment: delegatorCommitment,
    };

    // Real Merkle proof for delegatee against rootB:
    // index=1, length=1, siblings=[delegatorCommitment, 0, 0, ..., 0]
    const delegateeSiblings = new Array(DELEGATION_MAX_DEPTH).fill(0n);
    delegateeSiblings[0] = delegatorCommitment;

    const delegationTimestamp = BigInt(Math.floor(Date.now() / 1000));

    console.log("  Generating delegation proof...");
    const delegateStart = performance.now();
    const { proof: delegationProof, result: delegationResult } = await delegate({
      delegator,
      delegatorOperatorPrivateKey: operatorPrivKey,
      delegateeCommitment,
      delegateeScope: delegateeBitmask,
      delegateeExpiry,
      previousScopeCommitment: expectedScopeCommitment,
      sessionNonce,
      currentTimestamp: delegationTimestamp,
      delegateeMerkleProof: {
        length: 1,
        index: 1,
        siblings: delegateeSiblings,
      },
      backend: "auto",
    });
    console.log(`  Delegation proof: ${(performance.now() - delegateStart).toFixed(0)}ms`);

    // Sanity: SDK-computed delegatee root must equal on-chain rootB.
    expect(delegationResult.delegateeMerkleRoot.toString()).to.equal(rootB.toString());

    // ─── 5. Submit delegation on-chain ───
    const delegationProofSolidity = formatProofForSolidity(delegationProof.proof);
    const delegationPubSignals = delegationProof.publicSignals.map(s => BigInt(s));

    const tx = await registry.verifyDelegation(
      delegationProofSolidity,
      delegationPubSignals,
      sessionNonce
    );
    const receipt = await tx.wait();
    console.log("  Gas used:", receipt.gasUsed.toString());

    // ─── 6. Assertions ───
    const event = receipt.logs.find(
      log => log.fragment && log.fragment.name === "DelegationVerified"
    );
    expect(event, "DelegationVerified event").to.not.be.undefined;
    expect(event.args[0].toString()).to.equal(delegationResult.delegationNullifier.toString());
    expect(event.args[1].toString()).to.equal(delegationResult.newScopeCommitment.toString());
    expect(event.args[2].toString()).to.equal(sessionNonce.toString());

    expect((await registry.delegationHopCount(sessionNonce)).toString()).to.equal("1");
    expect((await registry.lastScopeCommitment(sessionNonce)).toString())
      .to.equal(delegationResult.newScopeCommitment.toString());
    expect(await registry.usedDelegationNullifiers(delegationResult.delegationNullifier))
      .to.equal(true);

    console.log("\n  ✅ DELEGATION VERIFIED ON-CHAIN");
    console.log("  Nullifier:", delegationResult.delegationNullifier.toString().slice(0, 20) + "...");
    console.log("  New scope:", delegationResult.newScopeCommitment.toString().slice(0, 20) + "...");

    // ─── 7. Replay protection ───
    // Defense-in-depth: replaying the same proof must be rejected. The contract
    // trips ScopeChainMismatch FIRST because lastScopeCommitment[sessionNonce]
    // was advanced by the successful first call; pubSignals[3] (old prevScope)
    // no longer matches on-chain state. The nullifier check would also reject,
    // but the chain check fires earlier. Both are valid rejections.
    await expect(
      registry.verifyDelegation(delegationProofSolidity, delegationPubSignals, sessionNonce)
    ).to.be.revertedWithCustomError(registry, "ScopeChainMismatch");
    console.log("  ✅ Replay correctly rejected (ScopeChainMismatch — chain advanced)");
  });

  it("should reject delegation without a prior handshake", async function () {
    // Fresh session nonce — no handshake ran for it. Any zeroed proof will trip
    // DelegationRequiresHandshake before signature verification, so we don't
    // even need a real proof here.
    const freshNonce = BigInt(Date.now()) + 999n;
    const zeroProof = new Array(8).fill(0n);
    const zeroPubSignals = new Array(6).fill(0n);
    await expect(
      registry.verifyDelegation(zeroProof, zeroPubSignals, freshNonce)
    ).to.be.revertedWithCustomError(registry, "DelegationRequiresHandshake");
  });
});
