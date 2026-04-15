const { expect } = require("chai");
const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const path = require("path");
const { buildPoseidon, buildBabyjub, buildEddsa } = require("circomlibjs");

/**
 * E2E Smoke Test: Real ZKP Proofs → On-Chain Verification
 *
 * This is the mandatory smoke test per prior learning (smoke-test-real-crypto-once).
 * Generates real Groth16 + PLONK proofs and verifies them on-chain.
 *
 * WHAT THIS PROVES:
 *   - Circom circuits produce valid witnesses
 *   - snarkjs generates valid proofs from those witnesses
 *   - Auto-generated Solidity verifiers accept those proofs
 *   - IdentityRegistry correctly orchestrates the full handshake
 *   - Public signals flow correctly from circuit → proof → contract
 */
describe("E2E Handshake: Real Proofs → On-Chain Verification", function () {
  this.timeout(300000); // proof generation takes time

  let registry;
  let poseidon, babyJub, eddsa, F;

  // Circuit artifacts
  const HUMAN_WASM = path.join(__dirname, "../../circuits/build/HumanUniqueness_js/HumanUniqueness.wasm");
  const HUMAN_ZKEY = path.join(__dirname, "../../circuits/build/HumanUniqueness_final.zkey");
  const AGENT_WASM = path.join(__dirname, "../../circuits/build/AgentPolicy_js/AgentPolicy.wasm");
  const AGENT_ZKEY = path.join(__dirname, "../../circuits/build/AgentPolicy_plonk.zkey");

  before(async function () {
    poseidon = await buildPoseidon();
    babyJub = await buildBabyjub();
    eddsa = await buildEddsa();
    F = poseidon.F;

    // Deploy all contracts
    const [deployer] = await ethers.getSigners();

    const PoseidonT3 = await ethers.getContractFactory("PoseidonT3");
    const poseidonT3 = await PoseidonT3.deploy();

    const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
    const groth16Verifier = await Groth16Verifier.deploy();

    const PlonkVerifier = await ethers.getContractFactory("PlonkVerifier");
    const plonkVerifier = await PlonkVerifier.deploy();

    const DelegationVerifier = await ethers.getContractFactory("DelegationPlonkVerifier");
    const delegationVerifier = await DelegationVerifier.deploy();

    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry", {
      libraries: { PoseidonT3: await poseidonT3.getAddress() },
    });
    registry = await IdentityRegistry.deploy(
      await groth16Verifier.getAddress(),
      await plonkVerifier.getAddress(),
      await delegationVerifier.getAddress()
    );
  });

  it("should verify a full mutual handshake with real proofs", async function () {
    console.log("\n  === E2E HANDSHAKE TEST ===\n");

    // ─── 1. Create human identity (EdDSA, Semaphore v4 compatible) ───
    const humanSecret = 123456789n;
    const humanPubKey = babyJub.mulPointEscalar(babyJub.Base8, humanSecret);
    const humanAx = F.toObject(humanPubKey[0]);
    const humanAy = F.toObject(humanPubKey[1]);
    const humanCommitment = F.toObject(poseidon([humanAx, humanAy]));
    console.log("  Human commitment:", humanCommitment.toString().slice(0, 20) + "...");

    // ─── 2. Create agent credential (EdDSA signed) ───
    const operatorPrivKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001", "hex"
    );
    const operatorPubKey = eddsa.prv2pub(operatorPrivKey);

    const modelHash = 12345n;
    const permissionBitmask = 0b00000111n; // read + write + financial <$100
    const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + 86400);

    const agentCommitmentFe = poseidon([
      modelHash,
      F.toObject(operatorPubKey[0]),
      permissionBitmask,
      expiryTimestamp,
    ]);
    const agentCommitment = F.toObject(agentCommitmentFe);
    const agentSig = eddsa.signPoseidon(operatorPrivKey, agentCommitmentFe);
    console.log("  Agent commitment:", agentCommitment.toString().slice(0, 20) + "...");

    // ─── 3. Enroll both into the registry ───
    await registry.enrollHuman(humanCommitment);
    await registry.enrollAgent(agentCommitment);
    console.log("  Enrolled human and agent on-chain");

    const humanRoot = await registry.humanTreeRoot();
    const agentRoot = await registry.agentTreeRoot();

    // ─── 4. Build Merkle proofs ───
    // LeanIMT with 1 leaf: root = leaf itself (depth 0, no siblings needed).
    // The BinaryMerkleRoot circuit with depth=0 returns the leaf directly.
    const siblings = new Array(20).fill("0");

    // ─── 5. Generate Human proof (Groth16) ───
    const scope = 1n;
    const sessionNonce = BigInt(Date.now());

    console.log("  Generating Groth16 proof (human)...");
    const humanStart = performance.now();
    const { proof: humanProofRaw, publicSignals: humanPubSignals } =
      await snarkjs.groth16.fullProve(
        {
          secret: humanSecret.toString(),
          merkleProofLength: "0",
          merkleProofIndex: "0",
          merkleProofSiblings: siblings,
          scope: scope.toString(),
          sessionNonce: sessionNonce.toString(),
        },
        HUMAN_WASM,
        HUMAN_ZKEY
      );
    console.log(`  Human proof: ${((performance.now() - humanStart) / 1000).toFixed(2)}s`);

    // Verify the computed root matches what's on-chain
    const proofHumanRoot = humanPubSignals[0];
    console.log("  Proof human root:", proofHumanRoot.slice(0, 20) + "...");
    console.log("  Chain human root:", humanRoot.toString().slice(0, 20) + "...");
    expect(proofHumanRoot).to.equal(humanRoot.toString());

    // ─── 6. Generate Agent proof (PLONK) ───
    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
    const requiredScopeMask = 0b00000011n; // require read + write

    console.log("  Generating PLONK proof (agent)...");
    const agentStart = performance.now();
    const { proof: agentProofRaw, publicSignals: agentPubSignals } =
      await snarkjs.plonk.fullProve(
        {
          modelHash: modelHash.toString(),
          operatorPubkeyAx: F.toObject(operatorPubKey[0]).toString(),
          operatorPubkeyAy: F.toObject(operatorPubKey[1]).toString(),
          permissionBitmask: permissionBitmask.toString(),
          expiryTimestamp: expiryTimestamp.toString(),
          sigR8x: F.toObject(agentSig.R8[0]).toString(),
          sigR8y: F.toObject(agentSig.R8[1]).toString(),
          sigS: agentSig.S.toString(),
          merkleProofLength: "0",
          merkleProofIndex: "0",
          merkleProofSiblings: siblings,
          requiredScopeMask: requiredScopeMask.toString(),
          currentTimestamp: currentTimestamp.toString(),
          sessionNonce: sessionNonce.toString(),
        },
        AGENT_WASM,
        AGENT_ZKEY
      );
    console.log(`  Agent proof: ${((performance.now() - agentStart) / 1000).toFixed(2)}s`);

    // Verify agent root matches
    const proofAgentRoot = agentPubSignals[0];
    console.log("  Proof agent root:", proofAgentRoot.slice(0, 20) + "...");
    console.log("  Chain agent root:", agentRoot.toString().slice(0, 20) + "...");
    expect(proofAgentRoot).to.equal(agentRoot.toString());

    // ─── 7. Format proofs for Solidity ───

    // Groth16: [pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1]]
    const humanProof = [
      humanProofRaw.pi_a[0], humanProofRaw.pi_a[1],
      humanProofRaw.pi_b[0][1], humanProofRaw.pi_b[0][0],
      humanProofRaw.pi_b[1][1], humanProofRaw.pi_b[1][0],
      humanProofRaw.pi_c[0], humanProofRaw.pi_c[1],
    ];

    // PLONK: 24 uint256 values from the proof object
    const agentProofCalldata = await snarkjs.plonk.exportSolidityCallData(
      agentProofRaw, agentPubSignals
    );
    // Parse the calldata string: first array is proof[24], second is pubSignals[6]
    const calldataParts = agentProofCalldata.split(",");
    // The proof is the first 24 values inside the first brackets
    const proofStr = agentProofCalldata.match(/\[([^\]]+)\]/)[1];
    const agentProof = proofStr.split(",").map(s => s.trim().replace(/"/g, ""));

    // ─── 8. Submit handshake to on-chain registry ───
    console.log("  Submitting handshake to on-chain registry...");
    const tx = await registry.verifyHandshake(
      humanProof,
      humanPubSignals,
      agentProof,
      agentPubSignals,
      sessionNonce
    );

    const receipt = await tx.wait();
    console.log("  Gas used:", receipt.gasUsed.toString());

    // ─── 9. Verify the HandshakeVerified event was emitted ───
    const event = receipt.logs.find(
      log => log.fragment && log.fragment.name === "HandshakeVerified"
    );
    expect(event).to.not.be.undefined;

    const humanNullifier = humanPubSignals[1];
    const agentNullifier = agentPubSignals[1];
    expect(event.args[0].toString()).to.equal(humanNullifier);
    expect(event.args[1].toString()).to.equal(agentNullifier);
    expect(event.args[2].toString()).to.equal(sessionNonce.toString());

    console.log("\n  ✅ E2E HANDSHAKE VERIFIED ON-CHAIN");
    console.log("  Human nullifier:", humanNullifier.slice(0, 20) + "...");
    console.log("  Agent nullifier:", agentNullifier.slice(0, 20) + "...");
    console.log("  Nonce:", sessionNonce.toString());
    console.log("  Gas:", receipt.gasUsed.toString());

    // ─── 10. Verify replay protection ───
    console.log("\n  Testing replay protection...");
    await expect(
      registry.verifyHandshake(
        humanProof, humanPubSignals,
        agentProof, agentPubSignals,
        sessionNonce
      )
    ).to.be.revertedWithCustomError(registry, "NonceAlreadyUsed");
    console.log("  ✅ Replay correctly rejected");
  });
});
