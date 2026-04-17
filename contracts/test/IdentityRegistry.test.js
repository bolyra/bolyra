const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IdentityRegistry", function () {
  let registry;
  let owner;
  let addr1;

  beforeEach(async function () {
    [owner, addr1] = await ethers.getSigners();

    // Deploy PoseidonT3 library (required by LeanIMT)
    const PoseidonT3 = await ethers.getContractFactory("PoseidonT3");
    const poseidonT3 = await PoseidonT3.deploy();
    await poseidonT3.waitForDeployment();

    // Deploy Groth16 verifier (HumanUniqueness)
    const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
    const groth16Verifier = await Groth16Verifier.deploy();
    await groth16Verifier.waitForDeployment();

    // Deploy PLONK verifier (AgentPolicy)
    const PlonkVerifier = await ethers.getContractFactory("contracts/AgentVerifier.sol:PlonkVerifier");
    const plonkVerifier = await PlonkVerifier.deploy();
    await plonkVerifier.waitForDeployment();

    // Deploy Delegation PLONK verifier
    const DelegationVerifier = await ethers.getContractFactory("DelegationPlonkVerifier");
    const delegationVerifier = await DelegationVerifier.deploy();
    await delegationVerifier.waitForDeployment();

    // Link PoseidonT3 and deploy IdentityRegistry with verifier addresses
    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry", {
      libraries: {
        PoseidonT3: await poseidonT3.getAddress(),
      },
    });
    registry = await IdentityRegistry.deploy(
      await groth16Verifier.getAddress(),
      await plonkVerifier.getAddress(),
      await delegationVerifier.getAddress()
    );
    await registry.waitForDeployment();
  });

  describe("Enrollment", function () {
    it("should enroll a human identity", async function () {
      const commitment = 12345n;
      await expect(registry.enrollHuman(commitment))
        .to.emit(registry, "HumanEnrolled");

      // LeanIMT: single leaf root = leaf itself
      expect(await registry.humanTreeRoot()).to.equal(commitment);
      expect(await registry.humanTreeSize()).to.equal(1n);
    });

    it("should enroll an agent credential", async function () {
      const commitment = 67890n;
      await expect(registry.enrollAgent(commitment))
        .to.emit(registry, "AgentEnrolled");

      expect(await registry.agentTreeSize()).to.equal(1n);
    });

    it("should track agent root history", async function () {
      // Enroll an agent, check its root is in history
      const commitment = 11111n;
      await registry.enrollAgent(commitment);

      const root = await registry.agentTreeRoot();
      expect(await registry.isValidAgentRoot(root)).to.be.true;
    });

    it("should maintain root history buffer (circular)", async function () {
      // Enroll 31 agents (more than ROOT_HISTORY_SIZE=30)
      // The first root should be evicted
      const commitments = [];
      for (let i = 1; i <= 31; i++) {
        commitments.push(BigInt(i * 1000));
      }

      // Enroll first agent, record its root
      await registry.enrollAgent(commitments[0]);
      const firstRoot = await registry.agentTreeRoot();

      // Enroll 30 more agents
      for (let i = 1; i < 31; i++) {
        await registry.enrollAgent(commitments[i]);
      }

      // First root should be evicted from history
      expect(await registry.isValidAgentRoot(firstRoot)).to.be.false;

      // Latest root should still be valid
      const latestRoot = await registry.agentTreeRoot();
      expect(await registry.isValidAgentRoot(latestRoot)).to.be.true;
    });

    it("should reject enrollment from non-owner", async function () {
      await expect(
        registry.connect(addr1).enrollHuman(12345n)
      ).to.be.revertedWithCustomError(registry, "NotOwner");
    });

    it("should batch enroll humans", async function () {
      await registry.enrollHumanBatch([100n, 200n, 300n]);
      expect(await registry.humanTreeSize()).to.equal(3n);
    });

    it("should batch enroll agents", async function () {
      await registry.enrollAgentBatch([100n, 200n, 300n]);
      expect(await registry.agentTreeSize()).to.equal(3n);
    });
  });

  describe("Revocation", function () {
    it("should revoke a human identity", async function () {
      const nullifier = 99999n;
      await expect(registry.revokeHuman(nullifier))
        .to.emit(registry, "IdentityRevoked")
        .withArgs(nullifier);

      expect(await registry.humanRevocations(nullifier)).to.be.true;
    });

    it("should revoke an agent credential via tree-level update", async function () {
      // Enroll two agents so the tree has size > 1 (update requires leaf has a sibling path)
      const commitmentA = 88888n;
      const commitmentB = 77777n;
      await registry.enrollAgent(commitmentA);
      await registry.enrollAgent(commitmentB);

      // Sibling of leaf 0 (commitmentA) at depth 0 is leaf 1 (commitmentB)
      const siblings = [commitmentB];

      await expect(registry.revokeAgent(commitmentA, siblings))
        .to.emit(registry, "AgentTreeRevocation")
        .withArgs(commitmentA);

      // After update, commitmentA is no longer in the tree
      // (LeanIMT _has returns false because the leaf was replaced with 0)
    });
  });

  describe("Handshake verification", function () {
    // Replay protection and successful handshake are covered by E2E test
    // (E2EHandshake.test.js) which uses real proofs. Fake proofs no longer
    // pass the real on-chain verifiers, which is correct behavior.
    it("should reject replayed nonces (covered by E2E test)", async function () {
      // Nonce replay is verified in E2EHandshake.test.js with real proofs.
      // Here we just verify the usedNonces mapping works directly.
      await registry.enrollHuman(100n);
      await registry.enrollAgent(200n);
      // Direct mapping check (no handshake needed)
      expect(await registry.usedNonces(42n)).to.be.false;
    });

    it("should reject handshake with revoked human", async function () {
      await registry.enrollHuman(100n);
      await registry.enrollAgent(200n);

      const humanRoot = await registry.humanTreeRoot();
      const agentRoot = await registry.agentTreeRoot();
      const nonce = 43n;
      const humanNullifier = 999n;

      // Revoke the human
      await registry.revokeHuman(humanNullifier);

      const humanProof = new Array(8).fill(0n);
      const humanPubSignals = [humanRoot, humanNullifier, 2n, 3n, nonce];
      const agentProof = new Array(24).fill(0n);
      const agentPubSignals = [agentRoot, 4n, 5n, 6n, 7n, nonce];

      await expect(
        registry.verifyHandshake(
          humanProof, humanPubSignals,
          agentProof, agentPubSignals,
          nonce
        )
      ).to.be.revertedWithCustomError(registry, "HumanIdentityRevoked");
    });

    it("should reject handshake with stale agent root", async function () {
      await registry.enrollHuman(100n);
      // Don't enroll any agents — agentTree root will be 0

      const humanRoot = await registry.humanTreeRoot();
      const fakeAgentRoot = 999999n; // not in history
      const nonce = 44n;

      const humanProof = new Array(8).fill(0n);
      const humanPubSignals = [humanRoot, 1n, 2n, 3n, nonce];
      const agentProof = new Array(24).fill(0n);
      const agentPubSignals = [fakeAgentRoot, 4n, 5n, 6n, 7n, nonce];

      await expect(
        registry.verifyHandshake(
          humanProof, humanPubSignals,
          agentProof, agentPubSignals,
          nonce
        )
      ).to.be.revertedWithCustomError(registry, "StaleAgentRoot");
    });

    // HandshakeVerified event emission is verified in E2EHandshake.test.js
    // with real proofs. Fake proofs no longer pass real verifiers.
    it("should emit HandshakeVerified on success (covered by E2E test)", async function () {
      // This test validates that the event exists in the contract ABI.
      const filter = registry.filters.HandshakeVerified();
      expect(filter).to.not.be.undefined;
    });

    it("should reject handshake with nonce mismatch in human pubSignals (Fix #1)", async function () {
      await registry.enrollHuman(100n);
      await registry.enrollAgent(200n);

      const humanRoot = await registry.humanTreeRoot();
      const agentRoot = await registry.agentTreeRoot();
      const nonce = 45n;

      const humanProof = new Array(8).fill(0n);
      // humanPubSignals[4] = wrong nonce (999)
      const humanPubSignals = [humanRoot, 1n, 2n, 3n, 999n];
      const agentProof = new Array(24).fill(0n);
      const agentPubSignals = [agentRoot, 4n, 5n, 6n, 7n, nonce];

      await expect(
        registry.verifyHandshake(
          humanProof, humanPubSignals,
          agentProof, agentPubSignals,
          nonce
        )
      ).to.be.revertedWithCustomError(registry, "NonceMismatch");
    });

    it("should reject handshake with nonce mismatch in agent pubSignals (Fix #1)", async function () {
      await registry.enrollHuman(100n);
      await registry.enrollAgent(200n);

      const humanRoot = await registry.humanTreeRoot();
      const agentRoot = await registry.agentTreeRoot();
      const nonce = 46n;

      const humanProof = new Array(8).fill(0n);
      const humanPubSignals = [humanRoot, 1n, 2n, 3n, nonce];
      const agentProof = new Array(24).fill(0n);
      // agentPubSignals[5] = wrong nonce (888)
      const agentPubSignals = [agentRoot, 4n, 5n, 6n, 7n, 888n];

      await expect(
        registry.verifyHandshake(
          humanProof, humanPubSignals,
          agentProof, agentPubSignals,
          nonce
        )
      ).to.be.revertedWithCustomError(registry, "NonceMismatch");
    });
  });

  describe("Human root history buffer (CIP-2)", function () {
    it("should track human root history on enrollment", async function () {
      const commitment = 12345n;
      await registry.enrollHuman(commitment);

      const root = await registry.humanTreeRoot();
      expect(await registry.isValidHumanRoot(root)).to.be.true;
    });

    it("should accept old human roots within 30-root buffer", async function () {
      // Enroll first human, record its root
      await registry.enrollHuman(1000n);
      const firstRoot = await registry.humanTreeRoot();

      // Enroll 29 more humans (total 30 roots in buffer)
      for (let i = 1; i < 30; i++) {
        await registry.enrollHuman(BigInt((i + 1) * 1000));
      }

      // First root should still be valid (exactly 30 roots)
      expect(await registry.isValidHumanRoot(firstRoot)).to.be.true;
    });

    it("should evict old human roots beyond 30-root buffer", async function () {
      // Enroll first human, record its root
      await registry.enrollHuman(1000n);
      const firstRoot = await registry.humanTreeRoot();

      // Enroll 30 more humans (31 total, first root evicted)
      for (let i = 1; i <= 30; i++) {
        await registry.enrollHuman(BigInt((i + 1) * 1000));
      }

      // First root should be evicted
      expect(await registry.isValidHumanRoot(firstRoot)).to.be.false;

      // Latest root should be valid
      const latestRoot = await registry.humanTreeRoot();
      expect(await registry.isValidHumanRoot(latestRoot)).to.be.true;
    });

    it("should track human roots from batch enrollment", async function () {
      await registry.enrollHumanBatch([100n, 200n, 300n]);

      // Current root should be valid
      const root = await registry.humanTreeRoot();
      expect(await registry.isValidHumanRoot(root)).to.be.true;
    });
  });

  describe("Delegation verification (Attack 2 fix: handshake-prerequisite + on-chain chain state)", function () {
    it("should reject delegation without prior handshake", async function () {
      // Session nonce has not been consumed by any handshake
      const proof = new Array(24).fill(0n);
      const pubSignals = [111n, 42n, 222n, 333n, 444n];
      const sessionNonce = 42n;

      await expect(
        registry.verifyDelegation(proof, pubSignals, sessionNonce)
      ).to.be.revertedWithCustomError(registry, "DelegationRequiresHandshake");
    });

    it("should expose lastScopeCommitment mapping (zero by default)", async function () {
      const commitment = await registry.lastScopeCommitment(12345n);
      expect(commitment).to.equal(0n);
    });

    it("should track delegation hop count (zero by default)", async function () {
      const count = await registry.delegationHopCount(12345n);
      expect(count).to.equal(0n);
    });

    it("should expose usedDelegationNullifiers mapping", async function () {
      const used = await registry.usedDelegationNullifiers(99999n);
      expect(used).to.be.false;
    });
  });
});
