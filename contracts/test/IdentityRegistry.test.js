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

    // Link PoseidonT3 to IdentityRegistry
    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry", {
      libraries: {
        PoseidonT3: await poseidonT3.getAddress(),
      },
    });
    registry = await IdentityRegistry.deploy();
    await registry.waitForDeployment();
  });

  describe("Enrollment", function () {
    it("should enroll a human identity", async function () {
      const commitment = 12345n;
      await expect(registry.enrollHuman(commitment))
        .to.emit(registry, "HumanEnrolled")
        .withArgs(commitment, await registry.humanTreeRoot());

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

    it("should revoke an agent credential", async function () {
      const commitment = 88888n;
      await expect(registry.revokeAgent(commitment))
        .to.emit(registry, "AgentCredentialRevoked")
        .withArgs(commitment);

      expect(await registry.agentRevocations(commitment)).to.be.true;
    });
  });

  describe("Handshake verification", function () {
    it("should reject replayed nonces", async function () {
      // First, enroll a human and an agent so roots are valid
      await registry.enrollHuman(100n);
      await registry.enrollAgent(200n);

      const humanRoot = await registry.humanTreeRoot();
      const agentRoot = await registry.agentTreeRoot();
      const nonce = 42n;

      const humanProof = new Array(8).fill(0n);
      const humanPubSignals = [humanRoot, 1n, 2n, 3n, nonce];
      const agentProof = new Array(24).fill(0n);
      const agentPubSignals = [agentRoot, 4n, 5n, 6n, 7n, nonce];

      // First handshake should succeed (placeholder verifiers return true)
      await registry.verifyHandshake(
        humanProof, humanPubSignals,
        agentProof, agentPubSignals,
        nonce
      );

      // Second handshake with same nonce should fail
      await expect(
        registry.verifyHandshake(
          humanProof, humanPubSignals,
          agentProof, agentPubSignals,
          nonce
        )
      ).to.be.revertedWithCustomError(registry, "NonceAlreadyUsed");
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

    it("should emit HandshakeVerified on success", async function () {
      await registry.enrollHuman(100n);
      await registry.enrollAgent(200n);

      const humanRoot = await registry.humanTreeRoot();
      const agentRoot = await registry.agentTreeRoot();
      const nonce = 45n;
      const humanNullifier = 111n;
      const agentNullifier = 222n;

      const humanProof = new Array(8).fill(0n);
      const humanPubSignals = [humanRoot, humanNullifier, 2n, 3n, nonce];
      const agentProof = new Array(24).fill(0n);
      const agentPubSignals = [agentRoot, agentNullifier, 5n, 6n, 7n, nonce];

      await expect(
        registry.verifyHandshake(
          humanProof, humanPubSignals,
          agentProof, agentPubSignals,
          nonce
        )
      ).to.emit(registry, "HandshakeVerified")
        .withArgs(humanNullifier, agentNullifier, nonce);
    });
  });
});
