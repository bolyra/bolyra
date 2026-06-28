const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * HumanRegistry v3.0.0 — Two-Nullifier Integration Tests
 *
 * These tests use a mock verifier that always returns true,
 * isolating the registry logic from ZK proof verification.
 *
 * Tests cover:
 *   1. First handshake accepted
 *   2. Replay of same session nullifier rejected
 *   3. Second handshake with new nonce accepted (same identity)
 *   4. Revoked commitment rejected
 *   5. Unaccepted root rejected
 *   6. View helpers return correct state
 */

describe("HumanRegistry (two-nullifier, v3.0.0)", function () {
  let registry;
  let mockVerifier;
  let admin;
  let user;

  // Test values
  const ROOT = 111n;
  const SESSION_NULLIFIER_1 = 1001n;
  const SESSION_NULLIFIER_2 = 1002n;
  const SCOPE = 12345n;
  const EXT_COMMITMENT = 9999n;
  const PROOF_BYTES = "0x1234";

  beforeEach(async () => {
    [admin, user] = await ethers.getSigners();

    // Deploy mock verifier that always returns true
    const MockVerifier = await ethers.getContractFactory("MockHumanVerifier");
    mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();

    // Deploy registry with mock verifier
    const Registry = await ethers.getContractFactory("HumanRegistry");
    registry = await Registry.deploy(await mockVerifier.getAddress());
    await registry.waitForDeployment();

    // Add a root
    await registry.addRoot(ROOT);
  });

  describe("Handshake acceptance", () => {
    it("should accept first valid handshake", async () => {
      await expect(
        registry.verifyAndRegister(
          PROOF_BYTES,
          ROOT,
          SESSION_NULLIFIER_1,
          SCOPE,
          EXT_COMMITMENT
        )
      )
        .to.emit(registry, "HandshakeVerified")
        .withArgs(SESSION_NULLIFIER_1, EXT_COMMITMENT, SCOPE);

      expect(await registry.isSessionUsed(SESSION_NULLIFIER_1)).to.be.true;
      expect(await registry.isCommitmentRegistered(EXT_COMMITMENT)).to.be.true;
    });

    it("should accept second handshake with different session nullifier (same identity)", async () => {
      // First handshake
      await registry.verifyAndRegister(
        PROOF_BYTES,
        ROOT,
        SESSION_NULLIFIER_1,
        SCOPE,
        EXT_COMMITMENT
      );

      // Second handshake — different session nullifier, same commitment
      await expect(
        registry.verifyAndRegister(
          PROOF_BYTES,
          ROOT,
          SESSION_NULLIFIER_2,
          SCOPE,
          EXT_COMMITMENT
        )
      )
        .to.emit(registry, "HandshakeVerified")
        .withArgs(SESSION_NULLIFIER_2, EXT_COMMITMENT, SCOPE);

      expect(await registry.isSessionUsed(SESSION_NULLIFIER_2)).to.be.true;
    });
  });

  describe("Replay prevention", () => {
    it("should reject replay of the same session nullifier", async () => {
      await registry.verifyAndRegister(
        PROOF_BYTES,
        ROOT,
        SESSION_NULLIFIER_1,
        SCOPE,
        EXT_COMMITMENT
      );

      await expect(
        registry.verifyAndRegister(
          PROOF_BYTES,
          ROOT,
          SESSION_NULLIFIER_1, // same session nullifier
          SCOPE,
          EXT_COMMITMENT
        )
      ).to.be.revertedWithCustomError(registry, "SessionNullifierAlreadyUsed");
    });
  });

  describe("Revocation", () => {
    it("should reject handshake with revoked commitment", async () => {
      await registry.revokeCommitment(EXT_COMMITMENT);

      await expect(
        registry.verifyAndRegister(
          PROOF_BYTES,
          ROOT,
          SESSION_NULLIFIER_1,
          SCOPE,
          EXT_COMMITMENT
        )
      ).to.be.revertedWithCustomError(registry, "CommitmentRevoked_");
    });

    it("should emit CommitmentRevoked event", async () => {
      await expect(registry.revokeCommitment(EXT_COMMITMENT))
        .to.emit(registry, "CommitmentRevoked")
        .withArgs(EXT_COMMITMENT);
    });

    it("should only allow admin to revoke", async () => {
      await expect(
        registry.connect(user).revokeCommitment(EXT_COMMITMENT)
      ).to.be.revertedWithCustomError(registry, "NotAdmin");
    });
  });

  describe("Root validation", () => {
    it("should reject handshake with unaccepted root", async () => {
      const BAD_ROOT = 999n;

      await expect(
        registry.verifyAndRegister(
          PROOF_BYTES,
          BAD_ROOT,
          SESSION_NULLIFIER_1,
          SCOPE,
          EXT_COMMITMENT
        )
      ).to.be.revertedWithCustomError(registry, "RootNotAccepted");
    });

    it("should allow admin to add and remove roots", async () => {
      const NEW_ROOT = 222n;
      await registry.addRoot(NEW_ROOT);
      expect(await registry.acceptedRoots(NEW_ROOT)).to.be.true;

      await registry.removeRoot(NEW_ROOT);
      expect(await registry.acceptedRoots(NEW_ROOT)).to.be.false;
    });
  });

  describe("View helpers", () => {
    it("isSessionUsed returns false before and true after", async () => {
      expect(await registry.isSessionUsed(SESSION_NULLIFIER_1)).to.be.false;

      await registry.verifyAndRegister(
        PROOF_BYTES,
        ROOT,
        SESSION_NULLIFIER_1,
        SCOPE,
        EXT_COMMITMENT
      );

      expect(await registry.isSessionUsed(SESSION_NULLIFIER_1)).to.be.true;
    });

    it("isCommitmentRevoked returns false before and true after revocation", async () => {
      expect(await registry.isCommitmentRevoked(EXT_COMMITMENT)).to.be.false;
      await registry.revokeCommitment(EXT_COMMITMENT);
      expect(await registry.isCommitmentRevoked(EXT_COMMITMENT)).to.be.true;
    });
  });
});

/**
 * Mock verifier for testing — always returns true.
 * In production, this would be the snarkjs-exported Groth16Verifier.
 *
 * Deploy this as a separate contract in the test setup.
 * Hardhat artifact: contracts/test/MockHumanVerifier.sol
 */
