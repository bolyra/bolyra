import { expect } from "chai";
import { ethers } from "hardhat";
import { Contract, Signer } from "ethers";

/**
 * IdentityRegistry — humanRootHistory[30] ring buffer tests.
 *
 * Covers:
 *   1. Proof root generated before a new enrollment remains valid.
 *   2. Proof root generated 30 enrollments ago is still accepted.
 *   3. Proof root generated 31 enrollments ago is rejected (evicted).
 *   4. Ring buffer wraparound correctness at index boundary.
 *   5. Concurrent enrollment simulation with interleaved proof submissions.
 */
describe("IdentityRegistry — humanRootHistory", function () {
  let registry: Contract;
  let owner: Signer;

  // Deterministic root generator for testing
  function makeRoot(index: number): string {
    return ethers.solidityPackedKeccak256(["string", "uint256"], ["root", index]);
  }

  // Deterministic identity commitment generator
  function makeCommitment(index: number): string {
    return ethers.solidityPackedKeccak256(
      ["string", "uint256"],
      ["commitment", index]
    );
  }

  beforeEach(async function () {
    [owner] = await ethers.getSigners();

    // Deploy stub verifiers (tests don't exercise proof math)
    const StubVerifier = await ethers.getContractFactory("StubVerifier");
    const humanVerifier = await StubVerifier.deploy();
    const agentVerifier = await StubVerifier.deploy();
    const delegationVerifier = await StubVerifier.deploy();

    const IdentityRegistry = await ethers.getContractFactory(
      "IdentityRegistry"
    );
    registry = await IdentityRegistry.deploy(
      await humanVerifier.getAddress(),
      await agentVerifier.getAddress(),
      await delegationVerifier.getAddress(),
      20, // humanTreeDepth
      20  // agentTreeDepth
    );
  });

  // ── Helper: enroll N humans with deterministic roots ───────────
  async function enrollN(count: number, startIndex = 0): Promise<string[]> {
    const roots: string[] = [];
    for (let i = startIndex; i < startIndex + count; i++) {
      const root = makeRoot(i);
      await registry.enrollHuman(makeCommitment(i), root);
      roots.push(root);
    }
    return roots;
  }

  // ────────────────────────────────────────────────────────────────
  // Test 1: Proof root from before a new enrollment remains valid
  // ────────────────────────────────────────────────────────────────
  it("accepts a root generated before the most recent enrollment", async function () {
    const roots = await enrollN(2);
    // Root from enrollment 0 should still be valid after enrollment 1
    expect(await registry.isValidHumanRoot(roots[0])).to.be.true;
    expect(await registry.isValidHumanRoot(roots[1])).to.be.true;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 2: Root from exactly 30 enrollments ago is still accepted
  // ────────────────────────────────────────────────────────────────
  it("accepts a root from exactly 30 enrollments ago", async function () {
    const roots = await enrollN(30);
    // roots[0] was written at slot 0; after 30 enrollments the pointer
    // is at 30, so slot 0 has NOT been overwritten yet.
    expect(await registry.isValidHumanRoot(roots[0])).to.be.true;
    expect(await registry.isValidHumanRoot(roots[29])).to.be.true;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 3: Root from 31 enrollments ago is rejected (evicted)
  // ────────────────────────────────────────────────────────────────
  it("rejects a root evicted after 31 enrollments", async function () {
    const roots = await enrollN(31);
    // roots[0] was at slot 0, then enrollment 30 wrote slot 0 again,
    // evicting roots[0].
    expect(await registry.isValidHumanRoot(roots[0])).to.be.false;
    // roots[1] is at slot 1 — still present
    expect(await registry.isValidHumanRoot(roots[1])).to.be.true;
    // Latest root is always present
    expect(await registry.isValidHumanRoot(roots[30])).to.be.true;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 4: Ring buffer wraparound correctness at index boundary
  // ────────────────────────────────────────────────────────────────
  it("wraps around correctly at the 30-slot boundary", async function () {
    // Fill the buffer twice (60 enrollments)
    const roots = await enrollN(60);

    // Only the last 30 roots should be valid
    for (let i = 0; i < 30; i++) {
      expect(await registry.isValidHumanRoot(roots[i])).to.be.false;
    }
    for (let i = 30; i < 60; i++) {
      expect(await registry.isValidHumanRoot(roots[i])).to.be.true;
    }

    // humanRootHistoryIndex should be 60
    expect(await registry.humanRootHistoryIndex()).to.equal(60);
  });

  // ────────────────────────────────────────────────────────────────
  // Test 5: Concurrent enrollment simulation with interleaved proofs
  // ────────────────────────────────────────────────────────────────
  it("handles interleaved enrollment and proof validation", async function () {
    // Simulate: user A generates proof at root 0, users B-D enroll,
    // user A's proof should still validate.
    const rootA = makeRoot(100);
    await registry.enrollHuman(makeCommitment(100), rootA);

    // 28 more enrollments (total 29 — root A is still in buffer)
    await enrollN(28, 200);

    // Root A is still valid (29 enrollments total, slot 0 not overwritten)
    expect(await registry.isValidHumanRoot(rootA)).to.be.true;

    // One more enrollment — root A is at slot 0, new write goes to slot 29
    await registry.enrollHuman(makeCommitment(999), makeRoot(999));
    // Root A still valid (30 total, slot 0 not yet overwritten — next
    // write will go to slot 0 and evict it)
    expect(await registry.isValidHumanRoot(rootA)).to.be.true;

    // The 31st enrollment evicts root A
    await registry.enrollHuman(makeCommitment(1000), makeRoot(1000));
    expect(await registry.isValidHumanRoot(rootA)).to.be.false;
  });

  // ────────────────────────────────────────────────────────────────
  // Edge: zero root is always invalid
  // ────────────────────────────────────────────────────────────────
  it("rejects the zero root even if present in the buffer", async function () {
    expect(
      await registry.isValidHumanRoot(ethers.ZeroHash)
    ).to.be.false;
  });

  // ────────────────────────────────────────────────────────────────
  // Event: HumanRootHistoryUpdated is emitted on enrollment
  // ────────────────────────────────────────────────────────────────
  it("emits HumanRootHistoryUpdated with correct index", async function () {
    const root = makeRoot(42);
    await expect(registry.enrollHuman(makeCommitment(42), root))
      .to.emit(registry, "HumanRootHistoryUpdated")
      .withArgs(root, 0);

    const root2 = makeRoot(43);
    await expect(registry.enrollHuman(makeCommitment(43), root2))
      .to.emit(registry, "HumanRootHistoryUpdated")
      .withArgs(root2, 1);
  });

  // ────────────────────────────────────────────────────────────────
  // Parity: agent root history still works after human changes
  // ────────────────────────────────────────────────────────────────
  it("does not interfere with agentRootHistory", async function () {
    const humanRoot = makeRoot(500);
    const agentRoot = ethers.solidityPackedKeccak256(
      ["string", "uint256"],
      ["agent-root", 500]
    );

    await registry.enrollHuman(makeCommitment(500), humanRoot);
    await registry.enrollAgent(makeCommitment(501), agentRoot);

    expect(await registry.isValidHumanRoot(humanRoot)).to.be.true;
    expect(await registry.isValidAgentRoot(agentRoot)).to.be.true;

    // Cross-check: human root is not in agent buffer and vice versa
    expect(await registry.isValidHumanRoot(agentRoot)).to.be.false;
    expect(await registry.isValidAgentRoot(humanRoot)).to.be.false;
  });
});
