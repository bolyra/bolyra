import { expect } from "chai";
import { ethers } from "hardhat";
import { Contract, Signer } from "ethers";

/**
 * IdentityRegistry — humanRootHistory[30] ring buffer tests.
 *
 * Covers:
 *   1. Proofs against the N most recent human roots are accepted.
 *   2. A root older than ROOT_HISTORY_SIZE enrollments is rejected.
 *   3. Ring-buffer wrapping is correct at boundary.
 *   4. Parity with existing agentRootHistory acceptance window.
 *   5. Zero root is always invalid.
 *   6. HumanRootHistoryUpdated event is emitted.
 *   7. Human and agent buffers are independent.
 */
describe("IdentityRegistry — humanRootHistory", function () {
  const ROOT_HISTORY_SIZE = 30;
  let registry: Contract;
  let owner: Signer;

  // Deterministic root generator for testing
  function makeRoot(index: number): string {
    return ethers.solidityPackedKeccak256(
      ["string", "uint256"],
      ["root", index]
    );
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

    const IdentityRegistry = await ethers.getContractFactory(
      "IdentityRegistry"
    );
    registry = await IdentityRegistry.deploy();
    await registry.waitForDeployment();
  });

  // ── Helper: enroll N humans with deterministic roots ───────────
  async function enrollN(
    count: number,
    startIndex = 0
  ): Promise<string[]> {
    const roots: string[] = [];
    for (let i = startIndex; i < startIndex + count; i++) {
      const root = makeRoot(i);
      await registry.enrollHuman(makeCommitment(i), root);
      roots.push(root);
    }
    return roots;
  }

  // ── Helper: enroll N agents with deterministic roots ───────────
  async function enrollAgentsN(
    count: number,
    startIndex = 0
  ): Promise<string[]> {
    const roots: string[] = [];
    for (let i = startIndex; i < startIndex + count; i++) {
      const root = ethers.solidityPackedKeccak256(
        ["string", "uint256"],
        ["agent-root", i]
      );
      await registry.enrollAgent(makeCommitment(i + 10000), root);
      roots.push(root);
    }
    return roots;
  }

  // ────────────────────────────────────────────────────────────────
  // Test 1: Proofs against the N most recent roots are accepted
  // ────────────────────────────────────────────────────────────────
  it("accepts all roots within the history window", async function () {
    const roots = await enrollN(ROOT_HISTORY_SIZE);
    for (const root of roots) {
      expect(await registry.isKnownHumanRoot(root)).to.be.true;
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Test 2: A root older than ROOT_HISTORY_SIZE is rejected
  // ────────────────────────────────────────────────────────────────
  it("rejects a root evicted after ROOT_HISTORY_SIZE+1 enrollments", async function () {
    const roots = await enrollN(ROOT_HISTORY_SIZE + 1);
    // roots[0] was at slot 0, enrollment 30 overwrote slot 0
    expect(await registry.isKnownHumanRoot(roots[0])).to.be.false;
    // roots[1] is still in slot 1
    expect(await registry.isKnownHumanRoot(roots[1])).to.be.true;
    // Latest root is always present
    expect(
      await registry.isKnownHumanRoot(roots[ROOT_HISTORY_SIZE])
    ).to.be.true;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 3: Ring buffer wraparound at boundary
  // ────────────────────────────────────────────────────────────────
  it("wraps the circular buffer correctly at the boundary", async function () {
    // Fill buffer twice (60 enrollments)
    const roots = await enrollN(ROOT_HISTORY_SIZE * 2);

    // Only the last 30 roots should be valid
    for (let i = 0; i < ROOT_HISTORY_SIZE; i++) {
      expect(await registry.isKnownHumanRoot(roots[i])).to.be.false;
    }
    for (let i = ROOT_HISTORY_SIZE; i < ROOT_HISTORY_SIZE * 2; i++) {
      expect(await registry.isKnownHumanRoot(roots[i])).to.be.true;
    }

    // humanRootHistoryIndex should be 60
    expect(await registry.humanRootHistoryIndex()).to.equal(
      ROOT_HISTORY_SIZE * 2
    );
  });

  // ────────────────────────────────────────────────────────────────
  // Test 4: Parity — agent root history has identical semantics
  // ────────────────────────────────────────────────────────────────
  it("maintains agent root history with identical buffer semantics", async function () {
    const agentRoots = await enrollAgentsN(ROOT_HISTORY_SIZE);

    // All 30 agent roots should be valid
    for (const root of agentRoots) {
      expect(await registry.isKnownAgentRoot(root)).to.be.true;
    }

    // One more pushes out slot 0
    const extraRoots = await enrollAgentsN(1, ROOT_HISTORY_SIZE);
    expect(await registry.isKnownAgentRoot(agentRoots[0])).to.be.false;
    expect(await registry.isKnownAgentRoot(extraRoots[0])).to.be.true;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 5: Zero root is always invalid
  // ────────────────────────────────────────────────────────────────
  it("rejects the zero root", async function () {
    expect(await registry.isKnownHumanRoot(ethers.ZeroHash)).to.be.false;
    expect(await registry.isKnownAgentRoot(ethers.ZeroHash)).to.be.false;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 6: HumanRootHistoryUpdated event is emitted
  // ────────────────────────────────────────────────────────────────
  it("emits HumanRootHistoryUpdated with correct index", async function () {
    const root0 = makeRoot(0);
    await expect(registry.enrollHuman(makeCommitment(0), root0))
      .to.emit(registry, "HumanRootHistoryUpdated")
      .withArgs(root0, 0);

    const root1 = makeRoot(1);
    await expect(registry.enrollHuman(makeCommitment(1), root1))
      .to.emit(registry, "HumanRootHistoryUpdated")
      .withArgs(root1, 1);
  });

  // ────────────────────────────────────────────────────────────────
  // Test 7: Human and agent buffers are independent
  // ────────────────────────────────────────────────────────────────
  it("does not cross-contaminate human and agent buffers", async function () {
    const humanRoots = await enrollN(3);
    const agentRoots = await enrollAgentsN(3);

    // Human roots are NOT in agent buffer
    for (const hr of humanRoots) {
      expect(await registry.isKnownAgentRoot(hr)).to.be.false;
    }
    // Agent roots are NOT in human buffer
    for (const ar of agentRoots) {
      expect(await registry.isKnownHumanRoot(ar)).to.be.false;
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Test 8: Interleaved enrollment and proof validation
  // ────────────────────────────────────────────────────────────────
  it("handles interleaved enrollment and proof validation", async function () {
    // User A generates proof at root 0
    const rootA = makeRoot(100);
    await registry.enrollHuman(makeCommitment(100), rootA);

    // 28 more enrollments (total 29 — root A still in buffer)
    await enrollN(28, 200);
    expect(await registry.isKnownHumanRoot(rootA)).to.be.true;

    // 30th enrollment — root A at slot 0, not yet overwritten
    await registry.enrollHuman(makeCommitment(999), makeRoot(999));
    expect(await registry.isKnownHumanRoot(rootA)).to.be.true;

    // 31st enrollment evicts root A from slot 0
    await registry.enrollHuman(makeCommitment(1000), makeRoot(1000));
    expect(await registry.isKnownHumanRoot(rootA)).to.be.false;
  });

  // ────────────────────────────────────────────────────────────────
  // Test 9: enrollHuman reverts on zero root
  // ────────────────────────────────────────────────────────────────
  it("reverts when enrolling with zero root", async function () {
    await expect(
      registry.enrollHuman(makeCommitment(0), ethers.ZeroHash)
    ).to.be.revertedWith("IdentityRegistry: zero root");
  });

  // ────────────────────────────────────────────────────────────────
  // Test 10: currentHumanRoot tracks the latest enrollment
  // ────────────────────────────────────────────────────────────────
  it("updates currentHumanRoot on each enrollment", async function () {
    const root0 = makeRoot(0);
    await registry.enrollHuman(makeCommitment(0), root0);
    expect(await registry.currentHumanRoot()).to.equal(root0);

    const root1 = makeRoot(1);
    await registry.enrollHuman(makeCommitment(1), root1);
    expect(await registry.currentHumanRoot()).to.equal(root1);
  });
});
