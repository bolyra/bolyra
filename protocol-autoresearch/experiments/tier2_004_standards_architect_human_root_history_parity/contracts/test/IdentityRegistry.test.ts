import { expect } from "chai";
import { ethers } from "hardhat";

describe("IdentityRegistry — human root history buffer", function () {
    let registry: any;

    beforeEach(async function () {
        const HumanFactory = await ethers.getContractFactory(
            "HumanUniquenessVerifier"
        );
        const humanVerifier = await HumanFactory.deploy();
        await humanVerifier.waitForDeployment();

        const AgentFactory = await ethers.getContractFactory(
            "AgentPolicyVerifier"
        );
        const agentVerifier = await AgentFactory.deploy();
        await agentVerifier.waitForDeployment();

        const RegistryFactory = await ethers.getContractFactory(
            "IdentityRegistry"
        );
        registry = await RegistryFactory.deploy(
            await humanVerifier.getAddress(),
            await agentVerifier.getAddress()
        );
        await registry.waitForDeployment();
    });

    const ROOT_HISTORY_SIZE = 30;

    function dummyProof(): bigint[] {
        return new Array(8).fill(0n);
    }

    function humanPubSignals(root: bigint): bigint[] {
        // [nullifierHash, nonceBinding, humanMerkleRoot, externalNullifier, sessionNonce, chainId]
        return [1n, 2n, root, 4n, 5n, 31337n];
    }

    async function enrollAndCaptureRoot(commitment: bigint): Promise<bigint> {
        const tx = await registry.enrollHuman(commitment);
        const receipt = await tx.wait();
        const event = receipt.logs.find(
            (log: any) => log.fragment?.name === "HumanEnrolled"
        );
        return event.args.newRoot;
    }

    // ------------------------------------------------------------------
    // Test 1: proof against current root verifies
    // ------------------------------------------------------------------
    it("should verify a proof against the current root", async function () {
        const root = await enrollAndCaptureRoot(100n);
        const result = await registry.verifyHumanProof(
            dummyProof(),
            humanPubSignals(root)
        );
        expect(result).to.be.true;
    });

    // ------------------------------------------------------------------
    // Test 2: proof generated before N<=30 enrollments still verifies
    // ------------------------------------------------------------------
    it("should verify a proof against a root within the history window", async function () {
        // Enroll first human and capture the root
        const oldRoot = await enrollAndCaptureRoot(100n);

        // Enroll 15 more humans (total 16 enrollments, well within buffer)
        for (let i = 1; i <= 15; i++) {
            await registry.enrollHuman(BigInt(100 + i));
        }

        // Old root should still be in the buffer
        const isValid = await registry.isValidHumanRoot(oldRoot);
        expect(isValid).to.be.true;

        // Proof against old root should verify
        const result = await registry.verifyHumanProof(
            dummyProof(),
            humanPubSignals(oldRoot)
        );
        expect(result).to.be.true;
    });

    // ------------------------------------------------------------------
    // Test 3: proof generated before N>30 enrollments fails (evicted)
    // ------------------------------------------------------------------
    it("should reject a proof against an evicted root (>30 enrollments)", async function () {
        // Enroll first human and capture the root
        const evictedRoot = await enrollAndCaptureRoot(1n);

        // Enroll 30 more humans to push the first root out of the buffer
        for (let i = 1; i <= ROOT_HISTORY_SIZE; i++) {
            await registry.enrollHuman(BigInt(1 + i));
        }

        // The original root should be evicted
        const isValid = await registry.isValidHumanRoot(evictedRoot);
        expect(isValid).to.be.false;

        // Proof against evicted root should revert
        await expect(
            registry.verifyHumanProof(
                dummyProof(),
                humanPubSignals(evictedRoot)
            )
        ).to.be.revertedWithCustomError(registry, "RootNotFound");
    });

    // ------------------------------------------------------------------
    // Test 4: buffer wraps correctly at index 30
    // ------------------------------------------------------------------
    it("should wrap the circular buffer correctly at index 30", async function () {
        const roots: bigint[] = [];

        // Fill the buffer exactly (30 enrollments)
        for (let i = 0; i < ROOT_HISTORY_SIZE; i++) {
            const root = await enrollAndCaptureRoot(BigInt(i));
            roots.push(root);
        }

        // All 30 roots should be valid
        for (const root of roots) {
            expect(await registry.isValidHumanRoot(root)).to.be.true;
        }

        // Enroll one more — this overwrites slot 0
        const newRoot = await enrollAndCaptureRoot(999n);

        // First root should now be evicted
        expect(await registry.isValidHumanRoot(roots[0])).to.be.false;

        // Second root should still be valid (slot 1 untouched)
        expect(await registry.isValidHumanRoot(roots[1])).to.be.true;

        // New root should be valid
        expect(await registry.isValidHumanRoot(newRoot)).to.be.true;

        // humanRootIndex should be 31
        expect(await registry.humanRootIndex()).to.equal(31n);
    });

    // ------------------------------------------------------------------
    // Test 5: fresh enrollment invalidates nothing within window
    // ------------------------------------------------------------------
    it("should not invalidate existing roots when a new enrollment lands", async function () {
        const roots: bigint[] = [];

        // Enroll 5 humans
        for (let i = 0; i < 5; i++) {
            const root = await enrollAndCaptureRoot(BigInt(i * 10));
            roots.push(root);
        }

        // Enroll one more
        await registry.enrollHuman(999n);

        // All 5 previous roots should still be valid
        for (const root of roots) {
            expect(await registry.isValidHumanRoot(root)).to.be.true;
        }
    });

    // ------------------------------------------------------------------
    // Test 6: zero root is never valid
    // ------------------------------------------------------------------
    it("should reject zero root", async function () {
        expect(await registry.isValidHumanRoot(0n)).to.be.false;
    });

    // ------------------------------------------------------------------
    // Test 7: agent root history buffer parity
    // ------------------------------------------------------------------
    it("should maintain agent root history buffer with identical semantics", async function () {
        const agentRoot1Tx = await registry.registerAgent(42n);
        const agentRoot1Receipt = await agentRoot1Tx.wait();
        const agentEvent = agentRoot1Receipt.logs.find(
            (log: any) => log.fragment?.name === "AgentRegistered"
        );
        const agentRoot1 = agentEvent.args.newRoot;

        // Register 29 more agents
        for (let i = 1; i < ROOT_HISTORY_SIZE; i++) {
            await registry.registerAgent(BigInt(42 + i));
        }

        // First agent root still valid (exactly at buffer boundary)
        expect(await registry.isValidAgentRoot(agentRoot1)).to.be.true;

        // One more pushes it out
        await registry.registerAgent(999n);
        expect(await registry.isValidAgentRoot(agentRoot1)).to.be.false;
    });
});
