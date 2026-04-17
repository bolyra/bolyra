/**
 * @file DelegationRegistry.test.ts
 * @notice Foundry-style tests expressed as TypeScript for Hardhat.
 *
 * Tests cover:
 *   1. Submit delegation with valid root in history → success
 *   2. Submit with unknown root → revert UnknownAgentRoot
 *   3. Submit with zero root → revert ZeroRoot
 *   4. Replay attack (same nullifier) → revert NullifierAlreadyUsed
 *   5. Event emission verification
 *   6. State queries after submission
 *
 * Prerequisites:
 *   - hardhat with @nomicfoundation/hardhat-chai-matchers
 *   - ethers v6
 *
 * Run: npx hardhat test test/contracts/DelegationRegistry.test.ts
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { Contract, Signer } from "ethers";

describe("DelegationRegistry", function () {
    let owner: Signer;
    let user: Signer;
    let identityRegistry: Contract;
    let delegationVerifier: Contract;
    let delegationRegistry: Contract;

    // Test constants
    const VALID_AGENT_ROOT = 123456789n;
    const STALE_AGENT_ROOT = 999999999n;
    const SCOPE_COMMITMENT = 111222333n;
    const NULLIFIER_HASH = ethers.keccak256(ethers.toUtf8Bytes("test-nullifier"));

    // Dummy Groth16 proof (non-zero for placeholder verifier)
    const DUMMY_PROOF = {
        a: [1n, 2n] as [bigint, bigint],
        b: [
            [3n, 4n],
            [5n, 6n],
        ] as [[bigint, bigint], [bigint, bigint]],
        c: [7n, 8n] as [bigint, bigint],
    };

    beforeEach(async () => {
        [owner, user] = await ethers.getSigners();

        // Deploy IdentityRegistry (provides IRootHistory)
        const IdentityRegistryFactory = await ethers.getContractFactory("IdentityRegistry");
        identityRegistry = await IdentityRegistryFactory.deploy();
        await identityRegistry.waitForDeployment();

        // Enroll an agent to populate the root history buffer
        await identityRegistry.enrollAgent(42n, VALID_AGENT_ROOT);

        // Deploy DelegationVerifier (placeholder)
        const VerifierFactory = await ethers.getContractFactory("DelegationVerifier");
        delegationVerifier = await VerifierFactory.deploy();
        await delegationVerifier.waitForDeployment();

        // Deploy DelegationRegistry
        const RegistryFactory = await ethers.getContractFactory("DelegationRegistry");
        delegationRegistry = await RegistryFactory.deploy(
            await identityRegistry.getAddress(),
            await delegationVerifier.getAddress()
        );
        await delegationRegistry.waitForDeployment();
    });

    // ── Helper ───────────────────────────────────────────────────────

    function makeDelegationProof(overrides: Partial<{
        a: [bigint, bigint];
        b: [[bigint, bigint], [bigint, bigint]];
        c: [bigint, bigint];
        agentTreeRoot: bigint;
        scopeCommitment: bigint;
        nullifierHash: string;
    }> = {}) {
        return {
            a: overrides.a ?? DUMMY_PROOF.a,
            b: overrides.b ?? DUMMY_PROOF.b,
            c: overrides.c ?? DUMMY_PROOF.c,
            agentTreeRoot: overrides.agentTreeRoot ?? VALID_AGENT_ROOT,
            scopeCommitment: overrides.scopeCommitment ?? SCOPE_COMMITMENT,
            nullifierHash: overrides.nullifierHash ?? NULLIFIER_HASH,
        };
    }

    // ── Tests ────────────────────────────────────────────────────────

    it("should accept a delegation with a valid agent root", async () => {
        const proof = makeDelegationProof();
        await expect(delegationRegistry.submitDelegation(proof))
            .to.not.be.reverted;
    });

    it("should emit DelegationSubmitted event with correct parameters", async () => {
        const proof = makeDelegationProof();
        await expect(delegationRegistry.submitDelegation(proof))
            .to.emit(delegationRegistry, "DelegationSubmitted")
            .withArgs(NULLIFIER_HASH, VALID_AGENT_ROOT, SCOPE_COMMITMENT);
    });

    it("should revert with UnknownAgentRoot for root not in history", async () => {
        const proof = makeDelegationProof({ agentTreeRoot: STALE_AGENT_ROOT });
        await expect(delegationRegistry.submitDelegation(proof))
            .to.be.revertedWithCustomError(delegationRegistry, "UnknownAgentRoot")
            .withArgs(STALE_AGENT_ROOT);
    });

    it("should revert with ZeroRoot for zero agent root", async () => {
        const proof = makeDelegationProof({ agentTreeRoot: 0n });
        await expect(delegationRegistry.submitDelegation(proof))
            .to.be.revertedWithCustomError(delegationRegistry, "ZeroRoot");
    });

    it("should revert with NullifierAlreadyUsed on replay", async () => {
        const proof = makeDelegationProof();

        // First submission succeeds
        await delegationRegistry.submitDelegation(proof);

        // Second submission with same nullifier should fail
        await expect(delegationRegistry.submitDelegation(proof))
            .to.be.revertedWithCustomError(delegationRegistry, "NullifierAlreadyUsed")
            .withArgs(NULLIFIER_HASH);
    });

    it("should allow different nullifiers with the same root", async () => {
        const proof1 = makeDelegationProof();
        const nullifier2 = ethers.keccak256(ethers.toUtf8Bytes("different-nullifier"));
        const proof2 = makeDelegationProof({ nullifierHash: nullifier2 });

        await expect(delegationRegistry.submitDelegation(proof1)).to.not.be.reverted;
        await expect(delegationRegistry.submitDelegation(proof2)).to.not.be.reverted;
    });

    it("should track delegation state correctly after submission", async () => {
        const proof = makeDelegationProof();
        await delegationRegistry.submitDelegation(proof);

        expect(await delegationRegistry.isDelegationSubmitted(NULLIFIER_HASH)).to.be.true;
        expect(await delegationRegistry.getScopeCommitment(NULLIFIER_HASH)).to.equal(
            SCOPE_COMMITMENT
        );
    });

    it("should return false for non-existent delegation", async () => {
        const unknownNullifier = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
        expect(await delegationRegistry.isDelegationSubmitted(unknownNullifier)).to.be.false;
        expect(await delegationRegistry.getScopeCommitment(unknownNullifier)).to.equal(0n);
    });

    it("should reject delegation after root is evicted from buffer", async () => {
        // Fill the buffer with 30 new roots to evict VALID_AGENT_ROOT
        for (let i = 0; i < 30; i++) {
            await identityRegistry.enrollAgent(BigInt(i + 100), BigInt(i + 200000));
        }

        // The original root should now be evicted
        const proof = makeDelegationProof();
        await expect(delegationRegistry.submitDelegation(proof))
            .to.be.revertedWithCustomError(delegationRegistry, "UnknownAgentRoot");
    });
});
