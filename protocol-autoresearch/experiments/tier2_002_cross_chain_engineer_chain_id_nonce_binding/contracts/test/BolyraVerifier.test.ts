import { expect } from "chai";
import { ethers } from "hardhat";

describe("BolyraVerifier — chainId enforcement", function () {
    let verifier: any;
    let humanVerifier: any;
    let agentVerifier: any;

    before(async function () {
        // Deploy stub verifiers (always return true)
        const HumanFactory = await ethers.getContractFactory(
            "HumanUniquenessVerifier"
        );
        humanVerifier = await HumanFactory.deploy();
        await humanVerifier.waitForDeployment();

        const AgentFactory = await ethers.getContractFactory(
            "AgentPolicyVerifier"
        );
        agentVerifier = await AgentFactory.deploy();
        await agentVerifier.waitForDeployment();

        const VerifierFactory = await ethers.getContractFactory(
            "BolyraVerifier"
        );
        verifier = await VerifierFactory.deploy(
            await humanVerifier.getAddress(),
            await agentVerifier.getAddress()
        );
        await verifier.waitForDeployment();
    });

    // Hardhat default chainId is 31337
    const HARDHAT_CHAIN_ID = 31337n;

    function dummyProof(): bigint[] {
        return new Array(8).fill(0n);
    }

    function humanPubSignals(chainId: bigint): bigint[] {
        // [nullifierHash, nonceBinding, humanMerkleRoot, externalNullifier, sessionNonce, chainId]
        return [1n, 2n, 3n, 4n, 5n, chainId];
    }

    function agentPubSignals(chainId: bigint): bigint[] {
        // [credentialHash, nonceBinding, agentMerkleRoot, currentTimestamp, requiredPermissions, sessionNonce, chainId]
        return [1n, 2n, 3n, 4n, 5n, 6n, chainId];
    }

    it("should pass when both chainIds match block.chainid", async function () {
        const result = await verifier.verifyHandshake(
            dummyProof(),
            humanPubSignals(HARDHAT_CHAIN_ID),
            dummyProof(),
            agentPubSignals(HARDHAT_CHAIN_ID)
        );
        expect(result).to.be.true;
    });

    it("should revert when human chainId != block.chainid", async function () {
        await expect(
            verifier.verifyHandshake(
                dummyProof(),
                humanPubSignals(1n), // wrong chain
                dummyProof(),
                agentPubSignals(HARDHAT_CHAIN_ID)
            )
        ).to.be.revertedWithCustomError(verifier, "ChainIdMismatch");
    });

    it("should revert when agent chainId != block.chainid", async function () {
        await expect(
            verifier.verifyHandshake(
                dummyProof(),
                humanPubSignals(HARDHAT_CHAIN_ID),
                dummyProof(),
                agentPubSignals(8453n) // Base mainnet, wrong for Hardhat
            )
        ).to.be.revertedWithCustomError(verifier, "ChainIdMismatch");
    });

    it("should revert when both chainIds are wrong", async function () {
        await expect(
            verifier.verifyHandshake(
                dummyProof(),
                humanPubSignals(1n),
                dummyProof(),
                agentPubSignals(8453n)
            )
        ).to.be.revertedWithCustomError(verifier, "ChainIdMismatch");
    });
});
