import { expect } from "chai";
import { ethers } from "hardhat";
import { Contract, ContractFactory } from "ethers";

/**
 * BN254 scalar field modulus.
 * r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Mock verifier that always returns true — isolates the field-bound
 * check logic in IdentityRegistry from actual ZKP verification.
 */
const MOCK_VERIFIER_SOURCE = `
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract MockVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[5] calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract MockVerifier6 {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external pure returns (bool) {
        return true;
    }
}
`;

describe("FieldOverflow", function () {
    let registry: Contract;
    let owner: any;

    // A valid field element used as a baseline for every signal slot.
    const VALID_ELEMENT = 42n;
    // Boundary: largest valid value
    const FIELD_MAX_VALID = FIELD_MODULUS - 1n;
    // Smallest invalid value
    const FIELD_FIRST_INVALID = FIELD_MODULUS;
    // Classic wrap-around attack: n + r
    const WRAPPED_NONCE = VALID_ELEMENT + FIELD_MODULUS;
    // uint256 max
    const UINT256_MAX = 2n ** 256n - 1n;

    // Helpers to build dummy proof & signal arrays
    function dummyProof(): bigint[] {
        return Array(8).fill(0n);
    }

    function validHumanSignals(overrides: Record<number, bigint> = {}): bigint[] {
        // [0] nullifierHash, [1] nonceBinding, [2] humanMerkleRoot,
        // [3] externalNullifier, [4] sessionNonce
        const base = [1n, 2n, 3n, 4n, VALID_ELEMENT];
        for (const [k, v] of Object.entries(overrides)) {
            base[Number(k)] = v;
        }
        return base;
    }

    function validAgentSignals(overrides: Record<number, bigint> = {}): bigint[] {
        // [0] credentialHash, [1] nonceBinding, [2] agentMerkleRoot,
        // [3] currentTimestamp, [4] requiredPermissions, [5] sessionNonce
        const base = [10n, 20n, 30n, 40n, 1n, VALID_ELEMENT];
        for (const [k, v] of Object.entries(overrides)) {
            base[Number(k)] = v;
        }
        return base;
    }

    function validDelegationSignals(overrides: Record<number, bigint> = {}): bigint[] {
        // [0] delegationHash, [1] narrowedPermissions, [2] nonceBinding,
        // [3] delegationMerkleRoot, [4] currentTimestamp, [5] sessionNonce
        const base = [100n, 1n, 200n, 300n, 400n, VALID_ELEMENT];
        for (const [k, v] of Object.entries(overrides)) {
            base[Number(k)] = v;
        }
        return base;
    }

    beforeEach(async function () {
        [owner] = await ethers.getSigners();

        // Deploy mock verifiers
        const MockVerifierFactory = await ethers.getContractFactory(
            "MockVerifier"
        );
        const mockHuman = await MockVerifierFactory.deploy();

        const MockVerifier6Factory = await ethers.getContractFactory(
            "MockVerifier6"
        );
        const mockAgent = await MockVerifier6Factory.deploy();
        const mockDelegation = await MockVerifier6Factory.deploy();

        // Deploy IdentityRegistry
        const RegistryFactory = await ethers.getContractFactory(
            "IdentityRegistry"
        );
        registry = await RegistryFactory.deploy(
            await mockHuman.getAddress(),
            await mockAgent.getAddress(),
            await mockDelegation.getAddress()
        );

        // Seed root history so root-validity checks pass
        const humanRoot = ethers.zeroPadValue(ethers.toBeHex(3n), 32);
        const agentRoot = ethers.zeroPadValue(ethers.toBeHex(30n), 32);
        await registry.enrollHuman(
            ethers.zeroPadValue("0x01", 32),
            humanRoot
        );
        await registry.enrollAgent(
            ethers.zeroPadValue("0x01", 32),
            agentRoot
        );
    });

    // ---------------------------------------------------------------
    // 1. Valid nonce — succeeds
    // ---------------------------------------------------------------
    it("accepts valid public signals (all < FIELD_MODULUS)", async function () {
        await expect(
            registry.verifyHandshake(
                dummyProof(),
                validHumanSignals(),
                dummyProof(),
                validAgentSignals()
            )
        ).to.not.be.reverted;
    });

    // ---------------------------------------------------------------
    // 2. sessionNonce = n + r — reverts with FieldModulusExceeded
    // ---------------------------------------------------------------
    it("reverts when human sessionNonce = n + FIELD_MODULUS (wrap attack)", async function () {
        await expect(
            registry.verifyHandshake(
                dummyProof(),
                validHumanSignals({ 4: WRAPPED_NONCE }),
                dummyProof(),
                validAgentSignals({ 5: WRAPPED_NONCE })
            )
        ).to.be.revertedWithCustomError(registry, "FieldModulusExceeded");
    });

    // ---------------------------------------------------------------
    // 3. currentTimestamp = 2^256 - 1 — reverts
    // ---------------------------------------------------------------
    it("reverts when agent currentTimestamp = 2^256-1", async function () {
        await expect(
            registry.verifyHandshake(
                dummyProof(),
                validHumanSignals(),
                dummyProof(),
                validAgentSignals({ 3: UINT256_MAX })
            )
        ).to.be.revertedWithCustomError(registry, "FieldModulusExceeded");
    });

    // ---------------------------------------------------------------
    // 4. Each signal at boundary (FIELD_MODULUS - 1) — passes
    // ---------------------------------------------------------------
    describe("boundary: FIELD_MODULUS - 1 passes for each human signal slot", function () {
        for (let slot = 0; slot < 5; slot++) {
            it(`human signal[${slot}] = FIELD_MODULUS - 1 does not revert on field check`, async function () {
                // Note: downstream checks (root validity, nonce match) may
                // still fail, but the field-bound check itself must pass.
                // We only assert it does NOT revert with FieldModulusExceeded.
                const humanSigs = validHumanSignals({ [slot]: FIELD_MAX_VALID });
                const agentSigs = validAgentSignals({ 5: FIELD_MAX_VALID });
                // Adjust human nonce to match agent nonce for slot 4
                if (slot === 4) {
                    humanSigs[4] = FIELD_MAX_VALID;
                }
                try {
                    await registry.verifyHandshake(
                        dummyProof(),
                        humanSigs,
                        dummyProof(),
                        agentSigs
                    );
                } catch (e: any) {
                    // Must NOT be FieldModulusExceeded
                    expect(e.message).to.not.include("FieldModulusExceeded");
                }
            });
        }
    });

    // ---------------------------------------------------------------
    // 5. Each signal at FIELD_MODULUS — reverts
    // ---------------------------------------------------------------
    describe("boundary: FIELD_MODULUS reverts for each human signal slot", function () {
        for (let slot = 0; slot < 5; slot++) {
            it(`human signal[${slot}] = FIELD_MODULUS reverts`, async function () {
                await expect(
                    registry.verifyHandshake(
                        dummyProof(),
                        validHumanSignals({ [slot]: FIELD_FIRST_INVALID }),
                        dummyProof(),
                        validAgentSignals()
                    )
                ).to.be.revertedWithCustomError(registry, "FieldModulusExceeded");
            });
        }
    });

    describe("boundary: FIELD_MODULUS reverts for each agent signal slot", function () {
        for (let slot = 0; slot < 6; slot++) {
            it(`agent signal[${slot}] = FIELD_MODULUS reverts`, async function () {
                await expect(
                    registry.verifyHandshake(
                        dummyProof(),
                        validHumanSignals(),
                        dummyProof(),
                        validAgentSignals({ [slot]: FIELD_FIRST_INVALID })
                    )
                ).to.be.revertedWithCustomError(registry, "FieldModulusExceeded");
            });
        }
    });

    // ---------------------------------------------------------------
    // 6. usedNonces: n is consumed, n + r cannot bypass
    // ---------------------------------------------------------------
    it("usedNonces[n] is set after valid handshake; n+r cannot bypass", async function () {
        // First handshake succeeds and marks nonce as used
        await registry.verifyHandshake(
            dummyProof(),
            validHumanSignals(),
            dummyProof(),
            validAgentSignals()
        );

        // Replay with same nonce fails (nonce reused)
        await expect(
            registry.verifyHandshake(
                dummyProof(),
                validHumanSignals({ 0: 999n }),  // different nullifier
                dummyProof(),
                validAgentSignals()
            )
        ).to.be.revertedWith("IdentityRegistry: nonce reused");

        // Attempt wrap-around: n + r reverts with FieldModulusExceeded
        // BEFORE it even reaches the usedNonces check
        await expect(
            registry.verifyHandshake(
                dummyProof(),
                validHumanSignals({ 0: 998n, 4: WRAPPED_NONCE }),
                dummyProof(),
                validAgentSignals({ 5: WRAPPED_NONCE })
            )
        ).to.be.revertedWithCustomError(registry, "FieldModulusExceeded");
    });

    // ---------------------------------------------------------------
    // 7. Delegation signals — field overflow reverts
    // ---------------------------------------------------------------
    describe("delegation: field overflow reverts", function () {
        for (let slot = 0; slot < 6; slot++) {
            it(`delegation signal[${slot}] = FIELD_MODULUS reverts`, async function () {
                await expect(
                    registry.verifyDelegation(
                        dummyProof(),
                        validDelegationSignals({ [slot]: FIELD_FIRST_INVALID })
                    )
                ).to.be.revertedWithCustomError(registry, "FieldModulusExceeded");
            });
        }
    });
});
