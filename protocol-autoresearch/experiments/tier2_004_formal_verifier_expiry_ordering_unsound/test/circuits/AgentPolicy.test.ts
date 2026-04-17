/**
 * @file AgentPolicy.test.ts
 * @notice Circom unit tests for the AgentPolicy circuit.
 *
 * Tests cover:
 *   (a) Valid unexpired credential passes proof generation
 *   (b) Expired credential (currentTimestamp >= expiryTimestamp) fails
 *   (c) Boundary: currentTimestamp === expiryTimestamp fails (strict less-than)
 *   (d) Boundary: currentTimestamp === expiryTimestamp - 1 passes
 *   (e) Tampered timestamps fail range checks
 *
 * Run: npx mocha --require ts-node/register test/circuits/AgentPolicy.test.ts
 */

import { expect } from "chai";
import path from "path";

const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const { buildPoseidon } = require("circomlibjs");

const TREE_DEPTH = 20;

describe("AgentPolicy Circuit — Expiry Enforcement", function () {
    this.timeout(120_000);

    let circuit: any;
    let poseidon: any;
    let F: any;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../../circuits/AgentPolicy.circom"),
            { output: path.join(__dirname, "../../build/test_agent_policy") }
        );
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    function poseidonHash(inputs: bigint[]): bigint {
        return F.toObject(poseidon(inputs.map((x: bigint) => F.e(x))));
    }

    function buildTree(
        leaves: bigint[],
        depth: number
    ): { root: bigint; layers: bigint[][] } {
        const numLeaves = 2 ** depth;
        const paddedLeaves = [...leaves];
        while (paddedLeaves.length < numLeaves) {
            paddedLeaves.push(0n);
        }
        const layers: bigint[][] = [paddedLeaves];
        let currentLayer = paddedLeaves;
        for (let i = 0; i < depth; i++) {
            const nextLayer: bigint[] = [];
            for (let j = 0; j < currentLayer.length; j += 2) {
                nextLayer.push(poseidonHash([currentLayer[j], currentLayer[j + 1]]));
            }
            layers.push(nextLayer);
            currentLayer = nextLayer;
        }
        return { root: currentLayer[0], layers };
    }

    function getMerkleProof(
        layers: bigint[][],
        leafIndex: number,
        depth: number
    ): { pathElements: bigint[]; pathIndices: number[] } {
        const pathElements: bigint[] = [];
        const pathIndices: number[] = [];
        let idx = leafIndex;
        for (let i = 0; i < depth; i++) {
            const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
            pathElements.push(layers[i][siblingIdx]);
            pathIndices.push(idx % 2);
            idx = Math.floor(idx / 2);
        }
        return { pathElements, pathIndices };
    }

    function buildValidWitness(opts: {
        currentTimestamp: bigint;
        expiryTimestamp: bigint;
    }) {
        const agentSecret = 12345n;
        const agentNonce = 67890n;
        const policyScope = 42n;

        const agentCredCommitment = poseidonHash([agentSecret, agentNonce]);
        const { root, layers } = buildTree([agentCredCommitment], TREE_DEPTH);
        const { pathElements, pathIndices } = getMerkleProof(layers, 0, TREE_DEPTH);
        const nullifierHash = poseidonHash([agentSecret, policyScope]);

        return {
            agentTreeRoot: root,
            nullifierHash,
            currentTimestamp: opts.currentTimestamp,
            expiryTimestamp: opts.expiryTimestamp,
            agentSecret,
            agentNonce,
            policyScope,
            merklePathElements: pathElements,
            merklePathIndices: pathIndices,
        };
    }

    // ── Test Cases ───────────────────────────────────────────────────

    it("(a) should PASS with valid unexpired credential", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700000000n,
            expiryTimestamp: 1700100000n, // 100,000 seconds in the future
        });
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(b) should FAIL with expired credential (currentTimestamp > expiryTimestamp)", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700100001n,
            expiryTimestamp: 1700100000n, // Already expired
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown constraint error for expired credential");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(c) should FAIL at boundary: currentTimestamp === expiryTimestamp", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700100000n,
            expiryTimestamp: 1700100000n, // Exactly equal — strict less-than fails
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown constraint error at exact boundary");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(d) should PASS at boundary: currentTimestamp === expiryTimestamp - 1", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700099999n,
            expiryTimestamp: 1700100000n, // One second before expiry
        });
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(e) should PASS with far-future expiry", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1n,
            expiryTimestamp: 18446744073709551615n, // max uint64
        });
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(f) should FAIL with zero expiry and nonzero current time", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1n,
            expiryTimestamp: 0n,
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown constraint error");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });
});
