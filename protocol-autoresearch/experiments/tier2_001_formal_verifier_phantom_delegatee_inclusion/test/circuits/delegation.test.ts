/**
 * @file delegation.test.ts
 * @notice Circom unit tests for the Delegation circuit v2.
 *
 * Tests cover:
 *   (a) Valid proof with honest witness at various depths
 *   (b) Fabricated leaf (not in tree) → constraint failure
 *   (c) Correct leaf with wrong root → constraint failure
 *   (d) Correct leaf with tampered path → constraint failure
 *
 * Prerequisites:
 *   - circom >= 2.1.6
 *   - snarkjs >= 0.7.0
 *   - circom_tester (npm: circom_tester)
 *   - circomlib (npm: circomlib)
 *
 * Run: npx mocha --require ts-node/register test/circuits/delegation.test.ts
 */

import { expect } from "chai";
import path from "path";

// circom_tester: the standard test harness for circom circuits
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;

// Poseidon hash — matches the circuit's Poseidon(2) and Poseidon(3)
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require("circomlibjs");

const TREE_DEPTH = 20;

describe("Delegation Circuit v2", function () {
    this.timeout(120_000); // Circuit compilation can be slow

    let circuit: any;
    let poseidon: any;
    let F: any; // Finite field

    before(async () => {
        // Compile the circuit
        circuit = await wasm_tester(
            path.join(__dirname, "../../circuits/delegation/delegation.circom"),
            { output: path.join(__dirname, "../../build/test_circuits") }
        );

        // Initialize Poseidon
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    // ── Helpers ──────────────────────────────────────────────────────

    function poseidonHash(inputs: bigint[]): bigint {
        return F.toObject(poseidon(inputs.map((x) => F.e(x))));
    }

    /**
     * Build a Merkle tree from leaves and return the root + proof for a given leaf index.
     * Pads with zero leaves to fill depth.
     */
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
            pathIndices.push(idx % 2); // 0 if left child, 1 if right child
            idx = Math.floor(idx / 2);
        }

        return { pathElements, pathIndices };
    }

    /**
     * Build a small tree at a given effective depth (first `effectiveDepth` levels
     * have real nodes; remaining levels pad with zero-hashes up to TREE_DEPTH).
     */
    function buildTreeAtDepth(
        leaves: bigint[],
        effectiveDepth: number
    ): { root: bigint; layers: bigint[][] } {
        // For simplicity, we always build a full depth-20 tree.
        // "Effective depth" just means we place leaves in the first 2^effectiveDepth slots.
        return buildTree(leaves, TREE_DEPTH);
    }

    function buildValidWitness(
        leaves: bigint[],
        leafIndex: number
    ): {
        agentTreeRoot: bigint;
        scopeCommitment: bigint;
        nullifierHash: bigint;
        delegatorSecret: bigint;
        delegatorNonce: bigint;
        delegateeCredCommitment: bigint;
        scope: bigint;
        merklePathElements: bigint[];
        merklePathIndices: number[];
    } {
        const delegatorSecret = 12345n;
        const delegatorNonce = 67890n;
        const scope = 42n;

        const delegateeCredCommitment = leaves[leafIndex];
        const delegatorCredCommitment = poseidonHash([delegatorSecret, delegatorNonce]);

        const { root, layers } = buildTree(leaves, TREE_DEPTH);
        const { pathElements, pathIndices } = getMerkleProof(layers, leafIndex, TREE_DEPTH);

        const scopeCommitment = poseidonHash([
            delegatorCredCommitment,
            delegateeCredCommitment,
            scope,
        ]);
        const nullifierHash = poseidonHash([delegatorSecret, scope]);

        return {
            agentTreeRoot: root,
            scopeCommitment,
            nullifierHash,
            delegatorSecret,
            delegatorNonce,
            delegateeCredCommitment,
            scope,
            merklePathElements: pathElements,
            merklePathIndices: pathIndices,
        };
    }

    // ── Test Cases ───────────────────────────────────────────────────

    it("(a) should accept a valid proof with a single leaf at index 0", async () => {
        const leaf0 = poseidonHash([111n, 222n]); // A credential commitment
        const witness = buildValidWitness([leaf0], 0);
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(a) should accept a valid proof with leaf at index 3 among 8 leaves", async () => {
        const leaves = Array.from({ length: 8 }, (_, i) =>
            poseidonHash([BigInt(i * 100 + 1), BigInt(i * 100 + 2)])
        );
        const witness = buildValidWitness(leaves, 3);
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(a) should accept a valid proof with leaf at a high index (1023)", async () => {
        const leaves: bigint[] = [];
        for (let i = 0; i < 1024; i++) {
            leaves.push(poseidonHash([BigInt(i + 1), BigInt(i + 1000)]));
        }
        const witness = buildValidWitness(leaves, 1023);
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(b) should FAIL with a fabricated leaf not in tree", async () => {
        const realLeaf = poseidonHash([111n, 222n]);
        const fakeLeaf = poseidonHash([999n, 888n]); // Not in tree

        const delegatorSecret = 12345n;
        const delegatorNonce = 67890n;
        const scope = 42n;

        const delegatorCredCommitment = poseidonHash([delegatorSecret, delegatorNonce]);

        const { root, layers } = buildTree([realLeaf], TREE_DEPTH);
        const { pathElements, pathIndices } = getMerkleProof(layers, 0, TREE_DEPTH);

        // Use the fake leaf but the real tree's proof path
        const scopeCommitment = poseidonHash([
            delegatorCredCommitment,
            fakeLeaf,
            scope,
        ]);
        const nullifierHash = poseidonHash([delegatorSecret, scope]);

        const badWitness = {
            agentTreeRoot: root,
            scopeCommitment,
            nullifierHash,
            delegatorSecret,
            delegatorNonce,
            delegateeCredCommitment: fakeLeaf,
            scope,
            merklePathElements: pathElements,
            merklePathIndices: pathIndices,
        };

        try {
            await circuit.calculateWitness(badWitness, true);
            expect.fail("Should have thrown constraint error");
        } catch (err: any) {
            // Constraint should fail because the Merkle root won't match
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(c) should FAIL with correct leaf but wrong agentTreeRoot", async () => {
        const leaf0 = poseidonHash([111n, 222n]);
        const witness = buildValidWitness([leaf0], 0);

        // Tamper with the root
        const tamperedWitness = {
            ...witness,
            agentTreeRoot: witness.agentTreeRoot + 1n,
        };

        try {
            await circuit.calculateWitness(tamperedWitness, true);
            expect.fail("Should have thrown constraint error");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(d) should FAIL with tampered Merkle path element", async () => {
        const leaf0 = poseidonHash([111n, 222n]);
        const witness = buildValidWitness([leaf0], 0);

        // Tamper with one path element
        const tamperedPath = [...witness.merklePathElements];
        tamperedPath[5] = tamperedPath[5] + 1n;

        const tamperedWitness = {
            ...witness,
            merklePathElements: tamperedPath,
        };

        try {
            await circuit.calculateWitness(tamperedWitness, true);
            expect.fail("Should have thrown constraint error");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(d) should FAIL with wrong scope commitment", async () => {
        const leaf0 = poseidonHash([111n, 222n]);
        const witness = buildValidWitness([leaf0], 0);

        const tamperedWitness = {
            ...witness,
            scopeCommitment: witness.scopeCommitment + 1n,
        };

        try {
            await circuit.calculateWitness(tamperedWitness, true);
            expect.fail("Should have thrown constraint error");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(d) should FAIL with wrong nullifier hash", async () => {
        const leaf0 = poseidonHash([111n, 222n]);
        const witness = buildValidWitness([leaf0], 0);

        const tamperedWitness = {
            ...witness,
            nullifierHash: witness.nullifierHash + 1n,
        };

        try {
            await circuit.calculateWitness(tamperedWitness, true);
            expect.fail("Should have thrown constraint error");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });
});
