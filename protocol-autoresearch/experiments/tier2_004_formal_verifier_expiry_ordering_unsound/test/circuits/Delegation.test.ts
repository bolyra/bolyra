/**
 * @file Delegation.test.ts
 * @notice Circom unit tests for the DelegationWithExpiry circuit.
 *
 * Tests cover:
 *   (a) Valid delegation with delegateeExpiry < delegatorExpiry passes
 *   (b) delegateeExpiry > delegatorExpiry fails proof generation
 *   (c) delegateeExpiry === delegatorExpiry passes (LessEqThan)
 *   (d) Expired delegation (currentTimestamp >= delegateeExpiry) fails
 *   (e) Boundary: currentTimestamp === delegateeExpiry fails (strict less-than)
 *
 * Run: npx mocha --require ts-node/register test/circuits/Delegation.test.ts
 */

import { expect } from "chai";
import path from "path";

const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const { buildPoseidon } = require("circomlibjs");

const TREE_DEPTH = 20;

describe("DelegationWithExpiry Circuit — Expiry Ordering", function () {
    this.timeout(120_000);

    let circuit: any;
    let poseidon: any;
    let F: any;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../../circuits/Delegation.circom"),
            { output: path.join(__dirname, "../../build/test_delegation_expiry") }
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
        delegatorExpiry: bigint;
        delegateeExpiry: bigint;
    }) {
        const delegatorSecret = 12345n;
        const delegatorNonce = 67890n;
        const scope = 42n;

        const delegateeCredCommitment = poseidonHash([555n, 666n]);
        const delegatorCredCommitment = poseidonHash([delegatorSecret, delegatorNonce]);

        const { root, layers } = buildTree([delegateeCredCommitment], TREE_DEPTH);
        const { pathElements, pathIndices } = getMerkleProof(layers, 0, TREE_DEPTH);

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
            currentTimestamp: opts.currentTimestamp,
            delegatorExpiry: opts.delegatorExpiry,
            delegateeExpiry: opts.delegateeExpiry,
            delegatorSecret,
            delegatorNonce,
            delegateeCredCommitment,
            scope,
            merklePathElements: pathElements,
            merklePathIndices: pathIndices,
        };
    }

    // ── Test Cases ───────────────────────────────────────────────────

    it("(a) should PASS: delegateeExpiry < delegatorExpiry, not expired", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700000000n,
            delegatorExpiry: 1700200000n,
            delegateeExpiry: 1700100000n,
        });
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(b) should FAIL: delegateeExpiry > delegatorExpiry", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700000000n,
            delegatorExpiry: 1700100000n,
            delegateeExpiry: 1700200000n, // Exceeds delegator
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown: delegatee expiry exceeds delegator");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(c) should PASS: delegateeExpiry === delegatorExpiry (LessEqThan)", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700000000n,
            delegatorExpiry: 1700100000n,
            delegateeExpiry: 1700100000n, // Equal is allowed
        });
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(d) should FAIL: delegation expired (currentTimestamp > delegateeExpiry)", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700100001n,
            delegatorExpiry: 1700200000n,
            delegateeExpiry: 1700100000n, // Already expired
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown: delegation expired");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(e) should FAIL: boundary currentTimestamp === delegateeExpiry", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700100000n,
            delegatorExpiry: 1700200000n,
            delegateeExpiry: 1700100000n, // Exact equality — strict LT fails
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown: exact boundary fails strict less-than");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });

    it("(f) should PASS: currentTimestamp === delegateeExpiry - 1", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700099999n,
            delegatorExpiry: 1700200000n,
            delegateeExpiry: 1700100000n,
        });
        const w = await circuit.calculateWitness(witness, true);
        await circuit.checkConstraints(w);
    });

    it("(g) should FAIL: delegateeExpiry exceeds delegator by 1", async () => {
        const witness = buildValidWitness({
            currentTimestamp: 1700000000n,
            delegatorExpiry: 1700100000n,
            delegateeExpiry: 1700100001n, // Off by one
        });

        try {
            await circuit.calculateWitness(witness, true);
            expect.fail("Should have thrown: off-by-one exceeds delegator");
        } catch (err: any) {
            expect(err.message).to.match(/assert|constraint|not equal/i);
        }
    });
});
