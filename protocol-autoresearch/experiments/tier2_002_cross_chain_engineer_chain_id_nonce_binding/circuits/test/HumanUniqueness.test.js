const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");

const CIRCUIT_SRC = path.join(__dirname, "..", "src");

describe("HumanUniqueness — chainId nonce binding", function () {
    this.timeout(120_000);

    let circuit;

    before(async function () {
        circuit = await wasmTester(
            path.join(CIRCUIT_SRC, "HumanUniqueness.circom"),
            {
                include: [
                    path.join(__dirname, "..", "node_modules"),
                ],
            }
        );
    });

    // Helper: minimal valid witness inputs
    function baseInputs(chainId = 1) {
        // Build a trivial depth-1 Merkle tree for testing.
        // In production this comes from the Semaphore v4 tree.
        const identitySecret = BigInt("12345678901234567890");
        const siblings = new Array(20).fill(BigInt(0));
        const indices = new Array(20).fill(0);

        return {
            identitySecret,
            merkleProofLength: 1,
            merkleProofSiblings: siblings,
            merkleProofIndices: indices,
            // humanMerkleRoot will be computed by the circuit;
            // for witness-only tests we let circom_tester derive it.
            humanMerkleRoot: BigInt(0), // placeholder — overridden below
            externalNullifier: BigInt("42"),
            sessionNonce: BigInt("99999"),
            chainId: BigInt(chainId),
        };
    }

    // To get a valid humanMerkleRoot we need to compute it from the
    // identity commitment. We do a two-pass: first compute with a
    // wrong root to get the witness, extract the real root, then re-run.
    async function validWitness(chainId = 1) {
        const inputs = baseInputs(chainId);
        // First pass: compute identity commitment and Merkle root
        // by generating a witness with the circuit.
        // circom_tester's calculateWitness will fail on the root check,
        // so we use a helper circuit or compute manually.
        //
        // For simplicity, we compute the expected root using Poseidon.
        // Since depth=1, root = Poseidon2(leaf, sibling[0]) or
        // Poseidon2(sibling[0], leaf) depending on index[0].
        const { buildPoseidon } = require("circomlibjs");
        const poseidon = await buildPoseidon();

        // identityCommitment = Poseidon(identitySecret)
        const commitment = poseidon.F.toObject(
            poseidon([inputs.identitySecret])
        );

        // With depth=1, index[0]=0: root = Poseidon2(commitment, sibling[0])
        const root = poseidon.F.toObject(
            poseidon([commitment, inputs.merkleProofSiblings[0]])
        );

        inputs.humanMerkleRoot = root;
        const witness = await circuit.calculateWitness(inputs, true);
        return { witness, inputs };
    }

    it("should accept a valid proof with correct chainId", async function () {
        const { witness } = await validWitness(1);
        // Witness generation succeeded — constraints satisfied
        expect(witness).to.not.be.undefined;
    });

    it("should produce different nonceBinding for different chainIds", async function () {
        const { witness: w1 } = await validWitness(1);
        const { witness: w8453 } = await validWitness(8453);

        // nonceBinding is the second output signal (index 2 in witness array,
        // after the constant 1 at index 0 and nullifierHash at index 1)
        const nonceBinding1 = w1[2];
        const nonceBinding8453 = w8453[2];

        expect(nonceBinding1.toString()).to.not.equal(
            nonceBinding8453.toString(),
            "nonceBinding must differ across chainIds"
        );
    });

    it("should produce same nullifierHash regardless of chainId", async function () {
        const { witness: w1 } = await validWitness(1);
        const { witness: w8453 } = await validWitness(8453);

        // nullifierHash is the first output (index 1)
        const nullifier1 = w1[1];
        const nullifier8453 = w8453[1];

        expect(nullifier1.toString()).to.equal(
            nullifier8453.toString(),
            "nullifierHash should be chain-independent"
        );
    });

    it("chainId=0 should still produce a valid witness", async function () {
        // chainId=0 is a valid field element; the on-chain verifier
        // would reject it (block.chainid is never 0), but the circuit
        // itself should not fail.
        const { witness } = await validWitness(0);
        expect(witness).to.not.be.undefined;
    });
});
