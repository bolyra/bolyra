const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");
const { buildEddsa } = require("circomlibjs");

const CIRCUIT_SRC = path.join(__dirname, "..", "src");

describe("AgentPolicy — chainId nonce binding", function () {
    this.timeout(120_000);

    let circuit;
    let poseidon;
    let eddsa;
    let F;

    before(async function () {
        circuit = await wasmTester(
            path.join(CIRCUIT_SRC, "AgentPolicy.circom"),
            {
                include: [
                    path.join(__dirname, "..", "node_modules"),
                ],
            }
        );
        poseidon = await buildPoseidon();
        eddsa = await buildEddsa();
        F = poseidon.F;
    });

    async function validWitness(chainId = 1) {
        // Generate a valid EdDSA key pair
        const privKey = Buffer.alloc(32);
        privKey[0] = 1; // deterministic test key
        const pubKey = eddsa.prv2pub(privKey);

        const modelHash = BigInt("111");
        const permissions = 3; // READ_DATA | WRITE_DATA
        const expiry = BigInt("9999999999");

        // credentialHash = Poseidon4(modelHash, pubKeyX, permissions, expiry)
        const credHash = F.toObject(
            poseidon([
                modelHash,
                F.toObject(pubKey[0]),
                BigInt(permissions),
                expiry,
            ])
        );

        // Sign the credential hash
        const sig = eddsa.signPoseidon(privKey, F.e(credHash));

        // Depth-1 Merkle tree with credential as leaf
        const siblings = new Array(20).fill(BigInt(0));
        const indices = new Array(20).fill(0);
        const root = F.toObject(poseidon([credHash, BigInt(0)]));

        const inputs = {
            modelHash,
            operatorPubKeyX: F.toObject(pubKey[0]),
            operatorPubKeyY: F.toObject(pubKey[1]),
            signatureR8x: F.toObject(sig.R8[0]),
            signatureR8y: F.toObject(sig.R8[1]),
            signatureS: sig.S,
            permissions,
            expiry,
            merkleProofLength: 1,
            merkleProofSiblings: siblings,
            merkleProofIndices: indices,
            agentMerkleRoot: root,
            currentTimestamp: BigInt("1000000000"),
            requiredPermissions: 1, // READ_DATA only
            sessionNonce: BigInt("99999"),
            chainId: BigInt(chainId),
        };

        const witness = await circuit.calculateWitness(inputs, true);
        return { witness, inputs };
    }

    it("should accept a valid proof with correct chainId", async function () {
        const { witness } = await validWitness(1);
        expect(witness).to.not.be.undefined;
    });

    it("should produce different nonceBinding for different chainIds", async function () {
        const { witness: w1 } = await validWitness(1);
        const { witness: w8453 } = await validWitness(8453);

        // nonceBinding is the second output (index 2 in witness)
        const nonceBinding1 = w1[2];
        const nonceBinding8453 = w8453[2];

        expect(nonceBinding1.toString()).to.not.equal(
            nonceBinding8453.toString(),
            "nonceBinding must differ across chainIds"
        );
    });

    it("should produce same credentialHash regardless of chainId", async function () {
        const { witness: w1 } = await validWitness(1);
        const { witness: w8453 } = await validWitness(8453);

        // credentialHash is the first output (index 1)
        const cred1 = w1[1];
        const cred8453 = w8453[1];

        expect(cred1.toString()).to.equal(
            cred8453.toString(),
            "credentialHash should be chain-independent"
        );
    });

    it("chainId=0 should still produce a valid witness", async function () {
        const { witness } = await validWitness(0);
        expect(witness).to.not.be.undefined;
    });
});
