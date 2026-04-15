const { expect } = require("chai");
const path = require("path");
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;

// Poseidon hash (using snarkjs/ffjavascript)
const { buildPoseidon } = require("circomlibjs");
const { buildEddsa } = require("circomlibjs");

describe("AgentPolicy Circuit", function () {
  this.timeout(120000); // circuit compilation can take time

  let circuit;
  let poseidon;
  let eddsa;
  let F; // finite field

  before(async function () {
    // Compile circuit with circom_tester
    circuit = await wasm_tester(
      path.join(__dirname, "../src/AgentPolicy.circom"),
      {
        include: [
          path.join(__dirname, "../node_modules"),
          path.join(__dirname, "../node_modules/circomlib/circuits"),
        ],
      }
    );

    poseidon = await buildPoseidon();
    eddsa = await buildEddsa();
    F = poseidon.F;
  });

  // Helper: create a valid agent credential and sign it
  function createAgentCredential(
    modelHash,
    permissionBitmask,
    expiryTimestamp
  ) {
    // Generate operator EdDSA keypair
    const privateKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );
    const pubKey = eddsa.prv2pub(privateKey);

    // Compute credential commitment = Poseidon4(modelHash, Ax, bitmask, expiry)
    const credentialCommitment = poseidon([
      modelHash,
      F.toObject(pubKey[0]),
      permissionBitmask,
      expiryTimestamp,
    ]);

    // Sign the credential commitment
    // signPoseidon expects the message as a field element (F.e), not a BigInt
    const signature = eddsa.signPoseidon(privateKey, credentialCommitment);

    return {
      modelHash: BigInt(modelHash),
      operatorPubkeyAx: F.toObject(pubKey[0]),
      operatorPubkeyAy: F.toObject(pubKey[1]),
      permissionBitmask: BigInt(permissionBitmask),
      expiryTimestamp: BigInt(expiryTimestamp),
      sigR8x: F.toObject(signature.R8[0]),
      sigR8y: F.toObject(signature.R8[1]),
      sigS: signature.S,
      credentialCommitment: F.toObject(credentialCommitment),
    };
  }

  // Helper: build a simple Merkle tree and generate a proof
  function buildMerkleTree(leaves, leafIndex, maxDepth) {
    // Simple binary Merkle tree using Poseidon2
    const depth = Math.max(1, Math.ceil(Math.log2(Math.max(leaves.length, 2))));
    let currentLevel = leaves.map((l) => BigInt(l));

    // Pad to power of 2
    while (currentLevel.length < 2 ** depth) {
      currentLevel.push(0n);
    }

    const siblings = [];
    let index = leafIndex;

    for (let level = 0; level < depth; level++) {
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
      siblings.push(currentLevel[siblingIndex]);

      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const hash = poseidon([currentLevel[i], currentLevel[i + 1]]);
        nextLevel.push(F.toObject(hash));
      }
      currentLevel = nextLevel;
      index = Math.floor(index / 2);
    }

    // Pad siblings to MAX_DEPTH
    while (siblings.length < maxDepth) {
      siblings.push(0n);
    }

    return {
      root: currentLevel[0],
      siblings,
      depth,
      index: leafIndex,
    };
  }

  it("should verify a valid agent credential (happy path)", async function () {
    const modelHash = 12345n;
    const permissionBitmask = 0b00000111n; // bits 0,1,2 set (read, write, financial <$100)
    const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + 86400); // +1 day
    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
    const sessionNonce = 42n;
    const requiredScopeMask = 0b00000011n; // require read + write

    const cred = createAgentCredential(
      modelHash,
      permissionBitmask,
      expiryTimestamp
    );

    // Build a tree with this credential as the only leaf
    const tree = buildMerkleTree(
      [cred.credentialCommitment],
      0,
      20
    );

    const input = {
      // Private
      modelHash: cred.modelHash,
      operatorPubkeyAx: cred.operatorPubkeyAx,
      operatorPubkeyAy: cred.operatorPubkeyAy,
      permissionBitmask: cred.permissionBitmask,
      expiryTimestamp: cred.expiryTimestamp,
      sigR8x: cred.sigR8x,
      sigR8y: cred.sigR8y,
      sigS: cred.sigS,
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings,
      // Public
      requiredScopeMask: requiredScopeMask,
      currentTimestamp: currentTimestamp,
      sessionNonce: sessionNonce,
    };

    // This should succeed without errors (witness generation passes)
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // Verify public outputs via witness signal extraction
    // In circom_tester, outputs are at witness indices 1, 2, 3 (index 0 is always 1)
    const agentMerkleRoot = witness[1];
    const nullifierHash = witness[2];
    const scopeCommitment = witness[3];

    // Merkle root should match what we computed
    expect(agentMerkleRoot.toString()).to.equal(tree.root.toString());

    console.log("  Merkle root:", agentMerkleRoot.toString().slice(0, 20) + "...");
    console.log("  Nullifier:", nullifierHash.toString().slice(0, 20) + "...");
    console.log("  Scope commitment:", scopeCommitment.toString().slice(0, 20) + "...");
  });

  it("should reject insufficient permissions", async function () {
    const modelHash = 12345n;
    const permissionBitmask = 0b00000001n; // only bit 0 (read)
    const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) + 86400);
    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
    const sessionNonce = 42n;
    const requiredScopeMask = 0b00000011n; // require read + write (bit 1 missing!)

    const cred = createAgentCredential(
      modelHash,
      permissionBitmask,
      expiryTimestamp
    );

    const tree = buildMerkleTree(
      [cred.credentialCommitment],
      0,
      20
    );

    const input = {
      modelHash: cred.modelHash,
      operatorPubkeyAx: cred.operatorPubkeyAx,
      operatorPubkeyAy: cred.operatorPubkeyAy,
      permissionBitmask: cred.permissionBitmask,
      expiryTimestamp: cred.expiryTimestamp,
      sigR8x: cred.sigR8x,
      sigR8y: cred.sigR8y,
      sigS: cred.sigS,
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings,
      requiredScopeMask: requiredScopeMask,
      currentTimestamp: currentTimestamp,
      sessionNonce: sessionNonce,
    };

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have thrown: insufficient permissions");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("should reject expired credentials", async function () {
    const modelHash = 12345n;
    const permissionBitmask = 0b00000111n;
    const expiryTimestamp = BigInt(Math.floor(Date.now() / 1000) - 3600); // 1 hour ago
    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
    const sessionNonce = 42n;
    const requiredScopeMask = 0b00000001n;

    const cred = createAgentCredential(
      modelHash,
      permissionBitmask,
      expiryTimestamp
    );

    const tree = buildMerkleTree(
      [cred.credentialCommitment],
      0,
      20
    );

    const input = {
      modelHash: cred.modelHash,
      operatorPubkeyAx: cred.operatorPubkeyAx,
      operatorPubkeyAy: cred.operatorPubkeyAy,
      permissionBitmask: cred.permissionBitmask,
      expiryTimestamp: cred.expiryTimestamp,
      sigR8x: cred.sigR8x,
      sigR8y: cred.sigR8y,
      sigS: cred.sigS,
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings,
      requiredScopeMask: requiredScopeMask,
      currentTimestamp: currentTimestamp,
      sessionNonce: sessionNonce,
    };

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have thrown: expired credential");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });
});
