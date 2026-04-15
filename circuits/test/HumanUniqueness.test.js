const { expect } = require("chai");
const path = require("path");
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const { buildPoseidon, buildBabyjub } = require("circomlibjs");

describe("HumanUniqueness Circuit", function () {
  this.timeout(120000);

  let circuit;
  let poseidon;
  let babyJub;
  let F;

  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "../src/HumanUniqueness.circom"),
      {
        include: [
          path.join(__dirname, "../node_modules"),
          path.join(__dirname, "../node_modules/circomlib/circuits"),
        ],
      }
    );

    poseidon = await buildPoseidon();
    babyJub = await buildBabyjub();
    F = poseidon.F;
  });

  // Helper: derive EdDSA identity (Semaphore v4 compatible)
  // secret → BabyPbk → (Ax, Ay) → identityCommitment = Poseidon2(Ax, Ay)
  function deriveIdentity(secretScalar) {
    // BabyPbk multiplies the base point by the secret scalar
    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, secretScalar);
    const Ax = F.toObject(pubKey[0]);
    const Ay = F.toObject(pubKey[1]);
    const commitment = poseidon([Ax, Ay]);
    return {
      secret: secretScalar,
      Ax,
      Ay,
      identityCommitment: F.toObject(commitment),
    };
  }

  // Helper: build Merkle tree and proof (same as AgentPolicy tests)
  function buildMerkleTree(leaves, leafIndex, maxDepth) {
    const depth = Math.max(1, Math.ceil(Math.log2(Math.max(leaves.length, 2))));
    let currentLevel = leaves.map((l) => BigInt(l));
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
    while (siblings.length < maxDepth) siblings.push(0n);

    return { root: currentLevel[0], siblings, depth, index: leafIndex };
  }

  // Use a small secret scalar that fits in the Baby Jubjub subgroup
  const TEST_SECRET = 123456789n;

  it("should verify a valid human identity (happy path)", async function () {
    const identity = deriveIdentity(TEST_SECRET);
    const tree = buildMerkleTree([identity.identityCommitment], 0, 20);
    const scope = 1n; // handshake scope
    const sessionNonce = 42n;

    const input = {
      secret: identity.secret.toString(),
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings.map((s) => s.toString()),
      scope: scope.toString(),
      sessionNonce: sessionNonce.toString(),
    };

    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // Public outputs: [humanMerkleRoot, nullifierHash, nonceBinding]
    const humanMerkleRoot = witness[1];
    const nullifierHash = witness[2];
    const nonceBinding = witness[3];

    expect(humanMerkleRoot.toString()).to.equal(tree.root.toString());

    // Verify nullifier = Poseidon2(scope, secret)
    const expectedNullifier = F.toObject(poseidon([scope, TEST_SECRET]));
    expect(nullifierHash.toString()).to.equal(expectedNullifier.toString());

    // Verify nonceBinding = Poseidon2(nullifierHash, sessionNonce)
    const expectedBinding = F.toObject(poseidon([expectedNullifier, sessionNonce]));
    expect(nonceBinding.toString()).to.equal(expectedBinding.toString());

    console.log("  Merkle root:", humanMerkleRoot.toString().slice(0, 20) + "...");
    console.log("  Nullifier:", nullifierHash.toString().slice(0, 20) + "...");
    console.log("  Nonce binding:", nonceBinding.toString().slice(0, 20) + "...");
  });

  it("should produce different nullifiers for different scopes", async function () {
    const identity = deriveIdentity(TEST_SECRET);
    const tree = buildMerkleTree([identity.identityCommitment], 0, 20);

    const input1 = {
      secret: identity.secret.toString(),
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings.map((s) => s.toString()),
      scope: "1",
      sessionNonce: "42",
    };
    const input2 = { ...input1, scope: "2" };

    const witness1 = await circuit.calculateWitness(input1, true);
    const witness2 = await circuit.calculateWitness(input2, true);

    const nullifier1 = witness1[2];
    const nullifier2 = witness2[2];

    expect(nullifier1.toString()).to.not.equal(nullifier2.toString());
  });

  it("should produce different nonce bindings for different nonces", async function () {
    const identity = deriveIdentity(TEST_SECRET);
    const tree = buildMerkleTree([identity.identityCommitment], 0, 20);

    const input1 = {
      secret: identity.secret.toString(),
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings.map((s) => s.toString()),
      scope: "1",
      sessionNonce: "42",
    };
    const input2 = { ...input1, sessionNonce: "43" };

    const witness1 = await circuit.calculateWitness(input1, true);
    const witness2 = await circuit.calculateWitness(input2, true);

    // Same nullifier (same scope + secret)
    expect(witness1[2].toString()).to.equal(witness2[2].toString());
    // Different nonce binding
    expect(witness1[3].toString()).to.not.equal(witness2[3].toString());
  });

  it("should reject wrong Merkle proof (non-member)", async function () {
    const identity = deriveIdentity(TEST_SECRET);
    const otherIdentity = deriveIdentity(999999n);
    // Tree contains otherIdentity, but we try to prove with TEST_SECRET
    const tree = buildMerkleTree([otherIdentity.identityCommitment], 0, 20);

    const input = {
      secret: identity.secret.toString(),
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings.map((s) => s.toString()),
      scope: "1",
      sessionNonce: "42",
    };

    // Witness generation should succeed (circuit computes a root),
    // but the computed root won't match the tree root.
    // The on-chain verifier catches this mismatch.
    const witness = await circuit.calculateWitness(input, true);
    const computedRoot = witness[1];

    expect(computedRoot.toString()).to.not.equal(tree.root.toString());
  });

  it("should produce consistent outputs for same inputs", async function () {
    const identity = deriveIdentity(TEST_SECRET);
    const tree = buildMerkleTree([identity.identityCommitment], 0, 20);

    const input = {
      secret: identity.secret.toString(),
      merkleProofLength: tree.depth,
      merkleProofIndex: tree.index,
      merkleProofSiblings: tree.siblings.map((s) => s.toString()),
      scope: "1",
      sessionNonce: "42",
    };

    const witness1 = await circuit.calculateWitness(input, true);
    const witness2 = await circuit.calculateWitness(input, true);

    // Deterministic: same inputs → same outputs
    expect(witness1[1].toString()).to.equal(witness2[1].toString()); // root
    expect(witness1[2].toString()).to.equal(witness2[2].toString()); // nullifier
    expect(witness1[3].toString()).to.equal(witness2[3].toString()); // nonce binding
  });

  it("should work with multiple members in tree", async function () {
    const identity1 = deriveIdentity(111n);
    const identity2 = deriveIdentity(222n);
    const identity3 = deriveIdentity(333n);

    const tree = buildMerkleTree(
      [identity1.identityCommitment, identity2.identityCommitment, identity3.identityCommitment],
      1, // prove identity2
      20
    );

    const input = {
      secret: identity2.secret.toString(),
      merkleProofLength: tree.depth,
      merkleProofIndex: "1",
      merkleProofSiblings: tree.siblings.map((s) => s.toString()),
      scope: "1",
      sessionNonce: "42",
    };

    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    const computedRoot = witness[1];
    expect(computedRoot.toString()).to.equal(tree.root.toString());
  });
});
