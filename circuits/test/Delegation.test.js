const { expect } = require("chai");
const path = require("path");
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;
const { buildPoseidon, buildEddsa } = require("circomlibjs");

const MAX_DEPTH = 20;

describe("Delegation Circuit", function () {
  this.timeout(120000);

  let circuit;
  let poseidon;
  let eddsa;
  let F;

  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "../src/Delegation.circom"),
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

  // Helper: build a minimal Merkle proof for a single-leaf tree.
  // For a tree with just the leaf, depth=1, index=0, siblings[0]=0 (empty sibling).
  // BinaryMerkleRoot computes: hash(leaf, 0) at depth 1.
  function buildSingleLeafMerkleProof(leaf) {
    const siblings = new Array(MAX_DEPTH).fill("0");
    return {
      delegateeMerkleProofLength: "1",
      delegateeMerkleProofIndex: "0",
      delegateeMerkleProofSiblings: siblings,
    };
  }

  // Helper: create a delegation and sign it
  function createDelegation({
    delegatorScope,
    delegateeScope,
    delegatorExpiry,
    delegateeExpiry,
    delegatorCredCommitment = 99999n,
    delegateeCredCommitment = 12345n,
    sessionNonce = 42n,
    delegatorPrivKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001", "hex"
    ),
    delegateeMerkleProof = null,
  }) {
    const delegatorPubKey = eddsa.prv2pub(delegatorPrivKey);

    // Previous scope commitment = Poseidon(delegatorScope, delegatorCredCommitment)
    // Identity-bound: scope + credential commitment (Fix #3)
    const previousScopeCommitment = F.toObject(poseidon([delegatorScope, delegatorCredCommitment]));

    // Delegation token = Poseidon4(prevScopeCommit, delegateeCredCommit, delegateeScope, delegateeExpiry)
    const tokenFe = poseidon([
      previousScopeCommitment,
      delegateeCredCommitment,
      delegateeScope,
      delegateeExpiry,
    ]);

    // Sign the token
    const sig = eddsa.signPoseidon(delegatorPrivKey, tokenFe);

    // Default: use single-leaf Merkle proof for delegatee
    const merkleProof = delegateeMerkleProof || buildSingleLeafMerkleProof(delegateeCredCommitment);

    return {
      delegatorScope: delegatorScope.toString(),
      delegateeScope: delegateeScope.toString(),
      delegateeExpiry: delegateeExpiry.toString(),
      delegatorExpiry: delegatorExpiry.toString(),
      delegatorPubkeyAx: F.toObject(delegatorPubKey[0]).toString(),
      delegatorPubkeyAy: F.toObject(delegatorPubKey[1]).toString(),
      sigR8x: F.toObject(sig.R8[0]).toString(),
      sigR8y: F.toObject(sig.R8[1]).toString(),
      sigS: sig.S.toString(),
      delegatorCredCommitment: delegatorCredCommitment.toString(),
      delegateeCredCommitment: delegateeCredCommitment.toString(),
      previousScopeCommitment: previousScopeCommitment.toString(),
      sessionNonce: sessionNonce.toString(),
      ...merkleProof,
    };
  }

  it("should verify a valid single-hop delegation", async function () {
    const input = createDelegation({
      delegatorScope: 0b00000111n,   // read + write + financial <$100
      delegateeScope: 0b00000011n,   // read + write (narrower)
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,      // earlier expiry (narrower)
    });

    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // Output: newScopeCommitment = Poseidon(delegateeScope, delegateeCredCommitment)
    const expectedNewCommitment = F.toObject(poseidon([0b00000011n, 12345n]));
    expect(witness[1].toString()).to.equal(expectedNewCommitment.toString());
    console.log("  New scope commitment:", witness[1].toString().slice(0, 20) + "...");
    console.log("  Delegation nullifier:", witness[2].toString().slice(0, 20) + "...");
  });

  it("should chain two delegations (scope commitment linking)", async function () {
    // Hop 1: delegator (0xFF) → agent A (0x0F)
    // delegateeCredCommitment for agent A = 54321
    const agentACredCommitment = 54321n;
    const hop1 = createDelegation({
      delegatorScope: 0b11111111n,
      delegateeScope: 0b00001111n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 800000n,
      delegateeCredCommitment: agentACredCommitment,
    });
    const witness1 = await circuit.calculateWitness(hop1, true);
    await circuit.checkConstraints(witness1);
    const hop1ScopeCommitment = witness1[1]; // newScopeCommitment from hop 1

    // Hop 2: agent A (0x0F) → agent B (0x03)
    // previousScopeCommitment must be hop1's output
    // agent A is now the delegator, so delegatorCredCommitment = agentACredCommitment
    const hop2PrivKey = Buffer.from(
      "0102030405060708090001020304050607080900010203040506070809000102", "hex"
    );
    const hop2 = createDelegation({
      delegatorScope: 0b00001111n,       // agent A's scope
      delegateeScope: 0b00000011n,       // agent B's scope (narrower)
      delegatorExpiry: 800000n,
      delegateeExpiry: 600000n,
      delegatorCredCommitment: agentACredCommitment,  // agent A's cred (now delegator)
      delegatorPrivKey: hop2PrivKey,
    });

    // Verify the identity-bound chain link:
    // hop1 output = Poseidon(0x0F, agentACredCommitment)
    // hop2 input previousScopeCommitment should match
    const expectedLink = F.toObject(poseidon([0b00001111n, agentACredCommitment]));
    expect(hop1ScopeCommitment.toString()).to.equal(expectedLink.toString());

    // Override previousScopeCommitment to match hop1's output (should already match)
    hop2.previousScopeCommitment = hop1ScopeCommitment.toString();

    const witness2 = await circuit.calculateWitness(hop2, true);
    await circuit.checkConstraints(witness2);

    console.log("  Hop 1 scope commitment:", hop1ScopeCommitment.toString().slice(0, 20) + "...");
    console.log("  Hop 2 scope commitment:", witness2[1].toString().slice(0, 20) + "...");
  });

  // ============ SECURITY TESTS ============

  it("should REJECT scope escalation attack", async function () {
    // Delegator has read-only (bit 0), delegatee tries to claim read+write (bits 0+1)
    const input = createDelegation({
      delegatorScope: 0b00000001n,   // read only
      delegateeScope: 0b00000011n,   // read + write (ESCALATION!)
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected scope escalation");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("should REJECT expiry escalation attack", async function () {
    // Delegatee tries to set expiry LATER than delegator's
    const input = createDelegation({
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 500000n,
      delegateeExpiry: 1000000n,     // LATER than delegator (ESCALATION!)
    });

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected expiry escalation");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("should REJECT broken cumulative bit invariant (bit 4 without bit 3)", async function () {
    // bit 4 (unlimited financial) requires bit 3 ($10k) to be set
    const input = createDelegation({
      delegatorScope: 0b00011111n,   // all financial bits set (valid)
      delegateeScope: 0b00010101n,   // bit 4 set, bit 3 NOT set (INVALID)
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected broken cumulative invariant");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("should REJECT broken cumulative bit invariant (bit 3 without bit 2)", async function () {
    // bit 3 ($10k financial) requires bit 2 ($100) to be set
    const input = createDelegation({
      delegatorScope: 0b00001111n,   // valid
      delegateeScope: 0b00001001n,   // bit 3 set, bit 2 NOT set (INVALID)
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected broken cumulative invariant");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("should ACCEPT valid cumulative bit encoding", async function () {
    // bit 4 with bits 2+3 set — valid
    const input = createDelegation({
      delegatorScope: 0b00011111n,
      delegateeScope: 0b00011100n,   // bits 2,3,4 all set — valid cumulative
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
  });

  it("should REJECT wrong previousScopeCommitment (chain break)", async function () {
    // Delegatee provides a delegatorScope that doesn't match previousScopeCommitment
    const input = createDelegation({
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    // Tamper with previousScopeCommitment
    input.previousScopeCommitment = "999999999";

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected broken chain link");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  it("should REJECT forged signature", async function () {
    const input = createDelegation({
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    // Tamper with signature
    input.sigS = "12345";

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have rejected forged signature");
    } catch (err) {
      expect(err.message).to.include("Assert Failed");
    }
  });

  // ============ CIP-1: Delegatee Merkle proof tests ============

  it("should output delegateeMerkleRoot for an enrolled delegatee (CIP-1)", async function () {
    const input = createDelegation({
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    });

    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // Output indices: [1] = newScopeCommitment, [2] = delegationNullifier, [3] = delegateeMerkleRoot
    const delegateeMerkleRoot = witness[3];
    expect(delegateeMerkleRoot).to.not.equal(0n);
    console.log("  Delegatee Merkle root:", delegateeMerkleRoot.toString().slice(0, 20) + "...");
  });

  it("should compute a different Merkle root for a different delegatee (CIP-1 on-chain check)", async function () {
    // Two delegations with different delegatees should produce different Merkle roots
    const input1 = createDelegation({
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
      delegateeCredCommitment: 11111n,
    });

    const input2 = createDelegation({
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
      delegateeCredCommitment: 22222n,
    });

    const witness1 = await circuit.calculateWitness(input1, true);
    const witness2 = await circuit.calculateWitness(input2, true);
    await circuit.checkConstraints(witness1);
    await circuit.checkConstraints(witness2);

    // Different delegatees should produce different Merkle roots
    // (which the on-chain verifier would check against agentRootExists)
    expect(witness1[3].toString()).to.not.equal(witness2[3].toString());
  });

  it("should produce unique nullifiers for different nonces", async function () {
    const base = {
      delegatorScope: 0b00000111n,
      delegateeScope: 0b00000011n,
      delegatorExpiry: 1000000n,
      delegateeExpiry: 500000n,
    };

    const input1 = createDelegation({ ...base, sessionNonce: 1n });
    const input2 = createDelegation({ ...base, sessionNonce: 2n });

    const witness1 = await circuit.calculateWitness(input1, true);
    const witness2 = await circuit.calculateWitness(input2, true);

    // Same scope commitments
    expect(witness1[1].toString()).to.equal(witness2[1].toString());
    // Different nullifiers
    expect(witness1[2].toString()).to.not.equal(witness2[2].toString());
  });
});
