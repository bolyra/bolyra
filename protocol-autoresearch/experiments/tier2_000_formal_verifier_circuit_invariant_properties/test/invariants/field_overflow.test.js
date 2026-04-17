/**
 * field_overflow.test.js
 *
 * circom_tester harness verifying no uint64 signal exceeds 2^64-1
 * after range checks, covering Identity, Credential, and Delegation circuits.
 *
 * Properties tested: P1, P4, P6, P7, P8
 * (P2, P3, P5 are field-element outputs from Poseidon — inherently < p)
 */

const path = require("path");
const { wasm: wasm_tester } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");

// Constants
const MAX_UINT64 = BigInt(2) ** BigInt(64) - BigInt(1); // 2^64 - 1
const OVERFLOW_UINT64 = BigInt(2) ** BigInt(64);          // 2^64 (should fail)
const ZERO = BigInt(0);
const MID_UINT64 = BigInt(2) ** BigInt(32);               // midpoint

// Merkle tree helpers — generate a valid path for depth 20
function generateMerklePath(leaf, poseidon, depth = 20) {
  const pathElements = [];
  const pathIndices = [];
  let current = leaf;
  for (let i = 0; i < depth; i++) {
    const sibling = poseidon.F.toObject(poseidon([BigInt(i + 1000), BigInt(i)]));
    pathElements.push(sibling);
    pathIndices.push(0);
    current = poseidon.F.toObject(poseidon([current, sibling]));
  }
  return { pathElements, pathIndices, root: current };
}

describe("Field Overflow Invariants", () => {
  let poseidon;

  beforeAll(async () => {
    poseidon = await buildPoseidon();
  });

  // ============================================================
  //  P1: Identity — identityCommitment range [0, 2^64)
  // ============================================================
  describe("P1: Identity commitment range", () => {
    let circuit;

    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../../circuits/src/Identity.circom")
      );
    });

    function makeIdentityWitness(identityCommitment) {
      const secret = BigInt(12345);
      const scope = BigInt(1);
      const leaf = poseidon.F.toObject(poseidon([identityCommitment, secret]));
      const humanPath = generateMerklePath(leaf, poseidon);
      const agentPath = generateMerklePath(leaf, poseidon);

      return {
        identityCommitment,
        secret,
        scope,
        humanPathElements: humanPath.pathElements,
        humanPathIndices: humanPath.pathIndices,
        humanRoot: humanPath.root,
        agentPathElements: agentPath.pathElements,
        agentPathIndices: agentPath.pathIndices,
        agentRoot: agentPath.root,
      };
    }

    test("ACCEPT: identityCommitment = 0", async () => {
      const w = await circuit.calculateWitness(makeIdentityWitness(ZERO));
      await circuit.checkConstraints(w);
    });

    test("ACCEPT: identityCommitment = 2^64 - 1", async () => {
      const w = await circuit.calculateWitness(makeIdentityWitness(MAX_UINT64));
      await circuit.checkConstraints(w);
    });

    test("REJECT: identityCommitment = 2^64 (overflow)", async () => {
      await expect(async () => {
        const w = await circuit.calculateWitness(makeIdentityWitness(OVERFLOW_UINT64));
        await circuit.checkConstraints(w);
      }).rejects.toThrow();
    });

    test("ACCEPT: identityCommitment = 2^32 (midpoint)", async () => {
      const w = await circuit.calculateWitness(makeIdentityWitness(MID_UINT64));
      await circuit.checkConstraints(w);
    });
  });

  // ============================================================
  //  P4: Credential — expiryTimestamp range [0, 2^64)
  // ============================================================
  describe("P4: Credential expiry range", () => {
    let circuit;

    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../../circuits/src/Credential.circom")
      );
    });

    function makeCredentialWitness(expiryTimestamp) {
      const credCommitment = poseidon.F.toObject(poseidon([BigInt(42), BigInt(99)]));
      const nonce = BigInt(7);
      const currentTimestamp = BigInt(1000);
      const leaf = poseidon.F.toObject(poseidon([credCommitment, expiryTimestamp]));
      const treePath = generateMerklePath(leaf, poseidon);

      return {
        credCommitment,
        expiryTimestamp,
        currentTimestamp,
        nonce,
        pathElements: treePath.pathElements,
        pathIndices: treePath.pathIndices,
        root: treePath.root,
      };
    }

    test("ACCEPT: expiryTimestamp = 0", async () => {
      const w = await circuit.calculateWitness(makeCredentialWitness(ZERO));
      await circuit.checkConstraints(w);
    });

    test("ACCEPT: expiryTimestamp = 2^64 - 1", async () => {
      const w = await circuit.calculateWitness(makeCredentialWitness(MAX_UINT64));
      await circuit.checkConstraints(w);
    });

    test("REJECT: expiryTimestamp = 2^64 (overflow)", async () => {
      await expect(async () => {
        const w = await circuit.calculateWitness(makeCredentialWitness(OVERFLOW_UINT64));
        await circuit.checkConstraints(w);
      }).rejects.toThrow();
    });
  });

  // ============================================================
  //  P6: Delegation — delegatorExpiry range [0, 2^64)
  //  P7: Delegation — delegateeExpiry range [0, 2^64)
  //  P8: Delegation — scope bitmask range [0, 2^64)
  // ============================================================
  describe("P6/P7/P8: Delegation expiry and scope ranges", () => {
    let circuit;

    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "../../circuits/src/Delegation.circom")
      );
    });

    function makeDelegationWitness(overrides = {}) {
      const defaults = {
        delegatorScope: BigInt(0xFF),
        delegateeScope: BigInt(0x0F),
        delegatorExpiry: BigInt(2000),
        delegateeExpiry: BigInt(1000),
        currentTimestamp: BigInt(500),
        delegatorCommitment: poseidon.F.toObject(poseidon([BigInt(1), BigInt(2)])),
        delegateeCommitment: poseidon.F.toObject(poseidon([BigInt(3), BigInt(4)])),
        nonce: BigInt(42),
      };
      const w = { ...defaults, ...overrides };

      const delegatorLeaf = poseidon.F.toObject(
        poseidon([w.delegatorCommitment, w.delegatorExpiry])
      );
      const delegateeLeaf = poseidon.F.toObject(
        poseidon([w.delegateeCommitment, w.delegateeExpiry])
      );
      const delegatorPath = generateMerklePath(delegatorLeaf, poseidon);
      const delegateePath = generateMerklePath(delegateeLeaf, poseidon);

      return {
        ...w,
        delegatorPathElements: delegatorPath.pathElements,
        delegatorPathIndices: delegatorPath.pathIndices,
        delegatorRoot: delegatorPath.root,
        delegateePathElements: delegateePath.pathElements,
        delegateePathIndices: delegateePath.pathIndices,
        delegateeRoot: delegateePath.root,
      };
    }

    // P6: delegatorExpiry
    test("P6 ACCEPT: delegatorExpiry = 2^64 - 1", async () => {
      const w = await circuit.calculateWitness(
        makeDelegationWitness({ delegatorExpiry: MAX_UINT64, delegateeExpiry: BigInt(1000) })
      );
      await circuit.checkConstraints(w);
    });

    test("P6 REJECT: delegatorExpiry = 2^64 (overflow)", async () => {
      await expect(async () => {
        const w = await circuit.calculateWitness(
          makeDelegationWitness({ delegatorExpiry: OVERFLOW_UINT64, delegateeExpiry: BigInt(1000) })
        );
        await circuit.checkConstraints(w);
      }).rejects.toThrow();
    });

    // P7: delegateeExpiry
    test("P7 ACCEPT: delegateeExpiry = 0", async () => {
      const w = await circuit.calculateWitness(
        makeDelegationWitness({ delegateeExpiry: ZERO })
      );
      await circuit.checkConstraints(w);
    });

    test("P7 REJECT: delegateeExpiry = 2^64 (overflow)", async () => {
      await expect(async () => {
        const w = await circuit.calculateWitness(
          makeDelegationWitness({
            delegateeExpiry: OVERFLOW_UINT64,
            delegatorExpiry: OVERFLOW_UINT64 + BigInt(1),
          })
        );
        await circuit.checkConstraints(w);
      }).rejects.toThrow();
    });

    // P8: scope bitmask range
    test("P8 ACCEPT: delegatorScope = 2^64 - 1, delegateeScope = 0", async () => {
      const w = await circuit.calculateWitness(
        makeDelegationWitness({ delegatorScope: MAX_UINT64, delegateeScope: ZERO })
      );
      await circuit.checkConstraints(w);
    });

    test("P8 REJECT: delegatorScope = 2^64 (overflow)", async () => {
      await expect(async () => {
        const w = await circuit.calculateWitness(
          makeDelegationWitness({ delegatorScope: OVERFLOW_UINT64 })
        );
        await circuit.checkConstraints(w);
      }).rejects.toThrow();
    });

    test("P8 REJECT: delegateeScope = 2^64 (overflow)", async () => {
      await expect(async () => {
        const w = await circuit.calculateWitness(
          makeDelegationWitness({ delegateeScope: OVERFLOW_UINT64 })
        );
        await circuit.checkConstraints(w);
      }).rejects.toThrow();
    });
  });
});
