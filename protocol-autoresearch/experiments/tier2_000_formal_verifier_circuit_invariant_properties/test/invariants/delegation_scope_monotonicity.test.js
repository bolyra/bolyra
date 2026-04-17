/**
 * delegation_scope_monotonicity.test.js
 *
 * Assertion harness verifying that for all valid Delegation circuit witnesses:
 *   delegateeScope AND NOT delegatorScope == 0
 *
 * Properties tested: P12, P13, P14
 */

const path = require("path");
const { wasm: wasm_tester } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");

const MAX_UINT64 = BigInt(2) ** BigInt(64) - BigInt(1);

function generateMerklePath(leaf, poseidon, depth = 20) {
  const pathElements = [];
  const pathIndices = [];
  let current = leaf;
  for (let i = 0; i < depth; i++) {
    const sibling = poseidon.F.toObject(poseidon([BigInt(i + 3000), BigInt(i)]));
    pathElements.push(sibling);
    pathIndices.push(0);
    current = poseidon.F.toObject(poseidon([current, sibling]));
  }
  return { pathElements, pathIndices, root: current };
}

describe("Delegation Scope Monotonicity Invariants", () => {
  let circuit;
  let poseidon;

  beforeAll(async () => {
    poseidon = await buildPoseidon();
    circuit = await wasm_tester(
      path.join(__dirname, "../../circuits/src/Delegation.circom")
    );
  });

  function makeDelegationWitness(delegatorScope, delegateeScope) {
    const delegatorExpiry = BigInt(2000);
    const delegateeExpiry = BigInt(1000);
    const currentTimestamp = BigInt(500);
    const delegatorCommitment = poseidon.F.toObject(poseidon([BigInt(10), BigInt(20)]));
    const delegateeCommitment = poseidon.F.toObject(poseidon([BigInt(30), BigInt(40)]));
    const nonce = BigInt(99);

    const delegatorLeaf = poseidon.F.toObject(
      poseidon([delegatorCommitment, delegatorExpiry])
    );
    const delegateeLeaf = poseidon.F.toObject(
      poseidon([delegateeCommitment, delegateeExpiry])
    );
    const delegatorPath = generateMerklePath(delegatorLeaf, poseidon);
    const delegateePath = generateMerklePath(delegateeLeaf, poseidon);

    return {
      delegatorScope,
      delegateeScope,
      delegatorExpiry,
      delegateeExpiry,
      currentTimestamp,
      delegatorCommitment,
      delegateeCommitment,
      nonce,
      delegatorPathElements: delegatorPath.pathElements,
      delegatorPathIndices: delegatorPath.pathIndices,
      delegatorRoot: delegatorPath.root,
      delegateePathElements: delegateePath.pathElements,
      delegateePathIndices: delegateePath.pathIndices,
      delegateeRoot: delegateePath.root,
    };
  }

  // Helper to verify the invariant holds at the JS level
  function assertMonotonicity(delegatorScope, delegateeScope) {
    return (delegateeScope & ~delegatorScope) === BigInt(0);
  }

  // ============================================================
  //  P12: Core monotonicity — delegateeScope ⊆ delegatorScope
  // ============================================================
  describe("P12: Scope subset enforcement", () => {
    // Valid cases: delegateeScope is a subset of delegatorScope
    const validCases = [
      { name: "full scope → full scope",    delegator: MAX_UINT64,   delegatee: MAX_UINT64 },
      { name: "full scope → half scope",    delegator: MAX_UINT64,   delegatee: BigInt(0xFFFFFFFF) },
      { name: "0xFF → 0x0F",                delegator: BigInt(0xFF), delegatee: BigInt(0x0F) },
      { name: "0xFF → 0x00",                delegator: BigInt(0xFF), delegatee: BigInt(0) },
      { name: "single bit → same bit",      delegator: BigInt(1),    delegatee: BigInt(1) },
      { name: "alternating → subset",       delegator: BigInt(0xAA), delegatee: BigInt(0x22) },
    ];

    for (const { name, delegator, delegatee } of validCases) {
      test(`ACCEPT: ${name}`, async () => {
        expect(assertMonotonicity(delegator, delegatee)).toBe(true);
        const witness = makeDelegationWitness(delegator, delegatee);
        const w = await circuit.calculateWitness(witness);
        await circuit.checkConstraints(w);
      });
    }

    // Invalid cases: delegateeScope has bits not in delegatorScope
    const invalidCases = [
      { name: "0x00 → 0x01 (extra bit)",         delegator: BigInt(0),    delegatee: BigInt(1) },
      { name: "0x0F → 0xF0 (disjoint)",           delegator: BigInt(0x0F), delegatee: BigInt(0xF0) },
      { name: "0xAA → 0x55 (complement)",         delegator: BigInt(0xAA), delegatee: BigInt(0x55) },
      { name: "single bit → different bit",        delegator: BigInt(1),    delegatee: BigInt(2) },
      { name: "half scope → full scope (superset)", delegator: BigInt(0xFFFFFFFF), delegatee: MAX_UINT64 },
    ];

    for (const { name, delegator, delegatee } of invalidCases) {
      test(`REJECT: ${name}`, async () => {
        expect(assertMonotonicity(delegator, delegatee)).toBe(false);
        await expect(async () => {
          const witness = makeDelegationWitness(delegator, delegatee);
          const w = await circuit.calculateWitness(witness);
          await circuit.checkConstraints(w);
        }).rejects.toThrow();
      });
    }
  });

  // ============================================================
  //  P13: Empty delegatee scope is always valid
  // ============================================================
  describe("P13: Empty delegatee scope", () => {
    const delegatorScopes = [BigInt(0), BigInt(1), BigInt(0xFF), MAX_UINT64];

    for (const delegator of delegatorScopes) {
      test(`ACCEPT: delegatee=0 with delegator=${delegator}`, async () => {
        const witness = makeDelegationWitness(delegator, BigInt(0));
        const w = await circuit.calculateWitness(witness);
        await circuit.checkConstraints(w);
      });
    }
  });

  // ============================================================
  //  P14: Identical scopes are valid
  // ============================================================
  describe("P14: Identical scopes", () => {
    const scopes = [BigInt(0), BigInt(1), BigInt(0xFF), BigInt(0xDEAD), MAX_UINT64];

    for (const scope of scopes) {
      test(`ACCEPT: delegator=delegatee=${scope}`, async () => {
        const witness = makeDelegationWitness(scope, scope);
        const w = await circuit.calculateWitness(witness);
        await circuit.checkConstraints(w);
      });
    }
  });
});
