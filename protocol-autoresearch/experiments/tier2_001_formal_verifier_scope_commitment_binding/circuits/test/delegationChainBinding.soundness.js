const path = require("path");
const { expect } = require("chai");
const { buildPoseidon } = require("circomlibjs");
const { wasm: wasmTester } = require("circom_tester");

/**
 * Exhaustive soundness test over the 8-bit permission space.
 *
 * For all 256 × 256 = 65 536 pairs of (delegatorScope, delegateeScope),
 * assert that witness generation succeeds IFF:
 *   (delegateeScope & delegatorScope) === delegateeScope  (subset predicate)
 *   AND delegateeScope satisfies cumulative-bit implications
 *   AND delegatorScope satisfies cumulative-bit implications
 */
describe("DelegationChainBinding — exhaustive soundness (2^8 × 2^8)", function () {
  this.timeout(600_000); // 10 min — 65K witness computations

  let circuit;
  let poseidon;
  let F;

  before(async () => {
    circuit = await wasmTester(
      path.join(__dirname, "..", "src", "DelegationChainBinding.circom"),
      { output: path.join(__dirname, "..", "build", "test_dcb_soundness") }
    );
    poseidon = await buildPoseidon();
    F = poseidon.F;
  });

  function hash(a, b) {
    return F.toObject(poseidon([a, b]));
  }

  /**
   * Check cumulative-bit implication rules:
   *   bit 4 → bit 3, bit 4 → bit 2, bit 3 → bit 2
   */
  function cumulativeValid(scope) {
    const bit2 = (scope >> 2) & 1;
    const bit3 = (scope >> 3) & 1;
    const bit4 = (scope >> 4) & 1;
    if (bit4 && !bit3) return false;
    if (bit4 && !bit2) return false;
    if (bit3 && !bit2) return false;
    return true;
  }

  /**
   * The full validity predicate.
   */
  function shouldSucceed(delegatorScope, delegateeScope) {
    const isSubset = (delegateeScope & delegatorScope) === delegateeScope;
    return isSubset && cumulativeValid(delegatorScope) && cumulativeValid(delegateeScope);
  }

  it("should match subset predicate for all 65 536 (delegator, delegatee) pairs", async () => {
    const credCommitment = 42n;
    const previousCredCommitment = 84n;

    let passCount = 0;
    let failCount = 0;
    const errors = [];

    for (let delegatorScope = 0; delegatorScope < 256; delegatorScope++) {
      for (let delegateeScope = 0; delegateeScope < 256; delegateeScope++) {
        const previousScopeCommitment = hash(delegatorScope, previousCredCommitment);
        const input = {
          previousScopeCommitment,
          delegatorScope,
          delegateeScope,
          credCommitment,
          previousCredCommitment,
        };

        const expectPass = shouldSucceed(delegatorScope, delegateeScope);
        let actualPass = false;

        try {
          const witness = await circuit.calculateWitness(input, true);
          await circuit.checkConstraints(witness);
          actualPass = true;
        } catch {
          actualPass = false;
        }

        if (actualPass !== expectPass) {
          errors.push(
            `delegator=0x${delegatorScope.toString(16).padStart(2, "0")} ` +
            `delegatee=0x${delegateeScope.toString(16).padStart(2, "0")} ` +
            `expected=${expectPass} actual=${actualPass}`
          );
        }

        if (actualPass) passCount++;
        else failCount++;
      }
    }

    console.log(
      `\n  Soundness: ${passCount} accepted, ${failCount} rejected, ${errors.length} mismatches`
    );

    if (errors.length > 0) {
      console.error("Mismatches (first 20):", errors.slice(0, 20));
    }
    expect(errors).to.have.length(0, "Soundness mismatches detected");
  });
});
