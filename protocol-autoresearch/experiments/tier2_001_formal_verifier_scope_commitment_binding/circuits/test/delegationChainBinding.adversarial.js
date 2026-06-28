const chai = require("chai");
const { expect } = chai;
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const { wasm: wasmTester } = require("circom_tester");

describe("DelegationChainBinding — adversarial harness", function () {
  this.timeout(120_000);

  let circuit;
  let poseidon;
  let F; // finite field

  before(async () => {
    circuit = await wasmTester(
      path.join(__dirname, "..", "src", "DelegationChainBinding.circom"),
      { output: path.join(__dirname, "..", "build", "test_dcb") }
    );
    poseidon = await buildPoseidon();
    F = poseidon.F;
  });

  /**
   * Helper: compute Poseidon(a, b) and return BigInt.
   */
  function hash(a, b) {
    return F.toObject(poseidon([a, b]));
  }

  /**
   * Build a valid witness input object.
   * delegatorScope=0xFF (all permissions), delegateeScope=0x07 (bits 0-2).
   */
  function validInput() {
    const delegatorScope = 0xff;
    const delegateeScope = 0x07; // READ | WRITE | FINANCIAL_SMALL
    const credCommitment = 12345n;
    const previousCredCommitment = 67890n;
    const previousScopeCommitment = hash(delegatorScope, previousCredCommitment);
    return {
      previousScopeCommitment,
      delegatorScope,
      delegateeScope,
      credCommitment,
      previousCredCommitment,
    };
  }

  // -----------------------------------------------------------------
  // Sanity: valid input should pass
  // -----------------------------------------------------------------
  it("should accept a valid delegation with subset scope", async () => {
    const input = validInput();
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // Verify currentScopeCommitment output matches expected
    const expectedCurrent = hash(input.delegateeScope, input.credCommitment);
    // Output signal index 0 is 1 (circom convention), index 1 is currentScopeCommitment
    expect(witness[1].toString()).to.equal(expectedCurrent.toString());
  });

  // -----------------------------------------------------------------
  // Case 1: Scope-expansion attack
  //   delegatee sets one extra bit beyond delegator's scope
  // -----------------------------------------------------------------
  it("should REJECT scope-expansion: delegatee bits exceed delegator bits", async () => {
    const input = validInput();
    // delegator has bits 0-2 (0x07), delegatee tries to add bit 5 (0x27)
    input.delegatorScope = 0x07;
    input.delegateeScope = input.delegatorScope | 0x20; // add SIGN_ON_BEHALF
    input.previousScopeCommitment = hash(
      input.delegatorScope,
      input.previousCredCommitment
    );

    try {
      await circuit.calculateWitness(input, true);
      expect.fail("Should have thrown — delegatee exceeds delegator scope");
    } catch (err) {
      expect(err.message).to.match(/Assert|Error|constraint/i);
    }
  });

  // -----------------------------------------------------------------
  // Case 2: Commitment-mismatch attack
  //   previousScopeCommitment is a random field element, not the
  //   actual Poseidon(delegatorScope, previousCredCommitment)
  // -----------------------------------------------------------------
  it("should REJECT commitment mismatch: tampered previousScopeCommitment", async () => {
    const input = validInput();
    // Replace with an arbitrary value
    input.previousScopeCommitment = 999999999999n;

    try {
      await circuit.calculateWitness(input, true);
      expect.fail(
        "Should have thrown — previousScopeCommitment doesn't match recomputation"
      );
    } catch (err) {
      expect(err.message).to.match(/Assert|Error|constraint/i);
    }
  });

  // -----------------------------------------------------------------
  // Case 3: Poseidon pre-image substitution attack
  //   Use a DIFFERENT delegatorScope that still satisfies the AND-mask
  //   for a particular delegateeScope but does NOT match the commitment.
  //   Specifically: delegator claims scope 0xFF but the commitment was
  //   built with scope 0x07. The AND-mask check passes (0x07 & 0xFF = 0x07)
  //   but the commitment recomputation fails.
  // -----------------------------------------------------------------
  it("should REJECT pre-image substitution: scope signal swap breaks commitment", async () => {
    const delegateeScope = 0x07;
    const credCommitment = 12345n;
    const previousCredCommitment = 67890n;

    // Build commitment with true delegator scope = 0x07
    const trueDelegatorScope = 0x07;
    const previousScopeCommitment = hash(
      trueDelegatorScope,
      previousCredCommitment
    );

    // Attacker claims delegator scope = 0xFF (superset, so AND-mask passes)
    // but the commitment was built with 0x07
    const input = {
      previousScopeCommitment,
      delegatorScope: 0xff, // LIED — doesn't match commitment
      delegateeScope,
      credCommitment,
      previousCredCommitment,
    };

    try {
      await circuit.calculateWitness(input, true);
      expect.fail(
        "Should have thrown — delegatorScope doesn't match commitment pre-image"
      );
    } catch (err) {
      expect(err.message).to.match(/Assert|Error|constraint/i);
    }
  });

  // -----------------------------------------------------------------
  // Case 4: Cumulative-bit implication violation
  //   delegatee sets bit 4 (FINANCIAL_UNLIMITED) without bit 3
  // -----------------------------------------------------------------
  it("should REJECT cumulative-bit violation: bit 4 without bit 3", async () => {
    const input = validInput();
    // Set delegatee to have bit 4 + bit 2 but NOT bit 3 → violates implication
    input.delegateeScope = 0x14; // bits 2 and 4 only
    input.previousScopeCommitment = hash(
      input.delegatorScope,
      input.previousCredCommitment
    );

    try {
      await circuit.calculateWitness(input, true);
      expect.fail(
        "Should have thrown — bit 4 set without bit 3 violates implication"
      );
    } catch (err) {
      expect(err.message).to.match(/Assert|Error|constraint/i);
    }
  });
});
