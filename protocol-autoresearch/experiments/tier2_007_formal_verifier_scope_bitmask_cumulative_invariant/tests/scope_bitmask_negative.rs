//! Negative and positive test vectors for ScopeBitmaskChip cumulative invariant.
//!
//! 12 negative vectors: each sets a higher scope bit without the required lower bits.
//! 4 positive control vectors: valid cumulative encodings.
//!
//! Uses halo2_proofs MockProver to assert constraint satisfaction / failure.

use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    pasta::Fp,
};

// Import the circuit from lib crate
use bolyra_scope_bitmask::ScopeBitmaskCircuit;

/// Helper: build a circuit from u64 bit values and run MockProver.
/// Returns Ok(()) if the prover accepts the witness, Err(Vec<VerifyFailure>) otherwise.
fn run_scope_circuit(bit2: u64, bit3: u64, bit4: u64) -> Result<(), Vec<String>> {
    let circuit = ScopeBitmaskCircuit::<Fp> {
        bit2: Value::known(Fp::from(bit2)),
        bit3: Value::known(Fp::from(bit3)),
        bit4: Value::known(Fp::from(bit4)),
    };

    let k = 4; // 2^4 = 16 rows, more than enough
    let prover = MockProver::run(k, &circuit, vec![]).expect("MockProver::run failed");
    prover.verify().map_err(|failures| {
        failures
            .into_iter()
            .map(|f| format!("{:?}", f))
            .collect()
    })
}

/// Assert that the given bit combination FAILS verification with at least one
/// constraint error mentioning the expected gate name substring.
fn assert_negative(bit2: u64, bit3: u64, bit4: u64, expected_gate_fragment: &str) {
    let result = run_scope_circuit(bit2, bit3, bit4);
    match result {
        Ok(()) => panic!(
            "Expected verification failure for (bit2={}, bit3={}, bit4={}) but prover accepted",
            bit2, bit3, bit4
        ),
        Err(failures) => {
            let has_expected = failures
                .iter()
                .any(|f| f.contains(expected_gate_fragment));
            assert!(
                has_expected,
                "Expected gate '{}' in failures for (bit2={}, bit3={}, bit4={}), got: {:?}",
                expected_gate_fragment, bit2, bit3, bit4, failures
            );
        }
    }
}

/// Assert that the given bit combination PASSES verification.
fn assert_positive(bit2: u64, bit3: u64, bit4: u64) {
    let result = run_scope_circuit(bit2, bit3, bit4);
    assert!(
        result.is_ok(),
        "Expected verification success for (bit2={}, bit3={}, bit4={}) but got failures: {:?}",
        bit2,
        bit3,
        bit4,
        result.err()
    );
}

// =========================================================================
// Negative vectors: bit4=1 without required lower bits
// =========================================================================

#[test]
fn neg_bit4_set_bit3_clear_bit2_clear() {
    // bit4=1, bit3=0, bit2=0 — violates bit4=>bit3
    assert_negative(0, 0, 1, "cumulative_bit4_implies_bit3");
}

#[test]
fn neg_bit4_set_bit3_clear_bit2_set() {
    // bit4=1, bit3=0, bit2=1 — violates bit4=>bit3
    assert_negative(1, 0, 1, "cumulative_bit4_implies_bit3");
}

#[test]
fn neg_bit4_set_bit3_set_bit2_clear() {
    // bit4=1, bit3=1, bit2=0 — violates bit3=>bit2
    assert_negative(0, 1, 1, "cumulative_bit3_implies_bit2");
}

// =========================================================================
// Negative vectors: bit3=1 without bit2
// =========================================================================

#[test]
fn neg_bit3_set_bit2_clear_bit4_clear() {
    // bit3=1, bit2=0, bit4=0 — violates bit3=>bit2
    assert_negative(0, 1, 0, "cumulative_bit3_implies_bit2");
}

// =========================================================================
// Negative vectors: non-boolean values (2, 3) — violate boolean gates
// =========================================================================

#[test]
fn neg_bit2_non_boolean_2() {
    assert_negative(2, 0, 0, "bool_bit2");
}

#[test]
fn neg_bit3_non_boolean_2() {
    assert_negative(0, 2, 0, "bool_bit3");
}

#[test]
fn neg_bit4_non_boolean_2() {
    assert_negative(0, 0, 2, "bool_bit4");
}

#[test]
fn neg_bit2_non_boolean_3() {
    assert_negative(3, 0, 0, "bool_bit2");
}

#[test]
fn neg_bit3_non_boolean_3() {
    assert_negative(0, 3, 0, "bool_bit3");
}

#[test]
fn neg_bit4_non_boolean_3() {
    assert_negative(0, 0, 3, "bool_bit4");
}

// =========================================================================
// Negative vectors: all upper bits set, lower cleared
// =========================================================================

#[test]
fn neg_all_upper_no_base() {
    // bit4=1, bit3=1, bit2=0 — bit3=>bit2 fails
    assert_negative(0, 1, 1, "cumulative_bit3_implies_bit2");
}

#[test]
fn neg_financial_unlimited_skip_mid() {
    // Simulates escalation: bit4=1, bit3=0, bit2=0
    // This is the critical "financial unlimited without intermediate tiers" vector
    assert_negative(0, 0, 1, "cumulative_bit4_implies_bit3");
}

// =========================================================================
// Positive control vectors
// =========================================================================

#[test]
fn pos_all_zeros() {
    assert_positive(0, 0, 0);
}

#[test]
fn pos_bit2_only() {
    assert_positive(1, 0, 0);
}

#[test]
fn pos_bit2_and_bit3() {
    assert_positive(1, 1, 0);
}

#[test]
fn pos_all_bits_set() {
    assert_positive(1, 1, 1);
}
