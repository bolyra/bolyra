#!/usr/bin/env python3
"""Property tests for AgentPolicy credential commitment binding uniqueness.

Validates that the InFieldBN254 range checks enforce BN254 scalar field
membership for modelHash, opPkAx, and opPkAy, and that the Poseidon5
credential commitment is injective over valid inputs.

These tests are structural / specification-level. The Mocha tests in
circuits/test/AgentPolicy.field-binding.test.js run the actual circom
witness generation and full proof round-trips.
"""
import json
import hashlib
import os

# BN254 scalar field modulus
BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def test_bn254_modulus_is_254_bits():
    """Verify that r fits in exactly 254 bits (so Num2Bits(254) is sufficient)."""
    assert BN254_R.bit_length() == 254, (
        f"Expected 254-bit modulus, got {BN254_R.bit_length()}"
    )
    assert BN254_R < (1 << 254), "r must be < 2^254"
    assert BN254_R > (1 << 253), "r must be > 2^253 (i.e., exactly 254 bits)"


def test_field_wrap_produces_distinct_external_value():
    """Two externally distinct values v and v + r map to the same field element.

    This is the attack the InFieldBN254 check prevents: without range-checking,
    a prover could substitute v' = v + r for v, which is the same element in F_r
    but a different 256-bit integer.
    """
    v = 42
    v_wrap = v + BN254_R
    # They are different integers
    assert v != v_wrap
    # But identical mod r
    assert v % BN254_R == v_wrap % BN254_R
    # v_wrap does NOT fit in 254 bits — InFieldBN254 would reject it
    assert v_wrap.bit_length() > 254


def test_diff_check_soundness():
    """Verify the (r - 1 - in) subtraction trick is sound for boundary values."""
    r_minus_1 = BN254_R - 1

    # in = 0: diff = r - 1, which is 254-bit
    diff_zero = r_minus_1 - 0
    assert diff_zero == r_minus_1
    assert diff_zero.bit_length() <= 254

    # in = r - 1: diff = 0, which is fine
    diff_max = r_minus_1 - r_minus_1
    assert diff_max == 0

    # in = r: diff = -1, which in unsigned representation is huge
    # (In F_r, this wraps to r - 1, but Num2Bits would see the
    #  pre-reduction value which is > 2^254)
    # We just verify the math here; the circuit enforces it.
    diff_overflow = r_minus_1 - BN254_R  # -1
    assert diff_overflow < 0, "Overflow produces negative diff"


def test_commitment_uniqueness_spec():
    """Specification-level check: 5-tuples should produce distinct SHA-256 hashes.

    This is a proxy for Poseidon collision resistance. We can't run Poseidon
    in pure Python without dependencies, so we use SHA-256 as a stand-in
    to verify the test harness logic.
    """
    seen = set()
    collisions = 0
    for i in range(1000):
        # Generate pseudo-random 5-tuples
        seed = i.to_bytes(4, 'big')
        h = hashlib.sha256(seed).digest()
        model_hash = int.from_bytes(h[:8], 'big') % BN254_R
        op_pk_ax = int.from_bytes(h[8:16], 'big') % BN254_R
        op_pk_ay = int.from_bytes(h[16:24], 'big') % BN254_R
        bitmask = h[24] & 0xFF
        expiry = int.from_bytes(h[25:29], 'big')

        # Hash the tuple (stand-in for Poseidon5)
        commitment = hashlib.sha256(
            f"{model_hash},{op_pk_ax},{op_pk_ay},{bitmask},{expiry}".encode()
        ).hexdigest()

        if commitment in seen:
            collisions += 1
        seen.add(commitment)

    assert collisions == 0, f"Found {collisions} hash collisions in 1000 samples"
    assert len(seen) == 1000


def test_cumulative_bit_implication_rules():
    """Verify the cumulative bit encoding rules at the spec level."""
    def is_valid_bitmask(b):
        bit2 = (b >> 2) & 1  # FINANCIAL_SMALL
        bit3 = (b >> 3) & 1  # FINANCIAL_MEDIUM
        bit4 = (b >> 4) & 1  # FINANCIAL_UNLIMITED
        # bit4 => bit3, bit3 => bit2
        if bit4 and not bit3:
            return False
        if bit3 and not bit2:
            return False
        return True

    valid_count = sum(1 for b in range(256) if is_valid_bitmask(b))
    # 3 financial bits with implication: 5 valid combos (00x, 01x pattern)
    # 00, 01 (invalid), 10 (invalid), 11 -> for 3 bits:
    # 000, 001(inv), 010(inv), 011(inv), 100, 101(inv), 110, 111 -> 4 valid
    # Actually: bit2=0,bit3=0,bit4=0; bit2=1,bit3=0,bit4=0;
    # bit2=1,bit3=1,bit4=0; bit2=1,bit3=1,bit4=1 => 4 valid combos for bits 2-4
    # Other 5 bits (0,1,5,6,7) are free: 2^5 = 32
    # Total valid: 4 * 32 = 128
    assert valid_count == 128, f"Expected 128 valid bitmasks, got {valid_count}"


def test_outline_artifacts_present():
    """Verify that all required experiment artifacts exist."""
    experiment_dir = os.path.dirname(os.path.abspath(__file__))
    required_files = [
        "circuit.circom",
        "lib/FieldCheck.circom",
        "test_field_binding.js",
        "formal_properties_addendum.md",
        "README.md",
    ]
    for f in required_files:
        path = os.path.join(experiment_dir, f)
        assert os.path.exists(path), f"Missing artifact: {f}"


def test_field_check_circom_has_modulus():
    """Verify FieldCheck.circom contains the correct BN254 modulus constant."""
    experiment_dir = os.path.dirname(os.path.abspath(__file__))
    fc_path = os.path.join(experiment_dir, "lib", "FieldCheck.circom")
    if not os.path.exists(fc_path):
        return  # Skip if file doesn't exist yet
    content = open(fc_path).read()
    r_minus_1 = str(BN254_R - 1)
    assert r_minus_1 in content, (
        f"FieldCheck.circom must contain r-1 = {r_minus_1}"
    )
