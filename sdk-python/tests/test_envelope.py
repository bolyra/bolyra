"""Tests for the proof envelope Python codec (envelope.py).

Mirrors the TypeScript envelope.test.ts suite for cross-SDK consistency.
"""
from __future__ import annotations

import json
import pathlib
import pytest

from bolyra.envelope import (
    CONTENT_TYPE,
    ENVELOPE_VERSION,
    BN254_FIELD_ORDER,
    ProofEnvelope,
    CircuitIdentity,
    ProofData,
    validate_envelope,
    envelope_from_proof,
)

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

FIXTURES_DIR = pathlib.Path(__file__).parent.parent.parent / "sdk" / "test" / "fixtures"

VALID_PROOF = {
    "pi_a": ["12345678901234567890", "98765432109876543210"],
    "pi_b": [
        ["11111111111111111111", "22222222222222222222"],
        ["33333333333333333333", "44444444444444444444"],
    ],
    "pi_c": ["55555555555555555555", "66666666666666666666"],
}

VALID_SIGNALS = [
    "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    "98765432109876543210",
    "42",
]

VALID_CIRCUIT = {"name": "HumanUniqueness", "version": "0.4.0"}

VALID_ENVELOPE_DICT = {
    "version": "1.0.0",
    "circuit": VALID_CIRCUIT,
    "proofType": "groth16",
    "publicSignals": VALID_SIGNALS,
    "proof": VALID_PROOF,
}


def make_envelope(**overrides) -> dict:
    d = dict(VALID_ENVELOPE_DICT)
    d.update(overrides)
    return d


# ---------------------------------------------------------------------------
# 1. Round-trip: to_json then from_json
# ---------------------------------------------------------------------------

def test_round_trip():
    env = validate_envelope(make_envelope())
    json_str = env.to_json()
    env2 = ProofEnvelope.from_json(json_str)

    assert env2.version == env.version
    assert env2.circuit.name == env.circuit.name
    assert env2.circuit.version == env.circuit.version
    assert env2.proof_type == env.proof_type
    assert env2.public_signals == env.public_signals
    assert env2.proof.pi_a == env.proof.pi_a
    assert env2.proof.pi_b == env.proof.pi_b
    assert env2.proof.pi_c == env.proof.pi_c


# ---------------------------------------------------------------------------
# 2. Version rejection: major mismatch raises ValueError
# ---------------------------------------------------------------------------

def test_version_rejection():
    d = make_envelope(version="2.0.0")
    with pytest.raises(ValueError, match="Major version mismatch"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 3. Version acceptance: minor bump is fine
# ---------------------------------------------------------------------------

def test_version_acceptance_minor():
    d = make_envelope(version="1.1.0")
    env = validate_envelope(d)
    assert env.version == "1.1.0"


# ---------------------------------------------------------------------------
# 4. Missing proof raises ValueError
# ---------------------------------------------------------------------------

def test_missing_proof():
    d = {
        "version": "1.0.0",
        "circuit": VALID_CIRCUIT,
        "proofType": "groth16",
        "publicSignals": VALID_SIGNALS,
        # no "proof" key
    }
    with pytest.raises(ValueError, match="Missing proof"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 5. Malformed coordinates: "abc" raises ValueError
# ---------------------------------------------------------------------------

def test_malformed_coordinates():
    bad_proof = dict(VALID_PROOF, pi_a=["abc", "98765432109876543210"])
    d = make_envelope(proof=bad_proof)
    with pytest.raises(ValueError, match="decimal string"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 6. Field element >= BN254 modulus raises ValueError
# ---------------------------------------------------------------------------

def test_field_element_at_modulus():
    modulus_str = str(BN254_FIELD_ORDER)
    d = make_envelope(publicSignals=[modulus_str, "42"])
    with pytest.raises(ValueError, match="BN254 field modulus"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 7. Leading zero rejection: "0042" raises ValueError
# ---------------------------------------------------------------------------

def test_leading_zero_rejection():
    d = make_envelope(publicSignals=["0042", "42"])
    with pytest.raises(ValueError, match="leading zeros"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 8. String length DoS: 100-char digit string raises ValueError
# ---------------------------------------------------------------------------

def test_string_length_dos():
    long_str = "1" * 100
    d = make_envelope(publicSignals=[long_str, "42"])
    with pytest.raises(ValueError, match="string too long"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 9. Forward compat: unknown key preserved via extra dict
# ---------------------------------------------------------------------------

def test_forward_compat_extra():
    d = make_envelope()
    d["unknownField"] = "preserved"
    env = validate_envelope(d)
    assert env.extra.get("unknownField") == "preserved"


# ---------------------------------------------------------------------------
# 10. Golden fixture: envelope_v1.json
# ---------------------------------------------------------------------------

def test_golden_fixture():
    fixture_path = FIXTURES_DIR / "envelope_v1.json"
    raw = fixture_path.read_text()
    env = ProofEnvelope.from_json(raw)

    assert env.version == "1.0.0"
    assert env.circuit.name == "HumanUniqueness"
    assert env.circuit.version == "0.4.0"
    assert env.circuit.vkey_hash == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert env.proof_type == "groth16"
    assert env.public_signals[2] == "42"
    assert env.proof.pi_a == ["12345678901234567890", "98765432109876543210"]
    assert env.proof.pi_b == [
        ["11111111111111111111", "22222222222222222222"],
        ["33333333333333333333", "44444444444444444444"],
    ]
    assert env.proof.pi_c == ["55555555555555555555", "66666666666666666666"]
    assert env.metadata.get("prover") == "@bolyra/sdk@0.4.0"


# ---------------------------------------------------------------------------
# 11. Boundary fixture: envelope_v1_boundary.json parses successfully
# ---------------------------------------------------------------------------

def test_boundary_fixture():
    fixture_path = FIXTURES_DIR / "envelope_v1_boundary.json"
    raw = fixture_path.read_text()
    env = ProofEnvelope.from_json(raw)
    # "0" and modulus-1 are both valid
    assert "0" in env.public_signals
    modulus_minus_1 = str(BN254_FIELD_ORDER - 1)
    assert modulus_minus_1 in env.public_signals


# ---------------------------------------------------------------------------
# 12. Forward compat fixture: futureField in extra
# ---------------------------------------------------------------------------

def test_forward_compat_fixture():
    fixture_path = FIXTURES_DIR / "envelope_v1_forward_compat.json"
    raw = fixture_path.read_text()
    env = ProofEnvelope.from_json(raw)
    assert "futureField" in env.extra
    assert env.extra["futureField"] == "this-should-be-preserved"


# ---------------------------------------------------------------------------
# 13. Invalid leading zero fixture raises ValueError
# ---------------------------------------------------------------------------

def test_invalid_leading_zero_fixture():
    fixture_path = FIXTURES_DIR / "envelope_v1_invalid_leading_zero.json"
    raw = fixture_path.read_text()
    with pytest.raises(ValueError, match="leading zeros"):
        ProofEnvelope.from_json(raw)


# ---------------------------------------------------------------------------
# 14. Invalid modulus fixture raises ValueError
# ---------------------------------------------------------------------------

def test_invalid_modulus_fixture():
    fixture_path = FIXTURES_DIR / "envelope_v1_invalid_modulus.json"
    raw = fixture_path.read_text()
    with pytest.raises(ValueError, match="BN254 field modulus"):
        ProofEnvelope.from_json(raw)


# ---------------------------------------------------------------------------
# 15. Invalid pi_b fixture raises ValueError
# ---------------------------------------------------------------------------

def test_invalid_pi_b_fixture():
    fixture_path = FIXTURES_DIR / "envelope_v1_invalid_pi_b.json"
    raw = fixture_path.read_text()
    with pytest.raises(ValueError, match=r"pi_b"):
        ProofEnvelope.from_json(raw)


# ---------------------------------------------------------------------------
# 16. envelope_from_proof produces a valid envelope
# ---------------------------------------------------------------------------

def test_envelope_from_proof():
    raw_proof = {
        "pi_a": ["12345678901234567890", "98765432109876543210"],
        "pi_b": [
            ["11111111111111111111", "22222222222222222222"],
            ["33333333333333333333", "44444444444444444444"],
        ],
        "pi_c": ["55555555555555555555", "66666666666666666666"],
    }
    signals = ["42", "98765432109876543210"]
    env = envelope_from_proof("HumanUniqueness", raw_proof, signals)

    assert env.version == ENVELOPE_VERSION
    assert env.circuit.name == "HumanUniqueness"
    assert env.proof_type == "groth16"
    assert env.public_signals == signals
    assert env.proof.pi_a == ["12345678901234567890", "98765432109876543210"]
    assert env.metadata.get("prover") == "bolyra@0.5.0"

    # Must also be re-parseable (validate round-trip)
    env2 = ProofEnvelope.from_json(env.to_json())
    assert env2.circuit.name == "HumanUniqueness"


# ---------------------------------------------------------------------------
# 17. Empty publicSignals raises ValueError
# ---------------------------------------------------------------------------

def test_empty_public_signals():
    d = make_envelope(publicSignals=[])
    with pytest.raises(ValueError, match="non-empty"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 18. Invalid circuit name raises ValueError
# ---------------------------------------------------------------------------

def test_invalid_circuit_name():
    d = make_envelope(circuit={"name": "UnknownCircuit", "version": "0.4.0"})
    with pytest.raises(ValueError, match="Invalid circuit.name"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 19. Invalid proofType raises ValueError
# ---------------------------------------------------------------------------

def test_invalid_proof_type():
    d = make_envelope(proofType="plonk")
    with pytest.raises(ValueError, match="Invalid proofType"):
        validate_envelope(d)


# ---------------------------------------------------------------------------
# 20. pi_b wrong row length raises ValueError
# ---------------------------------------------------------------------------

def test_pi_b_wrong_row_length():
    bad_proof = dict(VALID_PROOF)
    bad_proof["pi_b"] = [["1"], ["2", "3", "4"]]
    d = make_envelope(proof=bad_proof)
    with pytest.raises(ValueError, match=r"pi_b"):
        validate_envelope(d)
