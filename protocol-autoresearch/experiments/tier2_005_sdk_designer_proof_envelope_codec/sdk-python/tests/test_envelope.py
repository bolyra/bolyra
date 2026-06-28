"""Tests for bolyra.envelope — round-trip, from_raw, JSON, error cases."""

import json
import pytest

from bolyra.envelope import (
    BolyraEnvelope,
    EnvelopeError,
    ENVELOPE_VERSION,
    decode,
    encode,
    from_raw,
)
from bolyra.signals import SIGNAL_MAPS

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_PROOF = {
    "pi_a": ["1", "2", "1"],
    "pi_b": [["3", "4"], ["5", "6"], ["1", "0"]],
    "pi_c": ["7", "8", "1"],
    "protocol": "groth16",
    "curve": "bn128",
}


def mock_signals(circuit: str) -> list[str]:
    return [str(1000 + i) for i in range(len(SIGNAL_MAPS[circuit]))]


# ---------------------------------------------------------------------------
# Round-trip: encode → decode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("circuit", ["HumanUniqueness", "AgentPolicy", "Delegation"])
def test_round_trip(circuit: str) -> None:
    signals = mock_signals(circuit)
    envelope = encode(circuit, "groth16", MOCK_PROOF, signals)

    assert envelope.version == ENVELOPE_VERSION
    assert envelope.circuit == circuit
    assert envelope.proving_system == "groth16"

    result = decode(envelope)
    assert result["publicSignals"] == signals
    assert result["proof"] == MOCK_PROOF


def test_round_trip_plonk() -> None:
    signals = mock_signals("AgentPolicy")
    plonk_proof = {**MOCK_PROOF, "protocol": "plonk"}
    envelope = encode("AgentPolicy", "plonk", plonk_proof, signals)
    assert envelope.proving_system == "plonk"
    result = decode(envelope)
    assert result["publicSignals"] == signals


# ---------------------------------------------------------------------------
# from_raw: correct named fields
# ---------------------------------------------------------------------------


def test_from_raw_human() -> None:
    signals = ["111", "222", "333", "444", "555"]
    env = from_raw("HumanUniqueness", "groth16", MOCK_PROOF, signals)
    assert env.signals["nullifierHash"] == "111"
    assert env.signals["nonceBinding"] == "222"
    assert env.signals["humanMerkleRoot"] == "333"
    assert env.signals["externalNullifier"] == "444"
    assert env.signals["sessionNonce"] == "555"


def test_from_raw_agent() -> None:
    signals = ["10", "20", "30", "40", "50", "60"]
    env = from_raw("AgentPolicy", "groth16", MOCK_PROOF, signals)
    assert env.signals["credentialHash"] == "10"
    assert env.signals["nonceBinding"] == "20"
    assert env.signals["agentMerkleRoot"] == "30"
    assert env.signals["currentTimestamp"] == "40"
    assert env.signals["requiredPermissions"] == "50"
    assert env.signals["sessionNonce"] == "60"


def test_from_raw_delegation() -> None:
    signals = ["100", "200", "300", "400", "500", "600"]
    env = from_raw("Delegation", "groth16", MOCK_PROOF, signals)
    assert env.signals["delegationHash"] == "100"
    assert env.signals["narrowedPermissions"] == "200"
    assert env.signals["nonceBinding"] == "300"
    assert env.signals["delegationMerkleRoot"] == "400"
    assert env.signals["currentTimestamp"] == "500"
    assert env.signals["sessionNonce"] == "600"


# ---------------------------------------------------------------------------
# JSON serialisation round-trip
# ---------------------------------------------------------------------------


def test_json_round_trip() -> None:
    signals = mock_signals("Delegation")
    envelope = encode("Delegation", "groth16", MOCK_PROOF, signals)
    json_str = envelope.to_json()
    restored = BolyraEnvelope.from_json(json_str)
    assert restored == envelope
    result = decode(restored)
    assert result["publicSignals"] == signals


def test_to_dict_round_trip() -> None:
    signals = mock_signals("HumanUniqueness")
    envelope = encode("HumanUniqueness", "groth16", MOCK_PROOF, signals)
    d = envelope.to_dict()
    restored = BolyraEnvelope.from_dict(d)
    assert restored == envelope


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_unknown_circuit_encode() -> None:
    with pytest.raises(EnvelopeError, match="UNKNOWN_CIRCUIT"):
        encode("FakeCircuit", "groth16", MOCK_PROOF, ["1"])


def test_unknown_proving_system() -> None:
    signals = mock_signals("HumanUniqueness")
    with pytest.raises(EnvelopeError, match="UNKNOWN_PROVING_SYSTEM"):
        encode("HumanUniqueness", "fflonk", MOCK_PROOF, signals)


def test_signal_count_mismatch() -> None:
    with pytest.raises(EnvelopeError, match="SIGNAL_COUNT_MISMATCH"):
        encode("HumanUniqueness", "groth16", MOCK_PROOF, ["1", "2"])


def test_version_mismatch_decode() -> None:
    envelope = BolyraEnvelope(
        version="2.0.0",
        circuit="HumanUniqueness",
        proving_system="groth16",
        signals={
            "nullifierHash": "1",
            "nonceBinding": "2",
            "humanMerkleRoot": "3",
            "externalNullifier": "4",
            "sessionNonce": "5",
        },
        proof=MOCK_PROOF,
    )
    with pytest.raises(EnvelopeError, match="UNSUPPORTED_VERSION"):
        decode(envelope)


def test_invalid_json() -> None:
    with pytest.raises(EnvelopeError, match="INVALID_JSON"):
        BolyraEnvelope.from_json("not json{{")


def test_missing_signal_in_decode() -> None:
    envelope = BolyraEnvelope(
        version="1.0.0",
        circuit="HumanUniqueness",
        proving_system="groth16",
        signals={"nullifierHash": "1", "nonceBinding": "2"},  # missing 3
        proof=MOCK_PROOF,
    )
    with pytest.raises(EnvelopeError, match="MISSING_SIGNAL"):
        decode(envelope)


def test_from_dict_unknown_circuit() -> None:
    data = {
        "version": "1.0.0",
        "circuit": "Nonexistent",
        "provingSystem": "groth16",
        "signals": {},
        "proof": MOCK_PROOF,
    }
    with pytest.raises(EnvelopeError, match="UNKNOWN_CIRCUIT"):
        BolyraEnvelope.from_dict(data)
