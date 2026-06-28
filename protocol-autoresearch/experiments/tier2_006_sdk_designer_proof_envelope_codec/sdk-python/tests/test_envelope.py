"""Tests for BolyraEnvelope — Python SDK.

Verifies round-trip encode/decode, fromRaw migration helper, error cases,
and cross-SDK compatibility using shared JSON fixtures.
"""

import json
import os
from pathlib import Path

import pytest

from bolyra.envelope import (
    ENVELOPE_VERSION,
    HUMAN_UNIQUENESS_SIGNALS,
    AGENT_POLICY_SIGNALS,
    DELEGATION_SIGNALS,
    SIGNAL_MAPS,
    BolyraEnvelope,
    EnvelopeVersionError,
    UnknownCircuitError,
    SignalCountMismatch,
    InvalidProvingSystemError,
    encode,
    decode,
    from_raw,
)

# Path to shared fixtures (relative to this file)
FIXTURES_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "sdk"
    / "test"
    / "fixtures"
    / "envelope-v1-samples.json"
)

MOCK_PROOF = {
    "pi_a": ["12345678901234567890", "98765432109876543210", "1"],
    "pi_b": [
        ["11111111111111111111", "22222222222222222222"],
        ["33333333333333333333", "44444444444444444444"],
        ["1", "0"],
    ],
    "pi_c": ["55555555555555555555", "66666666666666666666", "1"],
    "protocol": "groth16",
    "curve": "bn128",
}


class TestEncode:
    def test_human_uniqueness(self):
        signals = ["100", "200", "300"]
        env = encode("HumanUniqueness", "groth16", MOCK_PROOF, signals)
        assert env.version == ENVELOPE_VERSION
        assert env.circuit == "HumanUniqueness"
        assert env.proving_system == "groth16"
        assert env.signals["humanMerkleRoot"] == "100"
        assert env.signals["nullifierHash"] == "200"
        assert env.signals["nonceBinding"] == "300"

    def test_agent_policy(self):
        signals = ["1000", "7", "2000", "1735689600"]
        env = encode("AgentPolicy", "groth16", MOCK_PROOF, signals)
        assert env.circuit == "AgentPolicy"
        assert env.signals["permissionsBitmask"] == "7"
        assert env.signals["expiryTimestamp"] == "1735689600"

    def test_delegation(self):
        signals = ["100", "200", "3", "400"]
        env = encode("Delegation", "groth16", MOCK_PROOF, signals)
        assert env.circuit == "Delegation"
        assert env.signals["narrowedPermissionsBitmask"] == "3"

    def test_agent_policy_plonk(self):
        signals = ["1000", "7", "2000", "1735689600"]
        env = encode("AgentPolicy", "plonk", MOCK_PROOF, signals)
        assert env.proving_system == "plonk"

    def test_human_uniqueness_rejects_plonk(self):
        with pytest.raises(InvalidProvingSystemError):
            encode("HumanUniqueness", "plonk", MOCK_PROOF, ["1", "2", "3"])

    def test_unknown_circuit(self):
        with pytest.raises(UnknownCircuitError):
            encode("FakeCircuit", "groth16", MOCK_PROOF, ["1"])

    def test_signal_count_mismatch(self):
        with pytest.raises(SignalCountMismatch):
            encode("HumanUniqueness", "groth16", MOCK_PROOF, ["1", "2"])


class TestDecode:
    def test_round_trip_human_uniqueness(self):
        signals = ["100", "200", "300"]
        env = encode("HumanUniqueness", "groth16", MOCK_PROOF, signals)
        data = env.to_dict()
        decoded = decode(data)
        assert decoded.circuit == "HumanUniqueness"
        assert decoded.signals["humanMerkleRoot"] == "100"
        assert decoded.to_public_signals() == [100, 200, 300]

    def test_round_trip_agent_policy(self):
        signals = ["1000", "7", "2000", "1735689600"]
        env = encode("AgentPolicy", "groth16", MOCK_PROOF, signals)
        decoded = decode(env.to_dict())
        assert decoded.to_public_signals() == [1000, 7, 2000, 1735689600]

    def test_round_trip_delegation(self):
        signals = ["100", "200", "3", "400"]
        env = encode("Delegation", "groth16", MOCK_PROOF, signals)
        decoded = decode(env.to_dict())
        assert decoded.to_public_signals() == [100, 200, 3, 400]

    def test_rejects_version_2(self):
        data = {
            "version": "2.0.0",
            "circuit": "HumanUniqueness",
            "provingSystem": "groth16",
            "signals": {"humanMerkleRoot": "1", "nullifierHash": "2", "nonceBinding": "3"},
            "proof": MOCK_PROOF,
        }
        with pytest.raises(EnvelopeVersionError):
            decode(data)

    def test_accepts_version_1_1(self):
        data = {
            "version": "1.1.0",
            "circuit": "HumanUniqueness",
            "provingSystem": "groth16",
            "signals": {"humanMerkleRoot": "1", "nullifierHash": "2", "nonceBinding": "3"},
            "proof": MOCK_PROOF,
        }
        decoded = decode(data)
        assert decoded.version == "1.1.0"

    def test_rejects_unknown_circuit(self):
        data = {
            "version": "1.0.0",
            "circuit": "Unknown",
            "provingSystem": "groth16",
            "signals": {},
            "proof": MOCK_PROOF,
        }
        with pytest.raises(UnknownCircuitError):
            decode(data)

    def test_rejects_missing_signals(self):
        data = {
            "version": "1.0.0",
            "circuit": "HumanUniqueness",
            "provingSystem": "groth16",
            "signals": {"humanMerkleRoot": "1", "nullifierHash": "2"},
            "proof": MOCK_PROOF,
        }
        with pytest.raises(SignalCountMismatch):
            decode(data)


class TestFromRaw:
    def test_matches_encode(self):
        signals = ["100", "200", "300"]
        encoded = encode("HumanUniqueness", "groth16", MOCK_PROOF, signals)
        from_raw_result = from_raw("HumanUniqueness", "groth16", MOCK_PROOF, signals)
        assert encoded.to_dict() == from_raw_result.to_dict()


class TestToDict:
    def test_json_serializable(self):
        signals = ["100", "200", "300"]
        env = encode("HumanUniqueness", "groth16", MOCK_PROOF, signals)
        data = env.to_dict()
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        decoded = decode(parsed)
        assert decoded.signals["humanMerkleRoot"] == "100"

    def test_uses_camel_case_proving_system(self):
        signals = ["100", "200", "300"]
        env = encode("HumanUniqueness", "groth16", MOCK_PROOF, signals)
        data = env.to_dict()
        assert "provingSystem" in data
        assert "proving_system" not in data


class TestCrossSdkFixtures:
    @pytest.fixture
    def fixtures(self):
        if not FIXTURES_PATH.exists():
            pytest.skip(f"Fixture file not found: {FIXTURES_PATH}")
        with open(FIXTURES_PATH) as f:
            return json.load(f)

    def test_decode_all_ts_fixtures(self, fixtures):
        for key, sample in fixtures["samples"].items():
            env = decode(sample)
            assert env.version == "1.0.0"
            signal_names = SIGNAL_MAPS[env.circuit]
            assert len(env.to_public_signals()) == len(signal_names)

    def test_python_encode_matches_ts_fixture(self, fixtures):
        ts_human = fixtures["samples"]["HumanUniqueness"]
        py_env = encode(
            "HumanUniqueness",
            "groth16",
            ts_human["proof"],
            [
                ts_human["signals"]["humanMerkleRoot"],
                ts_human["signals"]["nullifierHash"],
                ts_human["signals"]["nonceBinding"],
            ],
        )
        assert py_env.to_dict() == ts_human


class TestSignalMaps:
    def test_human_uniqueness_count(self):
        assert len(HUMAN_UNIQUENESS_SIGNALS) == 3

    def test_agent_policy_count(self):
        assert len(AGENT_POLICY_SIGNALS) == 4

    def test_delegation_count(self):
        assert len(DELEGATION_SIGNALS) == 4
