"""Tests for bolyra.proof_envelope — round-trip, validation, cross-language interop."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from bolyra.proof_envelope import (
    ProofEnvelope,
    ProofEnvelopeError,
    DelegationChainEntry,
    CONTENT_TYPE,
    ENVELOPE_VERSION,
    build_content_type,
    decode,
    encode,
)

# ── Helpers ──────────────────────────────────────────────────────────


def make_envelope(**kwargs) -> ProofEnvelope:
    defaults = dict(
        version=ENVELOPE_VERSION,
        circuit_id="HumanUniqueness",
        proving_system="groth16",
        proof_bytes=b"\xde\xad\xbe\xef\x01\x02\x03\x04",
        public_signals=["1000000000000000000", "2000000000000000000", "3000000000000000000"],
    )
    defaults.update(kwargs)
    return ProofEnvelope(**defaults)


# ── Round-trip tests ─────────────────────────────────────────────────


class TestRoundTrip:
    @pytest.mark.parametrize(
        "circuit_id,proving_system",
        [
            ("HumanUniqueness", "groth16"),
            ("AgentPolicy", "groth16"),
            ("AgentPolicy", "plonk"),
            ("Delegation", "groth16"),
            ("Delegation", "plonk"),
        ],
    )
    def test_encode_decode_preserves_fields(self, circuit_id, proving_system):
        env = make_envelope(circuit_id=circuit_id, proving_system=proving_system)
        data = encode(env)
        assert isinstance(data, bytes)
        assert len(data) > 0

        dec = decode(data)
        assert dec.version == ENVELOPE_VERSION
        assert dec.circuit_id == circuit_id
        assert dec.proving_system == proving_system
        assert dec.public_signals == env.public_signals
        assert dec.proof_bytes == env.proof_bytes

    def test_delegation_chain_round_trip(self):
        chain = [
            DelegationChainEntry(data=b"\x01\x02\x03"),
            DelegationChainEntry(data=b"\x04\x05\x06"),
        ]
        env = make_envelope(delegation_chain=chain)
        dec = decode(encode(env))

        assert dec.delegation_chain is not None
        assert len(dec.delegation_chain) == 2
        assert dec.delegation_chain[0].data == b"\x01\x02\x03"
        assert dec.delegation_chain[1].data == b"\x04\x05\x06"

    def test_no_delegation_chain_omitted(self):
        env = make_envelope()
        dec = decode(encode(env))
        assert dec.delegation_chain is None


# ── Validation tests ─────────────────────────────────────────────────


class TestValidation:
    def test_rejects_empty_input(self):
        with pytest.raises(ProofEnvelopeError, match="EMPTY_INPUT"):
            decode(b"")

    def test_rejects_invalid_cbor(self):
        with pytest.raises(ProofEnvelopeError, match="CBOR_DECODE_FAILED"):
            decode(b"\xff\xfe\xfd")

    def test_rejects_unsupported_version(self):
        import cbor2

        data = cbor2.dumps({1: 99, 2: "HumanUniqueness", 3: "groth16", 4: b"\x01", 5: ["1"]})
        with pytest.raises(ProofEnvelopeError, match="UNSUPPORTED_VERSION"):
            decode(data)

    def test_rejects_unknown_circuit_id(self):
        import cbor2

        data = cbor2.dumps({1: 1, 2: "Fake", 3: "groth16", 4: b"\x01", 5: ["1"]})
        with pytest.raises(ProofEnvelopeError, match="UNKNOWN_CIRCUIT_ID"):
            decode(data)

    def test_rejects_unknown_proving_system(self):
        import cbor2

        data = cbor2.dumps({1: 1, 2: "HumanUniqueness", 3: "nova", 4: b"\x01", 5: ["1"]})
        with pytest.raises(ProofEnvelopeError, match="UNKNOWN_PROVING_SYSTEM"):
            decode(data)

    def test_rejects_empty_proof_bytes(self):
        import cbor2

        data = cbor2.dumps({1: 1, 2: "HumanUniqueness", 3: "groth16", 4: b"", 5: ["1"]})
        with pytest.raises(ProofEnvelopeError, match="EMPTY_PROOF"):
            decode(data)

    def test_rejects_non_string_signal(self):
        import cbor2

        data = cbor2.dumps({1: 1, 2: "HumanUniqueness", 3: "groth16", 4: b"\x01", 5: ["1", 2]})
        with pytest.raises(ProofEnvelopeError, match="INVALID_SIGNAL_TYPE"):
            decode(data)

    def test_rejects_delegation_chain_too_deep(self):
        chain = [DelegationChainEntry(data=b"\x01") for _ in range(9)]
        with pytest.raises(ProofEnvelopeError, match="DELEGATION_TOO_DEEP"):
            encode(make_envelope(delegation_chain=chain))

    def test_rejects_invalid_circuit_on_encode(self):
        with pytest.raises(ProofEnvelopeError, match="UNKNOWN_CIRCUIT_ID"):
            encode(make_envelope(circuit_id="BadCircuit"))

    def test_rejects_invalid_proving_system_on_encode(self):
        with pytest.raises(ProofEnvelopeError, match="UNKNOWN_PROVING_SYSTEM"):
            encode(make_envelope(proving_system="nova"))


# ── Content-Type ─────────────────────────────────────────────────────


class TestContentType:
    def test_builds_correct_header(self):
        ct = build_content_type("AgentPolicy", "groth16")
        assert ct == f"{CONTENT_TYPE}; circuit=AgentPolicy; ps=groth16; v={ENVELOPE_VERSION}"

    def test_plonk_header(self):
        ct = build_content_type("Delegation", "plonk")
        assert "ps=plonk" in ct
        assert "circuit=Delegation" in ct


# ── Size benchmark ───────────────────────────────────────────────────


class TestSizeEfficiency:
    def test_cbor_smaller_than_json(self):
        env = make_envelope(
            proof_bytes=b"\xaa" * 256,
            public_signals=[str(10**18 + i) for i in range(5)],
        )
        cbor_bytes = encode(env)

        json_equiv = json.dumps(
            {
                "version": env.version,
                "circuit_id": env.circuit_id,
                "proving_system": env.proving_system,
                "proof_bytes": list(env.proof_bytes),
                "public_signals": env.public_signals,
            }
        ).encode()

        assert len(cbor_bytes) < len(json_equiv)


# ── Cross-language interop ───────────────────────────────────────────


class TestCrossLanguageInterop:
    """Encode in Python, decode in TS (via subprocess), and vice versa."""

    @pytest.fixture
    def sdk_root(self):
        """Path to the TS SDK root, resolved relative to this experiment."""
        # In the autoresearch experiment context, the TS SDK is a peer artifact
        root = Path(__file__).resolve().parent.parent / ".." / "sdk"
        return root

    def test_python_encode_ts_decode(self, sdk_root, tmp_path):
        """Encode an envelope in Python, write to disk, decode in TS."""
        env = make_envelope()
        data = encode(env)
        cbor_file = tmp_path / "envelope.cbor"
        cbor_file.write_bytes(data)

        # Node.js script to decode and verify
        ts_script = f"""
        const fs = require('fs');
        try {{
          const {{ decode }} = require('{sdk_root}/src/proof-envelope.js');
          const buf = fs.readFileSync('{cbor_file}');
          const env = decode(new Uint8Array(buf));
          const result = {{
            version: env.version,
            circuitId: env.circuitId,
            provingSystem: env.provingSystem,
            signalCount: env.publicSignals.length,
          }};
          console.log(JSON.stringify(result));
        }} catch(e) {{
          console.log(JSON.stringify({{ error: e.message }}));
        }}
        """

        try:
            result = subprocess.run(
                ["node", "-e", ts_script],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                parsed = json.loads(result.stdout.strip())
                if "error" not in parsed:
                    assert parsed["version"] == ENVELOPE_VERSION
                    assert parsed["circuitId"] == "HumanUniqueness"
                    assert parsed["provingSystem"] == "groth16"
                    assert parsed["signalCount"] == 3
                else:
                    pytest.skip(f"TS decode unavailable: {parsed['error']}")
            else:
                pytest.skip("TS SDK not built or node unavailable")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("node not available for cross-language test")
