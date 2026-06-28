"""Tests for bolyra.proof_envelope — round-trip, validation, cross-SDK vectors."""

import json
import os
from pathlib import Path

import pytest

from bolyra.proof_envelope import (
    BOLYRA_PROOF_CONTENT_TYPE,
    ENVELOPE_VERSION,
    BolyraEnvelopeError,
    DelegationLink,
    ProofEnvelope,
    SnarkProof,
)

VECTORS_PATH = (
    Path(__file__).resolve().parents[2]
    / "spec"
    / "test-vectors"
    / "proof-envelope-roundtrip.json"
)


def _make_proof() -> SnarkProof:
    return SnarkProof(
        pi_a=["1", "2", "1"],
        pi_b=[["3", "4"], ["5", "6"], ["1", "0"]],
        pi_c=["7", "8", "1"],
    )


def _make_envelope(**overrides) -> ProofEnvelope:
    defaults = dict(
        version=ENVELOPE_VERSION,
        circuit="HumanUniqueness",
        public_signals=["123", "456", "789"],
        proof=_make_proof(),
    )
    defaults.update(overrides)
    return ProofEnvelope(**defaults)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_content_type(self):
        assert BOLYRA_PROOF_CONTENT_TYPE == "application/bolyra-proof+json"

    def test_version(self):
        assert ENVELOPE_VERSION == "1"


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_minimal(self):
        env = _make_envelope()
        parsed = ProofEnvelope.parse(env.serialize())
        assert parsed.serialize() == env.serialize()

    def test_with_session_token(self):
        env = _make_envelope(session_token="tok_abc")
        parsed = ProofEnvelope.parse(env.serialize())
        assert parsed.session_token == "tok_abc"
        assert parsed.serialize() == env.serialize()

    def test_with_delegation_chain(self):
        env = _make_envelope(
            circuit="Delegation",
            delegation_chain=[
                DelegationLink(
                    delegator_commitment="111",
                    delegate_commitment="222",
                    scope_mask=255,
                    expiry=1719878400,
                )
            ],
        )
        parsed = ProofEnvelope.parse(env.serialize())
        assert len(parsed.delegation_chain) == 1
        assert parsed.serialize() == env.serialize()


# ---------------------------------------------------------------------------
# Test vector fidelity
# ---------------------------------------------------------------------------


class TestVectors:
    @pytest.fixture()
    def vectors(self):
        with open(VECTORS_PATH) as f:
            return json.load(f)["vectors"]

    def _envelope_from_vector(self, vec: dict) -> ProofEnvelope:
        e = vec["envelope"]
        proof_raw = e["proof"]
        chain = None
        if "delegationChain" in e:
            chain = [
                DelegationLink(
                    delegator_commitment=link["delegatorCommitment"],
                    delegate_commitment=link["delegateCommitment"],
                    scope_mask=link["scopeMask"],
                    expiry=link["expiry"],
                )
                for link in e["delegationChain"]
            ]
        return ProofEnvelope(
            version=e["version"],
            circuit=e["circuit"],
            public_signals=e["publicSignals"],
            proof=SnarkProof(
                pi_a=proof_raw["pi_a"],
                pi_b=proof_raw["pi_b"],
                pi_c=proof_raw["pi_c"],
            ),
            session_token=e.get("sessionToken"),
            delegation_chain=chain,
        )

    def test_canonical_json_human(self, vectors):
        vec = vectors[0]
        env = self._envelope_from_vector(vec)
        assert env.serialize() == vec["canonicalJson"]

    def test_canonical_json_agent(self, vectors):
        vec = vectors[1]
        env = self._envelope_from_vector(vec)
        assert env.serialize() == vec["canonicalJson"]

    def test_canonical_json_delegation(self, vectors):
        vec = vectors[2]
        env = self._envelope_from_vector(vec)
        assert env.serialize() == vec["canonicalJson"]

    def test_roundtrip_all_vectors(self, vectors):
        for vec in vectors:
            env = self._envelope_from_vector(vec)
            serialized = env.serialize()
            parsed = ProofEnvelope.parse(serialized)
            assert parsed.serialize() == serialized, f"Failed for {vec['id']}"


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


class TestValidation:
    def test_rejects_bad_version(self):
        with pytest.raises(BolyraEnvelopeError, match="UNSUPPORTED_VERSION"):
            _make_envelope(version="99")

    def test_rejects_unknown_circuit(self):
        with pytest.raises(BolyraEnvelopeError, match="UNKNOWN_CIRCUIT"):
            _make_envelope(circuit="FooCircuit")

    def test_rejects_empty_public_signals(self):
        with pytest.raises(BolyraEnvelopeError, match="INVALID_PUBLIC_SIGNALS"):
            _make_envelope(public_signals=[])

    def test_rejects_bad_pi_a_length(self):
        with pytest.raises(BolyraEnvelopeError, match="INVALID_PROOF"):
            _make_envelope(
                proof=SnarkProof(
                    pi_a=["1", "2"],
                    pi_b=[["3", "4"], ["5", "6"], ["1", "0"]],
                    pi_c=["7", "8", "1"],
                )
            )

    def test_rejects_bad_pi_b_inner_length(self):
        with pytest.raises(BolyraEnvelopeError, match="INVALID_PROOF"):
            _make_envelope(
                proof=SnarkProof(
                    pi_a=["1", "2", "1"],
                    pi_b=[["3", "4", "x"], ["5", "6"], ["1", "0"]],
                    pi_c=["7", "8", "1"],
                )
            )

    def test_rejects_scope_mask_out_of_range(self):
        with pytest.raises(BolyraEnvelopeError, match="INVALID_DELEGATION_CHAIN"):
            _make_envelope(
                circuit="Delegation",
                delegation_chain=[
                    DelegationLink(
                        delegator_commitment="a",
                        delegate_commitment="b",
                        scope_mask=256,
                        expiry=1719878400,
                    )
                ],
            )

    def test_rejects_invalid_json(self):
        with pytest.raises(BolyraEnvelopeError, match="INVALID_JSON"):
            ProofEnvelope.parse("not json")

    def test_rejects_non_object(self):
        with pytest.raises(BolyraEnvelopeError, match="INVALID_ENVELOPE"):
            ProofEnvelope.parse("[1,2,3]")


# ---------------------------------------------------------------------------
# Forward compatibility
# ---------------------------------------------------------------------------


class TestForwardCompat:
    def test_tolerates_unknown_keys(self):
        env = _make_envelope()
        raw = json.loads(env.serialize())
        raw["futureField"] = "hello"
        parsed = ProofEnvelope.parse(json.dumps(raw))
        assert parsed.circuit == "HumanUniqueness"
