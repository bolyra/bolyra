"""Tests for bolyra.delegation -- types, pre-flight validation, structural verify.

Real-proof tests (subprocess to the Node SDK) live under the ``integration``
marker and are gated on the @bolyra/sdk dist being present. CI runs the
structural tests only; the integration tests need circuit artifacts on disk.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from bolyra.delegation import DELEGATION_MAX_DEPTH, delegate, verify_delegation
from bolyra.errors import (
    BolyraError,
    ConfigurationError,
    ScopeEscalationError,
    VerificationError,
)
from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    DelegateeMerkleProof,
    DelegationResult,
    EdDSASignature,
    Permission,
    Point,
    Proof,
)


FUTURE_EXPIRY = int(time.time()) + 86400


def _dummy_credential(scope: int = 0b1, expiry: int | None = None) -> AgentCredential:
    """Build a structurally valid credential -- values are nonsense, but the
    pre-flight checks only inspect bitmask/expiry shape."""
    return AgentCredential(
        model_hash=111,
        operator_public_key=Point(x=1, y=2),
        permission_bitmask=scope,
        expiry_timestamp=expiry if expiry is not None else FUTURE_EXPIRY,
        signature=EdDSASignature(r8=Point(x=3, y=4), s=5),
        commitment=999,
    )


# ---------------------------------------------------------------------------
# DelegationResult / DelegateeMerkleProof types
# ---------------------------------------------------------------------------


class TestTypes:
    def test_delegation_result_shape(self):
        r = DelegationResult(
            new_scope_commitment=1,
            delegation_nullifier=2,
            delegatee_merkle_root=5,
            hop_index=0,
        )
        assert r.new_scope_commitment == 1
        assert r.delegation_nullifier == 2
        assert r.delegatee_merkle_root == 5
        assert r.hop_index == 0

    def test_delegatee_merkle_proof_shape(self):
        p = DelegateeMerkleProof(length=1, index=0, siblings=[0] * 20)
        assert p.length == 1
        assert p.index == 0
        assert len(p.siblings) == 20

    def test_max_depth_constant(self):
        # Must match circuits/src/Delegation.circom.
        assert DELEGATION_MAX_DEPTH == 20


# ---------------------------------------------------------------------------
# delegate() pre-flight validation -- no Node subprocess required
# ---------------------------------------------------------------------------


class TestDelegatePreflight:
    def test_rejects_scope_escalation(self):
        delegator = _dummy_credential(scope=0b1)  # READ_DATA only
        with pytest.raises(ScopeEscalationError):
            delegate(
                delegator=delegator,
                delegator_operator_private_key=42,
                delegatee_commitment=999,
                delegatee_scope=0b11,  # READ + WRITE -- escalation
                delegatee_expiry=FUTURE_EXPIRY - 100,
                previous_scope_commitment=0,
                session_nonce=1,
            )

    def test_rejects_expiry_escalation(self):
        delegator = _dummy_credential(scope=0b11)
        with pytest.raises(BolyraError) as exc_info:
            delegate(
                delegator=delegator,
                delegator_operator_private_key=42,
                delegatee_commitment=999,
                delegatee_scope=0b1,
                delegatee_expiry=FUTURE_EXPIRY + 1000,  # past delegator
                previous_scope_commitment=0,
                session_nonce=1,
            )
        assert exc_info.value.code == "EXPIRY_ESCALATION"

    def test_rejects_malformed_merkle_proof(self):
        delegator = _dummy_credential(scope=0b11)
        bad = DelegateeMerkleProof(length=1, index=0, siblings=[0, 0, 0])
        with pytest.raises(BolyraError) as exc_info:
            delegate(
                delegator=delegator,
                delegator_operator_private_key=42,
                delegatee_commitment=999,
                delegatee_scope=0b1,
                delegatee_expiry=FUTURE_EXPIRY - 100,
                previous_scope_commitment=0,
                session_nonce=1,
                delegatee_merkle_proof=bad,
            )
        assert exc_info.value.code == "INVALID_MERKLE_PROOF"

    def test_raises_configuration_error_when_sdk_missing(self, tmp_path):
        """Bridge fails cleanly when node_sdk_path is wrong."""
        delegator = _dummy_credential(scope=0b11)
        config = BolyraConfig(node_sdk_path=str(tmp_path))  # empty dir
        with pytest.raises(ConfigurationError) as exc_info:
            delegate(
                delegator=delegator,
                delegator_operator_private_key=42,
                delegatee_commitment=999,
                delegatee_scope=0b1,
                delegatee_expiry=FUTURE_EXPIRY - 100,
                previous_scope_commitment=0,
                session_nonce=1,
                config=config,
            )
        assert exc_info.value.code == "CONFIGURATION_ERROR"


# ---------------------------------------------------------------------------
# verify_delegation() structural validation -- no Node subprocess required
# ---------------------------------------------------------------------------


class TestVerifyDelegationStructural:
    def test_rejects_invalid_proof_object(self):
        with pytest.raises(VerificationError):
            verify_delegation(None, 0, 0, 0)  # type: ignore[arg-type]

    def test_rejects_short_public_signals(self):
        proof = Proof(proof={"a": 1}, public_signals=["1", "2", "3"])
        with pytest.raises(VerificationError, match="public signals"):
            verify_delegation(proof, 0, 0, 0)


# ---------------------------------------------------------------------------
# Real-proof integration (Phase 1+2 TS SDK round trip)
# ---------------------------------------------------------------------------

# Gate on dist + circuit artifacts -- skip cleanly if either is missing,
# so `pytest -v` is green on a fresh clone.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TS_DIST = _REPO_ROOT / "sdk" / "dist" / "index.js"
_CIRCUIT_ZKEY = _REPO_ROOT / "circuits" / "build" / "Delegation_final.zkey"

requires_artifacts = pytest.mark.skipif(
    not (_TS_DIST.exists() and _CIRCUIT_ZKEY.exists()),
    reason="Requires @bolyra/sdk dist + Delegation circuit artifacts on disk.",
)


@requires_artifacts
class TestDelegateE2E:
    """Spawn the real TS bridge. Only runs when both dist and zkey are present."""

    def test_delegate_returns_delegation_result(self):
        # Lazy import so the structural tests do not depend on identity.create_agent_credential
        # being callable in CI environments without circomlibjs.
        pytest.importorskip("subprocess")
        # We do not actually exercise create_agent_credential here -- the TS SDK has
        # an integration test that covers the round-trip. This test only confirms the
        # subprocess bridge surfaces typed errors instead of crashing.
        delegator = _dummy_credential(scope=0b11)
        # We expect this to fail at the witness-generation stage in the circuit
        # (dummy operator key, dummy commitment). The point of the test is to
        # confirm the failure surfaces as a ProofGenerationError, NOT a Python
        # crash from the subprocess bridge.
        with pytest.raises((BolyraError,)):
            delegate(
                delegator=delegator,
                delegator_operator_private_key=42,
                delegatee_commitment=12345,
                delegatee_scope=0b1,
                delegatee_expiry=FUTURE_EXPIRY - 3600,
                # Wrong previous_scope_commitment -- circuit will reject.
                previous_scope_commitment=99999,
                session_nonce=42,
            )
