"""Tests for bolyra.identity — permission bitmask, cumulative encoding, validation."""

import time

import pytest

from bolyra.errors import InvalidPermissionError, InvalidSecretError
from bolyra.identity import (
    BN254_FIELD_ORDER,
    permissions_to_bitmask,
    validate_cumulative_bit_encoding,
    validate_human_secret,
    validate_agent_expiry,
)
from bolyra.types import Permission


# ---------------------------------------------------------------------------
# permissions_to_bitmask
# ---------------------------------------------------------------------------


class TestPermissionsToBitmask:
    def test_single_read(self):
        assert permissions_to_bitmask([Permission.READ_DATA]) == 0b1

    def test_single_write(self):
        assert permissions_to_bitmask([Permission.WRITE_DATA]) == 0b10

    def test_read_and_write(self):
        assert permissions_to_bitmask([Permission.READ_DATA, Permission.WRITE_DATA]) == 0b11

    def test_financial_small(self):
        assert permissions_to_bitmask([Permission.FINANCIAL_SMALL]) == 1 << 2

    def test_financial_cumulative_full(self):
        perms = [
            Permission.FINANCIAL_SMALL,
            Permission.FINANCIAL_MEDIUM,
            Permission.FINANCIAL_UNLIMITED,
        ]
        expected = (1 << 2) | (1 << 3) | (1 << 4)
        assert permissions_to_bitmask(perms) == expected

    def test_all_permissions(self):
        all_perms = list(Permission)
        bitmask = permissions_to_bitmask(all_perms)
        assert bitmask == 0b11111111  # bits 0-7

    def test_empty_list(self):
        assert permissions_to_bitmask([]) == 0

    def test_duplicate_permissions(self):
        # Duplicates should not change the result (idempotent OR)
        result = permissions_to_bitmask([Permission.READ_DATA, Permission.READ_DATA])
        assert result == 0b1

    def test_access_pii(self):
        assert permissions_to_bitmask([Permission.ACCESS_PII]) == 1 << 7


# ---------------------------------------------------------------------------
# validate_cumulative_bit_encoding
# ---------------------------------------------------------------------------


class TestValidateCumulativeBitEncoding:
    def test_valid_all_financial(self):
        bitmask = (1 << 2) | (1 << 3) | (1 << 4)
        validate_cumulative_bit_encoding(bitmask)  # should not raise

    def test_valid_small_only(self):
        validate_cumulative_bit_encoding(1 << 2)

    def test_valid_small_and_medium(self):
        validate_cumulative_bit_encoding((1 << 2) | (1 << 3))

    def test_valid_no_financial(self):
        validate_cumulative_bit_encoding(0b11)  # READ + WRITE only

    def test_valid_zero(self):
        validate_cumulative_bit_encoding(0)

    def test_invalid_unlimited_without_medium(self):
        bitmask = (1 << 2) | (1 << 4)  # SMALL + UNLIMITED, no MEDIUM
        with pytest.raises(InvalidPermissionError, match="FINANCIAL_UNLIMITED.*FINANCIAL_MEDIUM"):
            validate_cumulative_bit_encoding(bitmask)

    def test_invalid_unlimited_without_small(self):
        bitmask = (1 << 3) | (1 << 4)  # MEDIUM + UNLIMITED, no SMALL
        with pytest.raises(InvalidPermissionError, match="FINANCIAL_UNLIMITED.*FINANCIAL_SMALL"):
            validate_cumulative_bit_encoding(bitmask)

    def test_invalid_medium_without_small(self):
        bitmask = 1 << 3  # MEDIUM only, no SMALL
        with pytest.raises(InvalidPermissionError, match="FINANCIAL_MEDIUM.*FINANCIAL_SMALL"):
            validate_cumulative_bit_encoding(bitmask)

    def test_invalid_unlimited_alone(self):
        bitmask = 1 << 4  # UNLIMITED alone
        with pytest.raises(InvalidPermissionError):
            validate_cumulative_bit_encoding(bitmask)


# ---------------------------------------------------------------------------
# validate_human_secret
# ---------------------------------------------------------------------------


class TestValidateHumanSecret:
    def test_valid_secret(self):
        validate_human_secret(42)  # should not raise

    def test_valid_large_secret(self):
        validate_human_secret(BN254_FIELD_ORDER - 1)

    def test_zero_secret(self):
        with pytest.raises(InvalidSecretError, match="non-zero"):
            validate_human_secret(0)

    def test_negative_secret(self):
        with pytest.raises(InvalidSecretError, match="positive"):
            validate_human_secret(-1)

    def test_exceeds_field_order(self):
        with pytest.raises(InvalidSecretError, match="exceeds BN254"):
            validate_human_secret(BN254_FIELD_ORDER)

    def test_exceeds_field_order_by_one(self):
        with pytest.raises(InvalidSecretError, match="exceeds BN254"):
            validate_human_secret(BN254_FIELD_ORDER + 1)


# ---------------------------------------------------------------------------
# validate_agent_expiry
# ---------------------------------------------------------------------------


class TestValidateAgentExpiry:
    def test_valid_future_timestamp(self):
        future = int(time.time()) + 86400
        validate_agent_expiry(future)  # should not raise

    def test_past_timestamp(self):
        past = int(time.time()) - 86400
        with pytest.raises(InvalidPermissionError, match="not in the future"):
            validate_agent_expiry(past)

    def test_zero_timestamp(self):
        with pytest.raises(InvalidPermissionError, match="not in the future"):
            validate_agent_expiry(0)


# ---------------------------------------------------------------------------
# Error class hierarchy
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_invalid_permission_is_bolyra_error(self):
        from bolyra.errors import BolyraError

        err = InvalidPermissionError("test")
        assert isinstance(err, BolyraError)
        assert err.code == "INVALID_PERMISSION"

    def test_invalid_secret_is_bolyra_error(self):
        from bolyra.errors import BolyraError

        err = InvalidSecretError("test reason")
        assert isinstance(err, BolyraError)
        assert err.code == "INVALID_SECRET"

    def test_proof_generation_error(self):
        from bolyra.errors import ProofGenerationError

        err = ProofGenerationError("HumanUniqueness", "timeout")
        assert "HumanUniqueness" in str(err)
        assert err.code == "PROOF_GENERATION_FAILED"
        assert err.details["circuit"] == "HumanUniqueness"

    def test_circuit_artifact_not_found(self):
        from bolyra.errors import CircuitArtifactNotFoundError, ProofGenerationError

        err = CircuitArtifactNotFoundError("/path/to/file.wasm", "wasm")
        assert isinstance(err, ProofGenerationError)
        assert err.code == "CIRCUIT_ARTIFACT_NOT_FOUND"
        assert err.details["artifact_path"] == "/path/to/file.wasm"

    def test_scope_escalation_error(self):
        from bolyra.errors import ScopeEscalationError

        err = ScopeEscalationError(7, 15)
        assert "escalation" in str(err).lower()
        assert err.code == "SCOPE_ESCALATION"

    def test_stale_proof_error(self):
        from bolyra.errors import StaleProofError

        err = StaleProofError("human")
        assert "stale" in str(err).lower()
        assert err.details["root_type"] == "human"

    def test_configuration_error(self):
        from bolyra.errors import ConfigurationError

        err = ConfigurationError("rpc_url", "invalid URL")
        assert err.code == "CONFIGURATION_ERROR"
        assert err.details["field"] == "rpc_url"

    def test_merkle_tree_error(self):
        from bolyra.errors import MerkleTreeError

        err = MerkleTreeError("index out of bounds", {"index": 999})
        assert err.code == "MERKLE_TREE_ERROR"
        assert err.details["index"] == 999

    def test_expired_credential_error(self):
        from bolyra.errors import ExpiredCredentialError

        err = ExpiredCredentialError(1000000)
        assert err.code == "CREDENTIAL_EXPIRED"
        assert "1000000" in str(err)

    def test_verification_error(self):
        from bolyra.errors import VerificationError

        err = VerificationError("bad proof")
        assert err.code == "VERIFICATION_FAILED"
