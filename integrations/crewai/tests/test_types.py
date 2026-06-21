"""Tests for Bolyra CrewAI types and permission parsing."""

from __future__ import annotations

import json

import pytest


class TestParsePermissions:
    """Tests for parse_permissions helper."""

    def test_single_permission(self):
        from bolyra_crewai.types import parse_permissions

        result = parse_permissions("read_data")
        assert result == ["read_data"]

    def test_multiple_permissions(self):
        from bolyra_crewai.types import parse_permissions

        result = parse_permissions("read_data, write_data, access_pii")
        assert result == ["read_data", "write_data", "access_pii"]

    def test_whitespace_handling(self):
        from bolyra_crewai.types import parse_permissions

        result = parse_permissions("  read_data ,  write_data  ")
        assert result == ["read_data", "write_data"]

    def test_case_insensitive(self):
        from bolyra_crewai.types import parse_permissions

        result = parse_permissions("READ_DATA, Write_Data")
        assert result == ["read_data", "write_data"]

    def test_invalid_permission_raises(self):
        from bolyra_crewai.types import parse_permissions

        with pytest.raises(ValueError, match="Unknown permission"):
            parse_permissions("read_data, nonexistent_perm")

    def test_empty_string_returns_empty(self):
        from bolyra_crewai.types import parse_permissions

        result = parse_permissions("")
        assert result == []

    def test_all_valid_permissions(self):
        from bolyra_crewai.types import parse_permissions, VALID_PERMISSIONS

        all_perms = ", ".join(sorted(VALID_PERMISSIONS))
        result = parse_permissions(all_perms)
        assert set(result) == VALID_PERMISSIONS


class TestAuthResult:
    """Tests for AuthResult dataclass."""

    def test_verified_to_dict(self):
        from bolyra_crewai.types import AuthResult

        r = AuthResult(
            verified=True,
            status="ok",
            human_nullifier="h123",
            agent_nullifier="a456",
            session_nonce="n789",
            scope_commitment="sc000",
            scope="test",
            required_permissions=["read_data"],
        )
        d = r.to_dict()
        assert d["verified"] is True
        assert d["session_nonce"] == "n789"
        assert "human_nullifier" in d

    def test_failed_to_dict_omits_nullifiers(self):
        from bolyra_crewai.types import AuthResult

        r = AuthResult(verified=False, status="error", message="test error")
        d = r.to_dict()
        assert d["verified"] is False
        assert "human_nullifier" not in d
        assert d["message"] == "test error"

    def test_to_json_is_valid(self):
        from bolyra_crewai.types import AuthResult

        r = AuthResult(verified=True, status="ok")
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["verified"] is True


class TestDelegationResult:
    """Tests for DelegationResult dataclass."""

    def test_delegated_to_dict(self):
        from bolyra_crewai.types import DelegationResult

        r = DelegationResult(
            delegated=True,
            status="ok",
            delegatee_id="0xabc",
            permissions=["read_data"],
            new_scope_commitment="sc123",
        )
        d = r.to_dict()
        assert d["delegated"] is True
        assert d["delegatee_id"] == "0xabc"

    def test_failed_to_dict_omits_details(self):
        from bolyra_crewai.types import DelegationResult

        r = DelegationResult(delegated=False, status="error")
        d = r.to_dict()
        assert "delegatee_id" not in d

    def test_to_json_is_valid(self):
        from bolyra_crewai.types import DelegationResult

        r = DelegationResult(delegated=False, status="error", message="fail")
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["status"] == "error"


class TestSDJWTResult:
    """Tests for SDJWTResult dataclass."""

    def test_success_to_dict(self):
        from bolyra_crewai.types import SDJWTResult

        r = SDJWTResult(
            success=True,
            status="ok",
            receipt_jti="jti-123",
            action="read",
            audience="api",
            permission="READ_DATA",
            expiry=9999,
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["receipt_jti"] == "jti-123"
        # Raw receipt field must NOT be in output
        assert "receipt" not in d

    def test_failed_to_dict_omits_details(self):
        from bolyra_crewai.types import SDJWTResult

        r = SDJWTResult(success=False, status="error")
        d = r.to_dict()
        assert "receipt_jti" not in d

    def test_to_json_is_valid(self):
        from bolyra_crewai.types import SDJWTResult

        r = SDJWTResult(success=True, status="ok", receipt_jti="j1")
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["success"] is True


class TestMakeCanonicalNonce:
    """Tests for canonical nonce generation."""

    def test_nonce_is_large_int(self):
        from bolyra_crewai.types import make_canonical_nonce

        nonce = make_canonical_nonce()
        assert isinstance(nonce, int)
        # Must be > 2^64 (has both time and random components)
        assert nonce > (1 << 64)

    def test_nonces_are_unique(self):
        from bolyra_crewai.types import make_canonical_nonce

        nonces = {make_canonical_nonce() for _ in range(10)}
        assert len(nonces) == 10


class TestIsDevModeAllowed:
    """Tests for dev mode environment guard."""

    def test_allowed_by_default(self):
        from bolyra_crewai.types import is_dev_mode_allowed
        import os

        # Remove BOLYRA_ENV if set
        old = os.environ.pop("BOLYRA_ENV", None)
        try:
            assert is_dev_mode_allowed() is True
        finally:
            if old is not None:
                os.environ["BOLYRA_ENV"] = old

    def test_blocked_in_production(self):
        from bolyra_crewai.types import is_dev_mode_allowed
        import os

        old = os.environ.get("BOLYRA_ENV")
        os.environ["BOLYRA_ENV"] = "production"
        try:
            assert is_dev_mode_allowed() is False
        finally:
            if old is not None:
                os.environ["BOLYRA_ENV"] = old
            else:
                os.environ.pop("BOLYRA_ENV", None)
