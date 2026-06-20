"""Tests for bolyra_agents types and permission checking."""

from __future__ import annotations

from bolyra_agents.types import (
    AuthMode,
    AuthResult,
    BolyraAuthError,
    ToolPermission,
    check_permissions,
)


def test_auth_mode_values():
    """AuthMode enum should have SD_JWT and GATEWAY values."""
    assert AuthMode.SD_JWT.value == "sd-jwt"
    assert AuthMode.GATEWAY.value == "gateway"


def test_auth_result_defaults():
    """AuthResult should have sensible defaults."""
    result = AuthResult(ok=True)
    assert result.ok is True
    assert result.claims is None
    assert result.reason is None
    assert result.permissions == []
    assert result.agent_id == ""


def test_check_permissions_basic():
    """Basic permission check should work."""
    assert check_permissions(["READ_DATA"], ["READ_DATA"]) is True
    assert check_permissions(["READ_DATA"], ["WRITE_DATA"]) is False
    assert check_permissions(["READ_DATA", "WRITE_DATA"], ["READ_DATA"]) is True


def test_check_permissions_implication():
    """FINANCIAL_MEDIUM should imply FINANCIAL_SMALL."""
    assert check_permissions(["FINANCIAL_MEDIUM"], ["FINANCIAL_SMALL"]) is True
    assert check_permissions(["FINANCIAL_SMALL"], ["FINANCIAL_MEDIUM"]) is False


def test_check_permissions_unlimited_implies_both():
    """FINANCIAL_UNLIMITED should imply both SMALL and MEDIUM."""
    assert check_permissions(["FINANCIAL_UNLIMITED"], ["FINANCIAL_SMALL"]) is True
    assert check_permissions(["FINANCIAL_UNLIMITED"], ["FINANCIAL_MEDIUM"]) is True
    assert check_permissions(["FINANCIAL_UNLIMITED"], ["FINANCIAL_UNLIMITED"]) is True


def test_check_permissions_string_input():
    """check_permissions should accept strings as well as lists."""
    assert check_permissions("READ_DATA", "READ_DATA") is True
    assert check_permissions("READ_DATA", "WRITE_DATA") is False


def test_check_permissions_multiple_required():
    """All required permissions must be satisfied."""
    assert check_permissions(
        ["READ_DATA", "WRITE_DATA"],
        ["READ_DATA", "WRITE_DATA"],
    ) is True
    assert check_permissions(
        ["READ_DATA"],
        ["READ_DATA", "WRITE_DATA"],
    ) is False


def test_bolyra_auth_error():
    """BolyraAuthError should carry a result."""
    result = AuthResult(ok=False, reason="TEST")
    err = BolyraAuthError("test error", result=result)
    assert str(err) == "test error"
    assert err.result is result


def test_tool_permission_enum():
    """ToolPermission enum should have all 8 permission values."""
    assert len(ToolPermission) == 8
    assert ToolPermission.READ_DATA.value == "READ_DATA"
    assert ToolPermission.ACCESS_PII.value == "ACCESS_PII"
