"""Tests for Bolyra tracing integration."""

from __future__ import annotations

from unittest.mock import MagicMock

from bolyra_agents._tracing import bolyra_auth_span, record_auth_result


def test_bolyra_auth_span_creates_span():
    """bolyra_auth_span should yield a span context."""
    with bolyra_auth_span("verify", agent_id="test-agent") as span:
        assert span is not None


def test_bolyra_auth_span_redacts_sensitive_keys():
    """bolyra_auth_span should only include allowlisted keys in span data."""
    with bolyra_auth_span(
        "verify",
        agent_id="test-agent",
        receipt="secret-receipt",
        token="secret-token",
        private_key="secret-key",
        tool_name="my-tool",
        unknown_field="should-be-redacted",
    ) as span:
        if hasattr(span, "span_data") and hasattr(span.span_data, "data"):
            data = span.span_data.data
            # Sensitive keys must not appear
            assert "receipt" not in data
            assert "token" not in data
            assert "private_key" not in data
            # Non-allowlisted keys must not appear
            assert "unknown_field" not in data
            # Allowlisted keys pass through
            assert data.get("tool_name") == "my-tool"


def test_record_auth_result_success():
    """record_auth_result should set auth_ok on span data."""
    span = MagicMock()
    span.span_data.data = {}

    record_auth_result(span, ok=True)
    assert span.span_data.data["auth_ok"] is True
    assert "auth_reason" not in span.span_data.data


def test_record_auth_result_failure():
    """record_auth_result should set auth_ok and auth_reason on failure."""
    span = MagicMock()
    span.span_data.data = {}

    record_auth_result(span, ok=False, reason="EXPIRED")
    assert span.span_data.data["auth_ok"] is False
    assert span.span_data.data["auth_reason"] == "EXPIRED"
