"""Tests for BolyraDelegateTool (CrewAI BaseTool subclass)."""

from __future__ import annotations

import json

import pytest
from tests.conftest import requires_crewai, requires_sdk


@requires_crewai
class TestBolyraDelegateToolMetadata:
    """Metadata tests -- no Node.js required."""

    def test_import(self):
        """Tool module is importable."""
        from bolyra_crewai import BolyraDelegateTool  # noqa: F401

    def test_tool_name(self):
        """Tool has correct name."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool()
        assert tool.name == "bolyra_delegate"

    def test_args_schema(self):
        """Tool has correct args_schema."""
        from bolyra_crewai import BolyraDelegateTool, BolyraDelegateInput

        tool = BolyraDelegateTool()
        assert tool.args_schema is BolyraDelegateInput

    def test_is_base_tool(self):
        """Tool is a proper BaseTool subclass."""
        from crewai.tools import BaseTool
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool()
        assert isinstance(tool, BaseTool)

    def test_returns_string(self):
        """_run returns a string (CrewAI convention)."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool()
        result = tool._run(
            delegatee_id="123",
            permissions="read_data",
            session_nonce="0",
        )
        assert isinstance(result, str)


@requires_crewai
class TestBolyraDelegateToolBehavior:
    """Behavior tests -- scope escalation and permission parsing."""

    def test_scope_escalation_rejected(self):
        """Cannot delegate permissions not held."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool(agent_permissions=["read_data"])
        result = json.loads(
            tool._run(
                delegatee_id="123",
                permissions="write_data",
                session_nonce="0",
            )
        )
        assert result["delegated"] is False
        assert result["status"] == "error"
        assert "not held" in result["message"]

    def test_comma_separated_permissions(self):
        """Comma-separated permissions are parsed correctly."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool(
            agent_permissions=["read_data", "write_data"]
        )
        # Should reject because financial_small is not held
        result = json.loads(
            tool._run(
                delegatee_id="123",
                permissions="read_data, financial_small",
                session_nonce="0",
            )
        )
        assert result["delegated"] is False
        assert "not held" in result["message"]

    def test_invalid_permission_returns_error(self):
        """Unknown permission in comma string returns error."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool(agent_permissions=["read_data"])
        result = json.loads(
            tool._run(
                delegatee_id="123",
                permissions="nonexistent_perm",
                session_nonce="0",
            )
        )
        assert result["delegated"] is False
        assert "Unknown permission" in result["message"]

    def test_empty_permissions_returns_error(self):
        """Empty permissions string returns error."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool()
        result = json.loads(
            tool._run(
                delegatee_id="123",
                permissions="",
                session_nonce="0",
            )
        )
        assert result["delegated"] is False
        assert "No permissions" in result["message"]

    def test_valid_subset_passes_escalation_check(self):
        """Valid subset of held permissions passes escalation check."""
        from bolyra_crewai import BolyraDelegateTool

        tool = BolyraDelegateTool(
            agent_permissions=["read_data", "write_data", "financial_small"]
        )
        result = json.loads(
            tool._run(
                delegatee_id="123",
                permissions="read_data, write_data",
                session_nonce="0",
            )
        )
        # Will fail at SDK level (no real Node.js delegation), but should
        # NOT fail at the escalation check level
        if result["delegated"] is False:
            assert "not held" not in result.get("message", "")
