"""Tests for BolyraDelegateTool (LangChain BaseTool subclass)."""

from __future__ import annotations

import pytest
from tests.conftest import requires_langchain, requires_sdk


@requires_langchain
class TestBolyraDelegateToolMetadata:
    """Metadata tests -- no Node.js required."""

    def test_import(self):
        """Tool module is importable."""
        from bolyra_langchain import BolyraDelegateTool  # noqa: F401

    def test_tool_name(self):
        """Tool has correct name."""
        from bolyra_langchain import BolyraDelegateTool
        tool = BolyraDelegateTool()
        assert tool.name == "bolyra_delegate"

    def test_args_schema(self):
        """Tool has correct args_schema."""
        from bolyra_langchain import BolyraDelegateTool, BolyraDelegateInput
        tool = BolyraDelegateTool()
        assert tool.args_schema is BolyraDelegateInput

    def test_is_base_tool(self):
        """Tool is a proper BaseTool subclass."""
        from langchain_core.tools import BaseTool
        from bolyra_langchain import BolyraDelegateTool
        tool = BolyraDelegateTool()
        assert isinstance(tool, BaseTool)


@requires_langchain
@requires_sdk
class TestBolyraDelegateToolBehavior:
    """Behavior tests."""

    def test_scope_escalation_rejected(self):
        """Cannot delegate permissions not held."""
        from bolyra_langchain import BolyraDelegateTool
        tool = BolyraDelegateTool(agent_permissions=["read_data"])
        result = tool.invoke({
            "delegatee_id": "123",
            "permissions": ["write_data"],
            "session_nonce": "0",
            "scope_commitment": "0",
        })
        assert result["delegated"] is False
        assert result["status"] == "error"
        assert "not held" in result["message"]

    def test_unknown_permission_returns_error(self):
        """Unknown permission string in delegation returns error."""
        from bolyra_langchain import BolyraDelegateTool
        tool = BolyraDelegateTool(agent_permissions=["read_data", "nonexistent"])
        result = tool.invoke({
            "delegatee_id": "123",
            "permissions": ["nonexistent"],
            "session_nonce": "0",
            "scope_commitment": "0",
        })
        assert result["delegated"] is False
        assert result["status"] == "error"
