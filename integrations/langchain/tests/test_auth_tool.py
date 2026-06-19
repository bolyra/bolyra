"""Tests for BolyraAuthTool (LangChain BaseTool subclass)."""

from __future__ import annotations

import pytest
from tests.conftest import requires_langchain, requires_node_and_sdk, requires_sdk


@requires_langchain
class TestBolyraAuthToolMetadata:
    """Tests that don't require Node.js or the SDK bridge."""

    def test_import(self):
        """Tool module is importable."""
        from bolyra_langchain import BolyraAuthTool  # noqa: F401

    def test_tool_name(self):
        """Tool has correct name."""
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool()
        assert tool.name == "bolyra_authenticate"

    def test_args_schema(self):
        """Tool has correct args_schema."""
        from bolyra_langchain import BolyraAuthTool, BolyraAuthInput
        tool = BolyraAuthTool()
        assert tool.args_schema is BolyraAuthInput

    def test_is_base_tool(self):
        """Tool is a proper BaseTool subclass."""
        from langchain_core.tools import BaseTool
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool()
        assert isinstance(tool, BaseTool)

    def test_description_not_empty(self):
        """Tool has a non-empty description."""
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool()
        assert len(tool.description) > 20

    def test_default_permissions(self):
        """Default permissions is ['read_data']."""
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool()
        assert tool.permissions == ["read_data"]

    def test_custom_permissions(self):
        """Custom permissions are accepted."""
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool(permissions=["read_data", "write_data"])
        assert tool.permissions == ["read_data", "write_data"]


@requires_langchain
@requires_sdk
class TestBolyraAuthToolBehavior:
    """Tests that require the SDK but mock or handle SDK errors."""

    def test_unknown_permission_returns_error(self):
        """Unknown permission string returns an error dict."""
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool(permissions=["nonexistent_perm"])
        result = tool.invoke({"scope": "test"})
        assert result["verified"] is False
        assert result["status"] == "error"

    def test_graceful_error_on_missing_sdk(self, monkeypatch):
        """Returns error dict instead of crashing when SDK import fails."""
        from bolyra_langchain import BolyraAuthTool
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("bolyra."):
                raise ImportError("mocked: bolyra not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        tool = BolyraAuthTool()
        result = tool.invoke({"scope": "test"})
        assert result["verified"] is False
        assert result["status"] == "error"
        assert "not installed" in result.get("message", "")


@requires_langchain
@requires_node_and_sdk
class TestBolyraAuthToolE2E:
    """End-to-end tests requiring Node.js and the full SDK."""

    def test_dev_mode_authentication(self):
        """Dev-mode auth produces a result (not a stub)."""
        from bolyra_langchain import BolyraAuthTool
        tool = BolyraAuthTool()
        result = tool.invoke({"scope": "test-scope"})
        assert result["tool"] == "bolyra_authenticate"
        assert result.get("status") != "not_implemented"
        assert result["status"] in ("ok", "error")
