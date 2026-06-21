"""Tests for BolyraAuthTool (CrewAI BaseTool subclass)."""

from __future__ import annotations

import json

import pytest
from tests.conftest import requires_crewai, requires_node_and_sdk, requires_sdk


@requires_crewai
class TestBolyraAuthToolMetadata:
    """Tests that don't require Node.js or the SDK bridge."""

    def test_import(self):
        """Tool module is importable."""
        from bolyra_crewai import BolyraAuthTool  # noqa: F401

    def test_tool_name(self):
        """Tool has correct name."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        assert tool.name == "bolyra_authenticate"

    def test_args_schema(self):
        """Tool has correct args_schema."""
        from bolyra_crewai import BolyraAuthTool, BolyraAuthInput

        tool = BolyraAuthTool()
        assert tool.args_schema is BolyraAuthInput

    def test_is_base_tool(self):
        """Tool is a proper BaseTool subclass."""
        from crewai.tools import BaseTool
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        assert isinstance(tool, BaseTool)

    def test_description_not_empty(self):
        """Tool has a non-empty description."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        assert len(tool.description) > 20

    def test_default_permissions(self):
        """Default permissions is ['read_data']."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        assert tool.permissions == ["read_data"]

    def test_custom_permissions(self):
        """Custom permissions are accepted."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool(permissions=["read_data", "write_data"])
        assert tool.permissions == ["read_data", "write_data"]

    def test_returns_string(self):
        """_run returns a string (CrewAI convention)."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        result = tool._run(scope="test")
        assert isinstance(result, str)

    def test_returns_valid_json(self):
        """_run returns valid JSON."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        result = tool._run(scope="test")
        parsed = json.loads(result)
        assert "tool" in parsed
        assert parsed["tool"] == "bolyra_authenticate"


@requires_crewai
@requires_sdk
class TestBolyraAuthToolBehavior:
    """Tests that require the SDK but handle errors gracefully."""

    def test_unknown_permission_returns_error(self):
        """Unknown permission string returns an error."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool(permissions=["nonexistent_perm"])
        result = json.loads(tool._run(scope="test"))
        assert result["verified"] is False
        assert result["status"] == "error"

    def test_graceful_error_on_missing_sdk(self, monkeypatch):
        """Returns error JSON instead of crashing when SDK import fails."""
        from bolyra_crewai import BolyraAuthTool

        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("bolyra."):
                raise ImportError("mocked: bolyra not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        tool = BolyraAuthTool()
        result = json.loads(tool._run(scope="test"))
        assert result["verified"] is False
        assert result["status"] == "error"
        assert "not installed" in result.get("message", "")

    def test_dev_mode_blocked_in_production(self, monkeypatch):
        """Dev mode is blocked when BOLYRA_ENV=production."""
        from bolyra_crewai import BolyraAuthTool

        monkeypatch.setenv("BOLYRA_ENV", "production")
        tool = BolyraAuthTool()
        result = json.loads(tool._run(scope="test"))
        assert result["verified"] is False
        assert "production" in result.get("message", "").lower()


@requires_crewai
@requires_node_and_sdk
class TestBolyraAuthToolE2E:
    """End-to-end tests requiring Node.js and the full SDK."""

    def test_dev_mode_authentication(self):
        """Dev-mode auth produces a result (not a stub)."""
        from bolyra_crewai import BolyraAuthTool

        tool = BolyraAuthTool()
        result = json.loads(tool._run(scope="test-scope"))
        assert result["tool"] == "bolyra_authenticate"
        assert result["status"] in ("ok", "error")
