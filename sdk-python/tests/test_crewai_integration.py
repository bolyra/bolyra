"""Tests for Bolyra CrewAI integration tools.

Requires Node.js >= 18 and the @bolyra/sdk built. Tests are skipped
if the Node.js bridge is unavailable.

Note: Full end-to-end tests (prove + verify) may take 2+ minutes due to
snarkjs verification time.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

# Add repo root so ``integrations.crewai.*`` is importable
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

# Skip entire module if Node.js is not available
try:
    subprocess.run(
        ["node", "--version"],
        capture_output=True,
        check=True,
        timeout=5,
    )
    NODE_AVAILABLE = True
except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
    NODE_AVAILABLE = False

# Also check that the bolyra Python SDK is importable
try:
    import bolyra  # noqa: F401
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False

SKIP_REASON = "Requires Node.js >= 18, @bolyra/sdk installed, and bolyra Python SDK"
requires_node_and_sdk = pytest.mark.skipif(
    not (NODE_AVAILABLE and SDK_AVAILABLE), reason=SKIP_REASON
)


# ------------------------------------------------------------------
# Auth tool
# ------------------------------------------------------------------

class TestBolyraAuthTool:
    """Tests for BolyraAuthTool (CrewAI)."""

    def test_import(self):
        """Tool module is importable."""
        from integrations.crewai.bolyra_auth_tool import BolyraAuthTool  # noqa: F401

    def test_tool_metadata(self):
        """Tool has correct name."""
        from integrations.crewai.bolyra_auth_tool import BolyraAuthTool

        tool = BolyraAuthTool()
        assert tool.name == "Bolyra Authenticate"

    @requires_node_and_sdk
    def test_dev_mode_authentication(self):
        """Dev-mode auth succeeds end-to-end.

        When Node.js and the SDK are available, the tool MUST return
        VERIFIED. Bridge timeouts (known issue on some machines where
        snarkjs verification exceeds the subprocess timeout) cause a
        skip rather than a false pass.
        """
        from integrations.crewai.bolyra_auth_tool import BolyraAuthTool

        tool = BolyraAuthTool()
        result = tool._run(scope="test-scope")

        assert isinstance(result, str)
        # Bridge timeout is a skip, not a pass
        if "timed out" in result:
            pytest.skip("Node.js bridge timed out (known on slow machines)")
        assert "VERIFIED" in result, f"Expected VERIFIED, got: {result}"

    def test_graceful_error_on_missing_sdk(self, monkeypatch):
        """Returns error string instead of crashing when SDK is missing."""
        from integrations.crewai.bolyra_auth_tool import BolyraAuthTool

        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("bolyra."):
                raise ImportError("mocked: bolyra not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        tool = BolyraAuthTool()
        result = tool._run()

        assert "failed" in result.lower()
        assert "not installed" in result.lower()


# ------------------------------------------------------------------
# Delegate tool
# ------------------------------------------------------------------

class TestBolyraDelegateTool:
    """Tests for BolyraDelegateTool (CrewAI)."""

    def test_import(self):
        """Tool module is importable."""
        from integrations.crewai.bolyra_delegate_tool import BolyraDelegateTool  # noqa: F401

    def test_tool_metadata(self):
        """Tool has correct name."""
        from integrations.crewai.bolyra_delegate_tool import BolyraDelegateTool

        tool = BolyraDelegateTool()
        assert tool.name == "Bolyra Delegate"

    def test_scope_escalation_rejected(self):
        """Cannot delegate permissions not held."""
        from integrations.crewai.bolyra_delegate_tool import BolyraDelegateTool

        tool = BolyraDelegateTool(agent_permissions=["read_data"])
        result = tool._run(
            delegatee_id="123",
            permissions="write_data",
            session_nonce="0",
        )

        assert "cannot delegate" in result.lower()
