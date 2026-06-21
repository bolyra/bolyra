"""Tests for BolyraGuard (pre-execution + step callback)."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest


class TestBolyraGuardInit:
    """Tests for guard initialization."""

    def test_default_on_failure(self):
        """Default on_failure is 'raise'."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard()
        assert guard.on_failure == "raise"

    def test_valid_on_failure_modes(self):
        """All three on_failure modes are accepted."""
        from bolyra_crewai.guard import BolyraGuard

        for mode in ("raise", "warn", "skip"):
            guard = BolyraGuard(on_failure=mode)
            assert guard.on_failure == mode

    def test_invalid_on_failure_raises(self):
        """Invalid on_failure mode raises ValueError."""
        from bolyra_crewai.guard import BolyraGuard

        with pytest.raises(ValueError, match="on_failure"):
            BolyraGuard(on_failure="invalid")

    def test_default_allow_list(self):
        """bolyra_authenticate is in the allow list by default."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard()
        assert "bolyra_authenticate" in guard.allow_unauthenticated_tools


class TestBolyraGuardRaiseMode:
    """Tests for raise mode (default)."""

    def test_raises_on_unauthenticated_tool(self):
        """Raises BolyraAuthError when no session is set."""
        from bolyra_crewai.guard import BolyraGuard, BolyraAuthError

        guard = BolyraGuard(on_failure="raise")
        step = SimpleNamespace(tool="some_tool")

        with pytest.raises(BolyraAuthError, match="requires"):
            guard.step_callback(step)

    def test_raises_when_session_not_authenticated(self):
        """Raises when session exists but is not authenticated."""
        from bolyra_crewai.guard import BolyraGuard, BolyraAuthError
        from bolyra_crewai.session import BolyraSession

        session = BolyraSession()
        guard = BolyraGuard(session=session, on_failure="raise")
        step = SimpleNamespace(tool="some_tool")

        with pytest.raises(BolyraAuthError, match="authentication"):
            guard.step_callback(step)

    def test_allows_authenticated_session(self):
        """No error when session is authenticated."""
        from bolyra_crewai.guard import BolyraGuard
        from bolyra_crewai.session import BolyraSession

        session = BolyraSession()
        # Manually set auth state
        session._auth_result = {"verified": True, "session_nonce": "n123"}

        guard = BolyraGuard(session=session, on_failure="raise")
        step = SimpleNamespace(tool="some_tool")

        # Should not raise
        guard.step_callback(step)

    def test_allows_auth_tool_without_session(self):
        """bolyra_authenticate tool is always allowed."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="raise")
        step = SimpleNamespace(tool="bolyra_authenticate")

        # Should not raise
        guard.step_callback(step)


class TestBolyraGuardWarnMode:
    """Tests for warn mode."""

    def test_warns_instead_of_raising(self, caplog):
        """Warn mode logs a warning instead of raising."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="warn")
        step = SimpleNamespace(tool="some_tool")

        with caplog.at_level(logging.WARNING):
            # Should not raise
            guard.step_callback(step)

        assert any("BolyraGuard" in record.message for record in caplog.records)


class TestBolyraGuardSkipMode:
    """Tests for skip mode."""

    def test_skip_bypasses_all_checks(self):
        """Skip mode does nothing regardless of session state."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="skip")
        step = SimpleNamespace(tool="some_tool")

        # Should not raise
        guard.step_callback(step)


class TestBolyraGuardNonToolSteps:
    """Tests for non-tool steps."""

    def test_non_tool_step_is_ignored(self):
        """Steps without tool attribute are ignored."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="raise")

        # No .tool attribute
        guard.step_callback("just a string")
        guard.step_callback(42)
        guard.step_callback(None)

    def test_dict_step_with_tool(self):
        """Dict-based step output with 'tool' key is checked."""
        from bolyra_crewai.guard import BolyraGuard, BolyraAuthError

        guard = BolyraGuard(on_failure="raise")
        step = {"tool": "some_tool"}

        with pytest.raises(BolyraAuthError):
            guard.step_callback(step)


class TestBolyraGuardSessionExpiry:
    """Tests for session TTL checking."""

    def test_expired_session_triggers_failure(self):
        """Expired session triggers failure action."""
        from bolyra_crewai.guard import BolyraGuard, BolyraAuthError
        from bolyra_crewai.session import BolyraSession
        import time

        session = BolyraSession()
        session._auth_result = {"verified": True, "session_nonce": "n123"}

        guard = BolyraGuard(
            session=session,
            on_failure="raise",
            session_ttl_seconds=1,
        )
        # Set auth timestamp to the past
        guard._auth_timestamp = time.time() - 10

        step = SimpleNamespace(tool="some_tool")
        with pytest.raises(BolyraAuthError, match="expired"):
            guard.step_callback(step)

    def test_fresh_session_passes(self):
        """Fresh session within TTL passes."""
        from bolyra_crewai.guard import BolyraGuard
        from bolyra_crewai.session import BolyraSession
        import time

        session = BolyraSession()
        session._auth_result = {"verified": True, "session_nonce": "n123"}

        guard = BolyraGuard(
            session=session,
            on_failure="raise",
            session_ttl_seconds=3600,
        )
        guard._auth_timestamp = time.time()

        step = SimpleNamespace(tool="some_tool")
        # Should not raise
        guard.step_callback(step)


class TestBolyraGuardTools:
    """Tests for pre-execution guard_tools wrapping."""

    def _make_mock_tool(self, name="some_tool"):
        """Create a mock tool with a _run method."""
        tool = SimpleNamespace(name=name)
        tool._run = lambda **kwargs: json.dumps({"result": "ok"})
        return tool

    def test_guard_tools_blocks_unauthenticated(self):
        """Wrapped tool raises BolyraAuthError before execution."""
        from bolyra_crewai.guard import BolyraGuard, BolyraAuthError

        guard = BolyraGuard(on_failure="raise")
        tool = self._make_mock_tool()
        guard.guard_tools([tool])

        with pytest.raises(BolyraAuthError, match="requires"):
            tool._run()

    def test_guard_tools_allows_authenticated(self):
        """Wrapped tool executes normally when session is authenticated."""
        from bolyra_crewai.guard import BolyraGuard
        from bolyra_crewai.session import BolyraSession

        session = BolyraSession()
        session._auth_result = {"verified": True, "session_nonce": "n"}

        guard = BolyraGuard(session=session, on_failure="raise")
        tool = self._make_mock_tool()
        guard.guard_tools([tool])

        result = json.loads(tool._run())
        assert result["result"] == "ok"

    def test_guard_tools_skips_allowlisted(self):
        """Allowlisted tools are not wrapped."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="raise")
        tool = self._make_mock_tool(name="bolyra_authenticate")
        guard.guard_tools([tool])

        # Should not raise even without session
        result = json.loads(tool._run())
        assert result["result"] == "ok"

    def test_guard_tools_warn_returns_error_json(self):
        """Warn mode returns error JSON instead of raising."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="warn")
        tool = self._make_mock_tool()
        guard.guard_tools([tool])

        result = json.loads(tool._run())
        assert result["error"] is True
        assert "requires" in result["message"]

    def test_guard_tools_returns_same_list(self):
        """guard_tools returns the same list it was given."""
        from bolyra_crewai.guard import BolyraGuard

        guard = BolyraGuard(on_failure="skip")
        tools = [self._make_mock_tool()]
        result = guard.guard_tools(tools)
        assert result is tools
