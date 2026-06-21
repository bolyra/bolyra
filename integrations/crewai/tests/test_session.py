"""Tests for BolyraSession (state management across tool calls)."""

from __future__ import annotations

import json

import pytest


class TestBolyraSession:
    """Session management tests -- uses mock tool results."""

    def test_initial_state(self):
        """Session starts unauthenticated."""
        from bolyra_crewai import BolyraSession

        session = BolyraSession()
        assert session.is_authenticated is False
        assert session.session_nonce is None
        assert session.scope_commitment is None
        assert session.auth_result is None
        assert session.delegation_chain == []

    def test_no_auth_tool_error(self):
        """Session without auth_tool returns error on authenticate."""
        from bolyra_crewai import BolyraSession

        session = BolyraSession()
        result = session.authenticate()
        assert result["verified"] is False
        assert "No auth_tool" in result["message"]

    def test_no_delegate_tool_error(self):
        """Session without delegate_tool returns error on delegate."""
        from bolyra_crewai import BolyraSession

        session = BolyraSession()
        result = session.delegate(delegatee_id="123", permissions="read_data")
        assert result["delegated"] is False
        assert "No delegate_tool" in result["message"]

    def test_no_sd_jwt_tool_error(self):
        """Session without sd_jwt_tool returns error on authorize."""
        from bolyra_crewai import BolyraSession

        session = BolyraSession()
        result = session.authorize(action="test", audience="aud")
        assert result["success"] is False
        assert "No sd_jwt_tool" in result["message"]

    def test_delegate_before_auth_error(self):
        """Delegating before authenticating returns error."""
        from bolyra_crewai import BolyraSession

        class MockDelegateTool:
            def _run(self, **kwargs):
                return json.dumps({"delegated": True, "status": "ok"})

        session = BolyraSession(delegate_tool=MockDelegateTool())
        result = session.delegate(delegatee_id="123", permissions="read_data")
        assert result["delegated"] is False
        assert "authenticate" in result["message"].lower()

    def test_auth_result_stored(self):
        """Successful auth stores result in session."""
        from bolyra_crewai import BolyraSession

        class MockAuthTool:
            def _run(self, **kwargs):
                return json.dumps({
                    "verified": True,
                    "status": "ok",
                    "session_nonce": "12345",
                    "scope_commitment": "67890",
                })

        session = BolyraSession(auth_tool=MockAuthTool())
        result = session.authenticate()
        assert result["verified"] is True
        assert session.is_authenticated is True
        assert session.session_nonce == "12345"
        assert session.scope_commitment == "67890"

    def test_delegate_uses_session_context(self):
        """Delegation auto-injects session_nonce and scope_commitment."""
        from bolyra_crewai import BolyraSession

        captured_kwargs = {}

        class MockAuthTool:
            def _run(self, **kwargs):
                return json.dumps({
                    "verified": True,
                    "status": "ok",
                    "session_nonce": "n123",
                    "scope_commitment": "sc456",
                })

        class MockDelegateTool:
            def _run(self, **kwargs):
                captured_kwargs.update(kwargs)
                return json.dumps({
                    "delegated": True,
                    "status": "ok",
                    "new_scope_commitment": "sc789",
                })

        session = BolyraSession(
            auth_tool=MockAuthTool(),
            delegate_tool=MockDelegateTool(),
        )
        session.authenticate()
        session.delegate(delegatee_id="0xabc", permissions="read_data")

        assert captured_kwargs["session_nonce"] == "n123"
        assert captured_kwargs["scope_commitment"] == "sc456"

    def test_delegation_chain_tracked(self):
        """Multiple delegations are tracked in chain order."""
        from bolyra_crewai import BolyraSession

        class MockAuthTool:
            def _run(self, **kwargs):
                return json.dumps({
                    "verified": True,
                    "status": "ok",
                    "session_nonce": "n",
                    "scope_commitment": "sc0",
                })

        call_count = 0

        class MockDelegateTool:
            def _run(self, **kwargs):
                nonlocal call_count
                call_count += 1
                return json.dumps({
                    "delegated": True,
                    "status": "ok",
                    "new_scope_commitment": f"sc{call_count}",
                })

        session = BolyraSession(
            auth_tool=MockAuthTool(),
            delegate_tool=MockDelegateTool(),
        )
        session.authenticate()
        session.delegate("a", "read_data")
        session.delegate("b", "read_data")

        assert len(session.delegation_chain) == 2
        assert session.scope_commitment == "sc2"

    def test_reset(self):
        """Reset clears all session state."""
        from bolyra_crewai import BolyraSession

        class MockAuthTool:
            def _run(self, **kwargs):
                return json.dumps({
                    "verified": True,
                    "status": "ok",
                    "session_nonce": "n",
                    "scope_commitment": "sc",
                })

        session = BolyraSession(auth_tool=MockAuthTool())
        session.authenticate()
        assert session.is_authenticated is True

        session.reset()
        assert session.is_authenticated is False
        assert session.auth_result is None
        assert session.delegation_chain == []

    def test_re_auth_resets_delegation_chain(self):
        """Re-authenticating resets the delegation chain."""
        from bolyra_crewai import BolyraSession

        class MockAuthTool:
            def _run(self, **kwargs):
                return json.dumps({
                    "verified": True,
                    "status": "ok",
                    "session_nonce": "n",
                    "scope_commitment": "sc0",
                })

        class MockDelegateTool:
            def _run(self, **kwargs):
                return json.dumps({
                    "delegated": True,
                    "status": "ok",
                    "new_scope_commitment": "sc1",
                })

        session = BolyraSession(
            auth_tool=MockAuthTool(),
            delegate_tool=MockDelegateTool(),
        )
        session.authenticate()
        session.delegate("a", "read_data")
        assert len(session.delegation_chain) == 1

        # Re-authenticate
        session.authenticate()
        assert len(session.delegation_chain) == 0

    def test_thread_safety(self):
        """Session is thread-safe."""
        import threading
        from bolyra_crewai import BolyraSession

        session = BolyraSession()
        errors = []

        def writer():
            try:
                for _ in range(100):
                    session._auth_result = {
                        "verified": True,
                        "session_nonce": "n",
                    }
                    session.reset()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
