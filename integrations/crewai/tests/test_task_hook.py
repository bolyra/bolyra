"""Tests for BolyraDelegationFlow (per-agent scoping + proof envelope audit trail)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any


# ---------------------------------------------------------------------------
# Shared mock helpers
# ---------------------------------------------------------------------------

def _make_auth_tool(verified: bool = True, session_nonce: str = "n123", scope_commitment: str = "sc456"):
    """Return a mock auth tool that returns a fixed JSON result."""
    class MockAuthTool:
        name = "bolyra_authenticate"

        def _run(self, **kwargs: Any) -> str:
            return json.dumps({
                "verified": verified,
                "status": "ok",
                "session_nonce": session_nonce,
                "scope_commitment": scope_commitment,
            })

    return MockAuthTool()


def _make_delegate_tool(delegated: bool = True, new_scope_commitment: str = "sc789", delegation_nullifier: str = "null1"):
    """Return a mock delegate tool."""
    class MockDelegateTool:
        name = "bolyra_delegate"

        def _run(self, **kwargs: Any) -> str:
            return json.dumps({
                "delegated": delegated,
                "status": "ok",
                "new_scope_commitment": new_scope_commitment,
                "delegation_nullifier": delegation_nullifier,
            })

    return MockDelegateTool()


def _make_session(authenticated: bool = False, delegate_succeeds: bool = True):
    """Return a BolyraSession wired with mock tools."""
    from bolyra_crewai import BolyraSession

    auth_tool = _make_auth_tool()
    delegate_tool = _make_delegate_tool(delegated=delegate_succeeds)
    session = BolyraSession(auth_tool=auth_tool, delegate_tool=delegate_tool)
    if authenticated:
        session.authenticate()
    return session


def _make_tool(name: str = "my_tool"):
    """Return a SimpleNamespace that looks like a CrewAI BaseTool."""
    calls = []

    def _run(**kwargs):
        calls.append(kwargs)
        return "tool result"

    tool = SimpleNamespace(name=name, _run=_run, _calls=calls)
    return tool


def _make_task_output(agent: str = "Researcher", description: str = "do research"):
    """Return a SimpleNamespace that looks like CrewAI TaskOutput."""
    return SimpleNamespace(agent=agent, description=description)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBolyraDelegationFlow:

    def test_tools_for_creates_guarded_tools_blocks_unauthenticated(self):
        """tools_for wraps tools; unauthenticated calls are blocked."""
        from bolyra_crewai.guard import BolyraAuthError
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=False)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
            on_failure="raise",
        )
        tool = _make_tool("my_tool")
        flow.tools_for("Researcher", [tool])

        # Unauthenticated call should raise BolyraAuthError
        try:
            tool._run()
            assert False, "Expected BolyraAuthError"
        except BolyraAuthError:
            pass

    def test_tools_for_unknown_role_raises_value_error(self):
        """tools_for raises ValueError for an unknown agent role (fail-closed)."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session()
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
        )
        try:
            flow.tools_for("UnknownBot", [_make_tool()])
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "UnknownBot" in str(exc)
            assert "Researcher" in str(exc)

    def test_tools_for_allows_authenticated_execution(self):
        """tools_for allows tool execution when session is authenticated."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=True)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
            on_failure="raise",
        )
        tool = _make_tool("my_tool")
        flow.tools_for("Researcher", [tool])

        result = tool._run()
        assert result == "tool result"

    def test_task_callback_appends_audit_entry(self):
        """task_callback appends an audit entry after a task completes."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=True)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
            emit_envelopes=False,
        )

        flow.task_callback(_make_task_output(agent="Researcher", description="gather data"))

        trail = flow.audit_trail
        assert len(trail) == 1
        entry = trail[0]
        assert entry["agent"] == "Researcher"
        assert entry["task"] == "gather data"
        assert entry["permissions"] == ["read_data"]
        assert entry["error"] is None
        assert entry["delegation"] is not None
        assert entry["delegation"]["delegated"] is True

    def test_task_callback_wraps_delegation_in_envelope(self):
        """task_callback produces an envelope dict when emit_envelopes=True and delegation succeeds."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=True)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Writer": ["read_data", "write_data"]},
            emit_envelopes=True,
        )

        flow.task_callback(_make_task_output(agent="Writer", description="write report"))

        trail = flow.audit_trail
        assert len(trail) == 1
        entry = trail[0]
        # Envelope should be present (bolyra.envelope is available in this venv)
        assert entry["envelope"] is not None
        assert entry["envelope"]["circuit"]["name"] == "Delegation"
        assert entry["envelope"]["proofType"] == "groth16"

    def test_task_callback_graceful_failure_no_crash(self):
        """task_callback produces an error entry on delegation failure without crashing."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow
        from bolyra_crewai import BolyraSession

        class BrokenDelegateTool:
            name = "bolyra_delegate"

            def _run(self, **kwargs: Any) -> str:
                raise RuntimeError("network error")

        session = BolyraSession(
            auth_tool=_make_auth_tool(),
            delegate_tool=BrokenDelegateTool(),
        )
        session.authenticate()

        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
        )

        # Must not raise
        flow.task_callback(_make_task_output(agent="Researcher"))

        trail = flow.audit_trail
        assert len(trail) == 1
        assert trail[0]["error"] is not None
        assert "network error" in trail[0]["error"]

    def test_task_callback_skips_unauthenticated_adds_error_entry(self):
        """task_callback adds error entry when session is not authenticated."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=False)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
        )

        flow.task_callback(_make_task_output(agent="Researcher"))

        trail = flow.audit_trail
        assert len(trail) == 1
        assert trail[0]["error"] is not None
        assert "not authenticated" in trail[0]["error"].lower()
        assert trail[0]["delegation"] is None

    def test_task_callback_silently_skips_unknown_agent_role(self):
        """task_callback silently skips task output from an unscoped agent."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=True)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
        )

        # UnknownBot is not in agent_scopes -- should be silently skipped
        flow.task_callback(_make_task_output(agent="UnknownBot"))

        assert flow.audit_trail == []

    def test_audit_trail_starts_empty(self):
        """A fresh BolyraDelegationFlow has an empty audit trail."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session()
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
        )
        assert flow.audit_trail == []

    def test_audit_trail_returns_copy_not_reference(self):
        """audit_trail returns a copy; mutating it does not affect internal state."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=True)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={"Researcher": ["read_data"]},
            emit_envelopes=False,
        )
        flow.task_callback(_make_task_output(agent="Researcher"))

        trail_copy = flow.audit_trail
        trail_copy.clear()

        # Internal state should be unchanged
        assert len(flow.audit_trail) == 1

    def test_end_to_end_two_agents_two_audit_entries(self):
        """End-to-end: authenticate, two mock tasks, verify 2 audit entries with correct agents."""
        from bolyra_crewai.task_hook import BolyraDelegationFlow

        session = _make_session(authenticated=True)
        flow = BolyraDelegationFlow(
            session=session,
            agent_scopes={
                "Researcher": ["read_data"],
                "Writer": ["read_data", "write_data"],
            },
            emit_envelopes=False,
        )

        # Simulate two tasks completing
        flow.task_callback(_make_task_output(agent="Researcher", description="find papers"))
        flow.task_callback(_make_task_output(agent="Writer", description="write summary"))

        trail = flow.audit_trail
        assert len(trail) == 2

        researcher_entry = next(e for e in trail if e["agent"] == "Researcher")
        writer_entry = next(e for e in trail if e["agent"] == "Writer")

        assert researcher_entry["permissions"] == ["read_data"]
        assert researcher_entry["task"] == "find papers"
        assert researcher_entry["error"] is None

        assert writer_entry["permissions"] == ["read_data", "write_data"]
        assert writer_entry["task"] == "write summary"
        assert writer_entry["error"] is None

        # Both should have delegation results
        assert researcher_entry["delegation"]["delegated"] is True
        assert writer_entry["delegation"]["delegated"] is True
