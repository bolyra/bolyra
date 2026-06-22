"""CrewAI delegation flow -- per-agent permission scoping with proof envelope audit trail.

Combines BolyraGuard (pre-execution enforcement) with BolyraSession.delegate()
(post-execution provenance) into a single class that manages the full delegation
lifecycle across a CrewAI Crew run.

Usage::

    flow = BolyraDelegationFlow(
        session=session,
        agent_scopes={"Researcher": ["read_data"], "Writer": ["read_data", "write_data"]},
    )
    researcher_tools = flow.tools_for("Researcher", [sd_jwt_tool])
    crew = Crew(..., task_callback=flow.task_callback)
    # After crew runs:
    for entry in flow.audit_trail:
        print(entry)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from bolyra_crewai.guard import BolyraGuard

logger = logging.getLogger(__name__)


class BolyraDelegationFlow:
    """Manages per-agent permission scoping and delegation audit trail.

    Pre-execution: ``tools_for()`` wraps each agent's tools with a BolyraGuard
    scoped to that agent's allowed permissions.

    Post-execution: ``task_callback`` captures delegation proofs as proof
    envelopes after each task completes.

    Args:
        session: BolyraSession for authentication and delegation.
        agent_scopes: Maps agent role names to their allowed permissions.
            Example: {"Researcher": ["read_data"], "Writer": ["read_data", "write_data"]}
        emit_envelopes: Whether to wrap delegation proofs in ProofEnvelope
            format. Requires bolyra.envelope module. Default True.
        on_failure: BolyraGuard failure mode for tools_for(). Default "raise".
    """

    def __init__(
        self,
        session: Any,
        agent_scopes: dict[str, list[str]],
        *,
        emit_envelopes: bool = True,
        on_failure: str = "raise",
    ) -> None:
        self.session = session
        self.agent_scopes = agent_scopes
        self.emit_envelopes = emit_envelopes
        self.on_failure = on_failure
        self._audit_trail: list[dict[str, Any]] = []
        self._guards: dict[str, BolyraGuard] = {}

    @property
    def audit_trail(self) -> list[dict[str, Any]]:
        """List of delegation audit entries from this crew run."""
        return list(self._audit_trail)

    def tools_for(self, agent_role: str, tools: list[Any]) -> list[Any]:
        """Wrap tools with a BolyraGuard scoped to this agent's permissions.

        Args:
            agent_role: The agent's role name (must exist in agent_scopes).
            tools: List of CrewAI BaseTool instances.

        Returns:
            The same list with non-auth tools guarded.

        Raises:
            ValueError: If agent_role is not in agent_scopes (fail-closed).
        """
        if agent_role not in self.agent_scopes:
            raise ValueError(
                f"Unknown agent role: '{agent_role}'. "
                f"Known roles: {list(self.agent_scopes.keys())}"
            )

        guard = BolyraGuard(
            session=self.session,
            required_permissions=self.agent_scopes[agent_role],
            on_failure=self.on_failure,
        )
        guard.guard_tools(tools)
        self._guards[agent_role] = guard
        return tools

    def task_callback(self, task_output: Any) -> None:
        """CrewAI task_callback -- captures delegation proof after task completion.

        Extracts the agent role from the task output, delegates with the
        agent's scoped permissions, and wraps the result in a proof envelope.
        Appends to the audit trail. Never crashes the crew on failure.

        Args:
            task_output: CrewAI TaskOutput object.
        """
        agent_role = self._extract_agent_role(task_output)
        task_desc = self._extract_task_description(task_output)
        ts = datetime.now(timezone.utc).isoformat()

        if agent_role is None or agent_role not in self.agent_scopes:
            # Not a scoped agent or can't determine role -- skip silently
            return

        permissions = self.agent_scopes[agent_role]
        entry: dict[str, Any] = {
            "agent": agent_role,
            "task": task_desc or "unknown",
            "timestamp": ts,
            "permissions": permissions,
            "delegation": None,
            "envelope": None,
            "error": None,
        }

        try:
            if not self.session.is_authenticated:
                entry["error"] = "Session not authenticated -- skipping delegation"
                self._audit_trail.append(entry)
                return

            delegation_result = self.session.delegate(
                delegatee_id="0",
                permissions=", ".join(permissions),
            )
            entry["delegation"] = delegation_result

            if delegation_result.get("delegated") and self.emit_envelopes:
                envelope = self._wrap_in_envelope(delegation_result, agent_role)
                entry["envelope"] = envelope

        except Exception as exc:
            logger.warning(
                "BolyraDelegationFlow: delegation failed for %s: %s",
                agent_role, exc,
            )
            entry["error"] = str(exc)

        self._audit_trail.append(entry)

    def _wrap_in_envelope(
        self, delegation_result: dict[str, Any], agent_role: str
    ) -> dict[str, Any] | None:
        """Wrap a delegation result in a ProofEnvelope if possible."""
        try:
            from bolyra.envelope import envelope_from_proof

            # Build a proof-like dict from the delegation result.
            # The delegation result has new_scope_commitment and delegation_nullifier.
            # We wrap these as public signals in a Delegation envelope.
            proof_data = {
                "pi_a": ["0", "0"],
                "pi_b": [["0", "0"], ["0", "0"]],
                "pi_c": ["0", "0"],
            }
            signals = [
                delegation_result.get("new_scope_commitment", "0"),
                delegation_result.get("delegation_nullifier", "0"),
            ]

            envelope = envelope_from_proof(
                circuit_name="Delegation",
                proof=proof_data,
                public_signals=signals,
                circuit_version="0.4.0",
            )
            return envelope.to_dict()

        except ImportError:
            logger.debug("bolyra.envelope not available -- skipping envelope")
            return None
        except Exception as exc:
            logger.warning("Envelope wrapping failed: %s", exc)
            return None

    @staticmethod
    def _extract_agent_role(task_output: Any) -> str | None:
        """Extract agent role from CrewAI TaskOutput."""
        # CrewAI TaskOutput has .agent which is the agent's role string
        if hasattr(task_output, "agent"):
            agent = task_output.agent
            if isinstance(agent, str):
                return agent
            # Agent object may have .role attribute
            if hasattr(agent, "role"):
                return str(agent.role)
        if isinstance(task_output, dict):
            return task_output.get("agent")
        return None

    @staticmethod
    def _extract_task_description(task_output: Any) -> str | None:
        """Extract task description from CrewAI TaskOutput."""
        if hasattr(task_output, "description"):
            return str(task_output.description)[:200]
        if hasattr(task_output, "task"):
            task = task_output.task
            if hasattr(task, "description"):
                return str(task.description)[:200]
        if isinstance(task_output, dict):
            return task_output.get("description", "")[:200]
        return None
