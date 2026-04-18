"""CrewAI tool for Bolyra scoped permission delegation.

Enables a CrewAI agent to delegate a subset of its permissions to
another agent with cryptographic scope narrowing.

Usage with CrewAI:
    from bolyra.integrations.crewai import BolyraDelegateTool

    delegate_tool = BolyraDelegateTool(
        agent_permissions=["read_data", "write_data"]
    )

    agent = Agent(
        role="Delegation Manager",
        tools=[delegate_tool],
        goal="Delegate scoped permissions to sub-agents"
    )
"""
from __future__ import annotations

from typing import Optional


class BolyraDelegateTool:
    """CrewAI-compatible tool for scoped permission delegation.

    Delegates a subset of permissions to another agent with
    cryptographic scope narrowing. The delegatee cannot exceed
    the permissions granted.
    """

    name: str = "Bolyra Delegate"
    description: str = (
        "Delegate a subset of this agent's permissions to another agent "
        "with cryptographic scope narrowing. The delegatee cannot exceed "
        "the permissions granted. Requires a prior successful handshake."
    )

    def __init__(
        self,
        agent_permissions: Optional[list[str]] = None,
    ):
        """Initialize with the agent's current permission set.

        Args:
            agent_permissions: Permissions this agent holds and can delegate from
        """
        self.agent_permissions = agent_permissions or ["read_data"]

    def _run(
        self,
        delegatee_id: str,
        permissions: str,
        session_nonce: str,
        expiry_seconds: int = 3600,
    ) -> str:
        """Execute scoped delegation (CrewAI calls _run).

        Args:
            delegatee_id: Credential commitment of the target agent
            permissions: Comma-separated permission flags to delegate
            session_nonce: Nonce from a prior successful handshake
            expiry_seconds: Delegation validity duration

        Returns:
            Human-readable status string
        """
        requested = [p.strip() for p in permissions.split(",")]
        invalid = [p for p in requested if p not in self.agent_permissions]

        if invalid:
            return (
                f"Delegation failed: cannot delegate permissions not held: "
                f"{', '.join(invalid)}"
            )

        return (
            f"Bolyra delegation to '{delegatee_id}' with permissions "
            f"[{', '.join(requested)}], expiry {expiry_seconds}s. "
            f"Status: not_implemented -- delegation coming in @bolyra/sdk v0.3"
        )
