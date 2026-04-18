"""CrewAI tool for Bolyra mutual ZKP authentication.

Enables CrewAI agents to perform mutual authentication with humans
or other agents before executing sensitive operations.

Usage with CrewAI:
    from bolyra.integrations.crewai import BolyraAuthTool

    auth_tool = BolyraAuthTool(permissions=["read_data", "write_data"])

    agent = Agent(
        role="Authenticated Data Analyst",
        tools=[auth_tool],
        goal="Analyze data only after mutual ZKP authentication"
    )
"""
from __future__ import annotations

from typing import Optional


class BolyraAuthTool:
    """CrewAI-compatible tool for mutual ZKP authentication.

    Wraps the Bolyra mutual handshake protocol for use in CrewAI
    multi-agent workflows. The agent generates a PLONK proof of
    credential validity, and the counterparty generates a Groth16
    proof of group membership.
    """

    name: str = "Bolyra Authenticate"
    description: str = (
        "Perform mutual ZKP authentication with a human or AI agent. "
        "Verifies identity and permissions without revealing private data. "
        "Use before any operation requiring verified counterparty identity."
    )

    def __init__(
        self,
        permissions: Optional[list[str]] = None,
        agent_model_hash: str = "default",
    ):
        """Initialize with permission set.

        Args:
            permissions: Permission flags for this agent
            agent_model_hash: Hash identifying the AI model
        """
        self.permissions = permissions or ["read_data"]
        self.agent_model_hash = agent_model_hash

    def _run(self, scope: str = "bolyra-handshake-v1") -> str:
        """Execute authentication (CrewAI calls _run).

        Args:
            scope: Authentication scope identifier

        Returns:
            Human-readable status string
        """
        return (
            f"Bolyra authentication initiated with scope '{scope}'. "
            f"Permissions: {', '.join(self.permissions)}. "
            f"Status: not_implemented -- requires @bolyra/sdk circuit artifacts. "
            f"Install: npm install @bolyra/sdk && npx bolyra setup"
        )
