"""LangChain tool for Bolyra scoped permission delegation.

Enables a LangChain agent to delegate a subset of its permissions to
another agent with cryptographic scope narrowing. The delegatee cannot
exceed the permissions granted.

Usage:
    from bolyra.integrations.langchain import BolyraDelegateTool

    tools = [BolyraDelegateTool(agent_permissions=["read_data", "write_data"])]
    agent = create_react_agent(llm, tools)
"""
from __future__ import annotations

from typing import Any, Optional, Type

from pydantic import BaseModel, Field


class BolyraDelegateInput(BaseModel):
    """Input schema for BolyraDelegateTool."""

    delegatee_id: str = Field(
        description="Credential commitment of the agent to delegate to",
    )
    permissions: list[str] = Field(
        description="Subset of current permissions to delegate",
    )
    expiry_seconds: int = Field(
        default=3600,
        description="Delegation validity duration in seconds",
    )
    session_nonce: str = Field(
        description="Session nonce from a prior successful handshake",
    )


class BolyraDelegateTool:
    """LangChain-compatible tool for scoped permission delegation.

    Delegates a subset of this agent's permissions to another agent
    with cryptographic scope narrowing. Requires a prior successful
    mutual handshake (the session_nonce binds delegation to an
    authenticated session).

    Example::

        from bolyra.integrations.langchain import BolyraDelegateTool

        delegate_tool = BolyraDelegateTool(
            agent_permissions=["read_data", "write_data", "financial_small"],
        )

        result = delegate_tool.invoke({
            "delegatee_id": "0xabc123...",
            "permissions": ["read_data"],
            "session_nonce": "nonce-from-handshake",
        })
    """

    name: str = "bolyra_delegate"
    description: str = (
        "Delegate a subset of this agent's permissions to another agent "
        "with cryptographic scope narrowing. The delegatee cannot exceed "
        "the permissions granted. Requires a prior successful handshake."
    )
    args_schema: Type[BaseModel] = BolyraDelegateInput

    def __init__(
        self,
        agent_permissions: Optional[list[str]] = None,
    ):
        """Initialize with the agent's current permission set.

        Args:
            agent_permissions: Permissions this agent holds and can delegate from
        """
        self.agent_permissions = agent_permissions or ["read_data"]

    def invoke(self, input: dict[str, Any]) -> dict[str, Any]:
        """Execute scoped delegation.

        Returns a structured result with delegation status and
        the narrowed permission set.
        """
        requested = input.get("permissions", [])
        invalid = [p for p in requested if p not in self.agent_permissions]

        if invalid:
            return {
                "delegated": False,
                "status": "error",
                "message": f"Cannot delegate permissions not held: {invalid}",
                "tool": "bolyra_delegate",
            }

        return {
            "delegated": False,
            "status": "not_implemented",
            "message": "Delegation coming in @bolyra/sdk v0.3",
            "delegatee_id": input.get("delegatee_id", ""),
            "permissions": requested,
            "expiry_seconds": input.get("expiry_seconds", 3600),
            "tool": "bolyra_delegate",
            "protocol_version": "0.2.0",
        }

    async def ainvoke(self, input: dict[str, Any]) -> dict[str, Any]:
        """Async version of invoke."""
        return self.invoke(input)
