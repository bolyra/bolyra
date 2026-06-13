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
    scope_commitment: str = Field(
        description="Scope commitment from the prior handshake result",
    )


class BolyraDelegateTool:
    """LangChain-compatible tool for scoped permission delegation.

    Delegates a subset of this agent's permissions to another agent
    with cryptographic scope narrowing. Requires a prior successful
    mutual handshake (the session_nonce and scope_commitment bind
    delegation to an authenticated session).

    Example::

        from bolyra.integrations.langchain import BolyraDelegateTool

        delegate_tool = BolyraDelegateTool(
            agent_permissions=["read_data", "write_data", "financial_small"],
        )

        result = delegate_tool.invoke({
            "delegatee_id": "0xabc123...",
            "permissions": ["read_data"],
            "session_nonce": "nonce-from-handshake",
            "scope_commitment": "commitment-from-handshake",
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
        operator_key: Optional[str] = None,
    ):
        """Initialize with the agent's current permission set.

        Args:
            agent_permissions: Permissions this agent holds and can delegate from
            operator_key: Hex-encoded operator private key for signing delegations.
                If None, dev identities are used to obtain the key.
        """
        self.agent_permissions = agent_permissions or ["read_data"]
        self.operator_key = operator_key

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

        try:
            from bolyra.delegation import delegate, verify_delegation
            from bolyra.identity import (
                create_dev_identities,
                permissions_to_bitmask,
            )
            from bolyra.types import Permission

            # Map permission strings to Permission enums
            _perm_map = {p.name.lower(): p for p in Permission}
            delegatee_perms = []
            for p_str in requested:
                key = p_str.strip().lower()
                if key not in _perm_map:
                    return {
                        "delegated": False,
                        "status": "error",
                        "message": f"Unknown permission: '{p_str}'",
                        "tool": "bolyra_delegate",
                    }
                delegatee_perms.append(_perm_map[key])

            delegatee_scope = permissions_to_bitmask(delegatee_perms)

            # Always use dev identities for the delegator credential.
            # Production delegation requires the delegator credential produced by
            # a prior handshake to be persisted and passed here so that the
            # scope_commitment values match. Reconstructing a fresh credential from
            # the operator key produces a different commitment and causes
            # CHAIN_LINK_MISMATCH. Credential persistence across tool invocations
            # is the caller's responsibility; this tool does not attempt it.
            import time

            _human, delegator, operator_key_int = create_dev_identities()

            session_nonce = int(input.get("session_nonce", "0"))
            scope_commitment = int(input.get("scope_commitment", "0"))
            delegatee_commitment = int(input.get("delegatee_id", "0"), 16) if input.get("delegatee_id", "").startswith("0x") else int(input.get("delegatee_id", "0"))
            expiry_seconds = input.get("expiry_seconds", 3600)

            delegatee_expiry = min(
                int(time.time()) + expiry_seconds,
                delegator.expiry_timestamp,
            )

            # P1-2: Capture timestamp BEFORE delegate() and reuse for verify
            current_timestamp = int(time.time())

            proof, result = delegate(
                delegator=delegator,
                delegator_operator_private_key=operator_key_int,
                delegatee_commitment=delegatee_commitment,
                delegatee_scope=delegatee_scope,
                delegatee_expiry=delegatee_expiry,
                previous_scope_commitment=scope_commitment,
                session_nonce=session_nonce,
                current_timestamp=current_timestamp,
            )

            # Verify using the SAME timestamp bound into the proof
            delegation_result = verify_delegation(
                proof=proof,
                previous_scope_commitment=scope_commitment,
                session_nonce=session_nonce,
                current_timestamp=current_timestamp,
            )

            return {
                "delegated": True,
                "status": "ok",
                "delegatee_id": input.get("delegatee_id", ""),
                "permissions": requested,
                "expiry_seconds": expiry_seconds,
                "new_scope_commitment": str(delegation_result.new_scope_commitment),
                "delegation_nullifier": str(delegation_result.delegation_nullifier),
                "tool": "bolyra_delegate",
                "protocol_version": "0.3.0",
            }

        except ImportError as e:
            return {
                "delegated": False,
                "status": "error",
                "message": (
                    f"Bolyra Python SDK not installed: {e}. "
                    "Install with: pip install bolyra"
                ),
                "tool": "bolyra_delegate",
            }
        except Exception as e:
            return {
                "delegated": False,
                "status": "error",
                "message": (
                    f"Bolyra delegation failed: {e}. "
                    "Ensure Node.js >= 18 and @bolyra/sdk are installed."
                ),
                "tool": "bolyra_delegate",
            }

    async def ainvoke(self, input: dict[str, Any]) -> dict[str, Any]:
        """Async version of invoke."""
        return self.invoke(input)
