"""LangChain tool for Bolyra scoped permission delegation.

Proper BaseTool subclass for delegating a subset of permissions
to another agent with cryptographic scope narrowing.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from bolyra_langchain._compat import (
    BaseTool,
    CallbackManagerForToolRun,
    AsyncCallbackManagerForToolRun,
    check_langchain_available,
)
from bolyra_langchain.types import DelegationResult

check_langchain_available()


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
        default="0",
        description="Session nonce from a prior successful handshake",
    )
    scope_commitment: str = Field(
        default="0",
        description="Scope commitment from the prior handshake result",
    )


class BolyraDelegateTool(BaseTool):
    """Scoped permission delegation tool for LangChain agents.

    Delegates a subset of this agent's permissions to another agent
    with cryptographic scope narrowing. The delegatee cannot exceed
    the permissions granted. Requires a prior successful handshake
    (the session_nonce and scope_commitment bind delegation to an
    authenticated session).

    Example::

        from bolyra_langchain import BolyraDelegateTool

        delegate = BolyraDelegateTool(
            agent_permissions=["read_data", "write_data", "financial_small"],
        )
        result = delegate.invoke({
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
    args_schema: type[BaseModel] = BolyraDelegateInput

    # Configuration
    agent_permissions: list[str] = ["read_data"]
    operator_key: Optional[str] = None

    def _run(
        self,
        delegatee_id: str = "0",
        permissions: list[str] | None = None,
        expiry_seconds: int = 3600,
        session_nonce: str = "0",
        scope_commitment: str = "0",
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> dict[str, Any]:
        """Execute scoped delegation."""
        if permissions is None:
            permissions = []

        # Scope escalation check
        invalid = [p for p in permissions if p not in self.agent_permissions]
        if invalid:
            return DelegationResult(
                delegated=False, status="error",
                message=f"Cannot delegate permissions not held: {invalid}",
            ).to_dict()

        if run_manager:
            run_manager.on_text(f"Starting Bolyra delegation to {delegatee_id}")

        try:
            from bolyra.delegation import delegate, verify_delegation
            from bolyra.identity import create_dev_identities, permissions_to_bitmask
            from bolyra.types import Permission

            _perm_map = {p.name.lower(): p for p in Permission}
            delegatee_perms = []
            for p_str in permissions:
                key = p_str.strip().lower()
                if key not in _perm_map:
                    return DelegationResult(
                        delegated=False, status="error",
                        message=f"Unknown permission: '{p_str}'",
                    ).to_dict()
                delegatee_perms.append(_perm_map[key])

            delegatee_scope = permissions_to_bitmask(delegatee_perms)

            # Use dev identities (production delegation requires credential persistence)
            perm_enums = [Permission[p.upper()] for p in self.agent_permissions]
            bitmask = permissions_to_bitmask(perm_enums)
            _human, delegator, operator_key_int = create_dev_identities(
                permission_bitmask=bitmask,
            )

            nonce_int = int(session_nonce)
            commitment_int = int(scope_commitment)
            delegatee_commitment = (
                int(delegatee_id, 16) if delegatee_id.startswith("0x") else int(delegatee_id)
            )

            delegatee_expiry = min(
                int(time.time()) + expiry_seconds,
                delegator.expiry_timestamp,
            )

            current_timestamp = int(time.time())

            proof, result = delegate(
                delegator=delegator,
                delegator_operator_private_key=operator_key_int,
                delegatee_commitment=delegatee_commitment,
                delegatee_scope=delegatee_scope,
                delegatee_expiry=delegatee_expiry,
                previous_scope_commitment=commitment_int,
                session_nonce=nonce_int,
                current_timestamp=current_timestamp,
            )

            delegation_result = verify_delegation(
                proof=proof,
                previous_scope_commitment=commitment_int,
                session_nonce=nonce_int,
                current_timestamp=current_timestamp,
            )

            return DelegationResult(
                delegated=True, status="ok",
                delegatee_id=delegatee_id,
                permissions=permissions,
                expiry_seconds=expiry_seconds,
                new_scope_commitment=str(delegation_result.new_scope_commitment),
                delegation_nullifier=str(delegation_result.delegation_nullifier),
            ).to_dict()

        except ImportError as e:
            return DelegationResult(
                delegated=False, status="error",
                message=f"Bolyra Python SDK not installed: {e}. Install with: pip install bolyra",
            ).to_dict()
        except Exception as e:
            return DelegationResult(
                delegated=False, status="error",
                message=f"Bolyra delegation failed: {e}.",
            ).to_dict()

    async def _arun(
        self,
        delegatee_id: str = "0",
        permissions: list[str] | None = None,
        expiry_seconds: int = 3600,
        session_nonce: str = "0",
        scope_commitment: str = "0",
        run_manager: AsyncCallbackManagerForToolRun | None = None,
    ) -> dict[str, Any]:
        """Async version -- runs sync in executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._run, delegatee_id, permissions, expiry_seconds,
            session_nonce, scope_commitment, run_manager
        )
