"""CrewAI tool for Bolyra scoped permission delegation.

Proper BaseTool subclass for delegating a subset of permissions
to another agent with cryptographic scope narrowing.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field

from bolyra_crewai._compat import BaseTool, check_crewai_available
from bolyra_crewai.types import DelegationResult, parse_permissions

check_crewai_available()


class BolyraDelegateInput(BaseModel):
    """Input schema for BolyraDelegateTool."""

    delegatee_id: str = Field(
        description="Credential commitment of the agent to delegate to",
    )
    permissions: str = Field(
        description=(
            "Comma-separated permission flags to delegate, e.g. "
            "'read_data, write_data'"
        ),
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
    """Scoped permission delegation tool for CrewAI agents.

    Delegates a subset of this agent's permissions to another agent
    with cryptographic scope narrowing. The delegatee cannot exceed
    the permissions granted. Requires a prior successful handshake
    (the session_nonce and scope_commitment bind delegation to an
    authenticated session).

    Note: The ``permissions`` input is a comma-separated string (not a list)
    because CrewAI LLM agents are more reliable at producing single string
    arguments than JSON arrays. The tool splits on commas internally.

    Example::

        from bolyra_crewai import BolyraDelegateTool

        delegate = BolyraDelegateTool(
            agent_permissions=["read_data", "write_data"],
        )
        agent = Agent(
            role="Delegation Manager",
            tools=[delegate],
            goal="Delegate scoped permissions to sub-agents",
        )
    """

    name: str = "bolyra_delegate"
    description: str = (
        "Delegate a subset of this agent's permissions to another agent "
        "with cryptographic scope narrowing. The delegatee cannot exceed "
        "the permissions granted. Requires a prior successful handshake. "
        "Pass permissions as a comma-separated string, e.g. 'read_data, write_data'."
    )
    args_schema: type[BaseModel] = BolyraDelegateInput

    # Configuration
    agent_permissions: list[str] = ["read_data"]
    operator_key: str | None = None

    def _run(
        self,
        delegatee_id: str = "0",
        permissions: str = "",
        expiry_seconds: int = 3600,
        session_nonce: str = "0",
        scope_commitment: str = "0",
    ) -> str:
        """Execute scoped delegation.

        Returns a JSON string with the delegation result (CrewAI convention).
        """
        # Parse comma-separated permissions
        try:
            requested = parse_permissions(permissions)
        except ValueError as e:
            return DelegationResult(
                delegated=False,
                status="error",
                message=str(e),
            ).to_json()

        if not requested:
            return DelegationResult(
                delegated=False,
                status="error",
                message="No permissions specified for delegation.",
            ).to_json()

        # Scope escalation check: cannot delegate what you don't hold
        held = [p.strip().lower() for p in self.agent_permissions]
        invalid = [p for p in requested if p not in held]
        if invalid:
            return DelegationResult(
                delegated=False,
                status="error",
                message=f"Cannot delegate permissions not held: {invalid}",
            ).to_json()

        try:
            import hashlib

            from bolyra.delegation import delegate, verify_delegation
            from bolyra.identity import (
                create_agent_credential,
                create_dev_identities,
                permissions_to_bitmask,
            )
            from bolyra.types import Permission

            _perm_map = {p.name.lower(): p for p in Permission}
            delegatee_perms = []
            for p_str in requested:
                key = p_str.strip().lower()
                if key not in _perm_map:
                    return DelegationResult(
                        delegated=False,
                        status="error",
                        message=f"Unknown permission: '{p_str}'",
                    ).to_json()
                delegatee_perms.append(_perm_map[key])

            delegatee_scope = permissions_to_bitmask(delegatee_perms)

            perm_enums = [Permission[p.strip().upper()] for p in self.agent_permissions]
            bitmask = permissions_to_bitmask(perm_enums)

            if self.operator_key:
                # Production path: use real operator key
                operator_key_int = int(self.operator_key, 16)
                model_hash_int = int(
                    hashlib.sha256(b"delegator").hexdigest()[:16], 16
                )
                expiry_ts = int(time.time()) + 86400
                delegator = create_agent_credential(
                    model_hash_int, operator_key_int, perm_enums, expiry_ts
                )
            else:
                # Dev path: use dev identities
                _human, delegator, operator_key_int = create_dev_identities(
                    permission_bitmask=bitmask,
                )

            nonce_int = int(session_nonce)
            commitment_int = int(scope_commitment)
            delegatee_commitment = (
                int(delegatee_id, 16)
                if delegatee_id.startswith("0x")
                else int(delegatee_id)
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

            if not delegation_result.verified:
                return DelegationResult(
                    delegated=False,
                    status="verification_failed",
                    message="Delegation proof verification failed.",
                ).to_json()

            return DelegationResult(
                delegated=True,
                status="ok",
                delegatee_id=delegatee_id,
                permissions=requested,
                expiry_seconds=expiry_seconds,
                new_scope_commitment=str(
                    delegation_result.new_scope_commitment
                ),
                delegation_nullifier=str(
                    delegation_result.delegation_nullifier
                ),
            ).to_json()

        except ImportError as e:
            return DelegationResult(
                delegated=False,
                status="error",
                message=(
                    f"Bolyra Python SDK not installed: {e}. "
                    "Install with: pip install bolyra"
                ),
            ).to_json()
        except Exception as e:
            return DelegationResult(
                delegated=False,
                status="error",
                message=f"Bolyra delegation failed: {e}.",
            ).to_json()
