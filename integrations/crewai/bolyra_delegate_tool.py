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

import time
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
        operator_key: Optional[str] = None,
    ):
        """Initialize with the agent's current permission set.

        Args:
            agent_permissions: Permissions this agent holds and can delegate from
            operator_key: Hex-encoded operator private key for signing delegations.
                If None, dev identities are used.
        """
        self.agent_permissions = agent_permissions or ["read_data"]
        self.operator_key = operator_key

    def _run(
        self,
        delegatee_id: str,
        permissions: str,
        session_nonce: str,
        scope_commitment: str = "0",
        expiry_seconds: int = 3600,
    ) -> str:
        """Execute scoped delegation (CrewAI calls _run).

        Args:
            delegatee_id: Credential commitment of the target agent
            permissions: Comma-separated permission flags to delegate
            session_nonce: Nonce from a prior successful handshake
            scope_commitment: Scope commitment from the prior handshake
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
                    return f"Delegation failed: unknown permission '{p_str}'"
                delegatee_perms.append(_perm_map[key])

            delegatee_scope = permissions_to_bitmask(delegatee_perms)

            # P2-1: Use consistent identity mode -- don't mix dev/production
            import hashlib

            if self.operator_key is not None:
                # Production: create a real agent credential with the operator key
                from bolyra.identity import create_agent_credential
                operator_key_int = int(self.operator_key, 16)
                model_hash_int = int(
                    hashlib.sha256(b"delegation-agent").hexdigest()[:16], 16
                )
                agent_perm_enums = []
                for p_str in self.agent_permissions:
                    key = p_str.strip().lower()
                    if key in _perm_map:
                        agent_perm_enums.append(_perm_map[key])
                expiry = int(time.time()) + 86400
                delegator = create_agent_credential(
                    model_hash_int, operator_key_int, agent_perm_enums, expiry
                )
            else:
                # Dev mode: use dev identities entirely
                _human, delegator, operator_key_int = create_dev_identities()

            nonce_int = int(session_nonce)
            scope_commitment_int = int(scope_commitment)
            delegatee_commitment = int(delegatee_id, 16) if delegatee_id.startswith("0x") else int(delegatee_id)

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
                previous_scope_commitment=scope_commitment_int,
                session_nonce=nonce_int,
                current_timestamp=current_timestamp,
            )

            # Verify using the SAME timestamp bound into the proof
            delegation_result = verify_delegation(
                proof=proof,
                previous_scope_commitment=scope_commitment_int,
                session_nonce=nonce_int,
                current_timestamp=current_timestamp,
            )

            return (
                f"Bolyra delegation VERIFIED to '{delegatee_id}' with permissions "
                f"[{', '.join(requested)}], expiry {expiry_seconds}s. "
                f"New scope commitment: {delegation_result.new_scope_commitment}. "
                f"Delegation nullifier: {delegation_result.delegation_nullifier}."
            )

        except ImportError as e:
            return (
                f"Delegation failed: Python SDK not installed ({e}). "
                "Install with: pip install bolyra"
            )
        except Exception as e:
            return (
                f"Delegation failed: {e}. "
                "Ensure Node.js >= 18 and @bolyra/sdk are installed."
            )
