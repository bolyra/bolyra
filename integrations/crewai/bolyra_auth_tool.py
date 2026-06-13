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

import hashlib
import time
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
        operator_key: Optional[str] = None,
        human_secret: Optional[int] = None,
        expiry_seconds: int = 86400,
    ):
        """Initialize with permission set.

        Args:
            permissions: Permission flags for this agent
            agent_model_hash: Hash identifying the AI model
            operator_key: Hex-encoded operator private key.
                If None, dev identities are used.
            human_secret: Human secret for production mode.
            expiry_seconds: Credential validity duration from now
        """
        self.permissions = permissions or ["read_data"]
        self.agent_model_hash = agent_model_hash
        self.operator_key = operator_key
        self.human_secret = human_secret
        self.expiry_seconds = expiry_seconds

    def _run(self, scope: str = "bolyra-handshake-v1") -> str:
        """Execute authentication (CrewAI calls _run).

        Args:
            scope: Authentication scope identifier

        Returns:
            Human-readable status string
        """
        try:
            from bolyra.identity import (
                create_agent_credential,
                create_dev_identities,
                create_human_identity,
            )
            from bolyra.handshake import prove_handshake, verify_handshake
            from bolyra.types import Permission

            # Map string permission names to Permission enum values
            _perm_map = {p.name.lower(): p for p in Permission}
            perm_enums = []
            for p_str in self.permissions:
                key = p_str.strip().lower()
                if key not in _perm_map:
                    return (
                        f"Bolyra authentication failed: unknown permission '{p_str}'. "
                        f"Valid: {list(_perm_map.keys())}"
                    )
                perm_enums.append(_perm_map[key])

            # Decide dev vs production mode
            use_dev = self.operator_key is None and self.human_secret is None

            if use_dev:
                human, agent, _op_key = create_dev_identities()
            else:
                model_hash_int = int(
                    hashlib.sha256(self.agent_model_hash.encode()).hexdigest()[:16], 16
                )
                operator_key_int = int(self.operator_key, 16) if self.operator_key else 0
                expiry = int(time.time()) + self.expiry_seconds

                agent = create_agent_credential(
                    model_hash_int, operator_key_int, perm_enums, expiry
                )

                if self.human_secret is not None:
                    human = create_human_identity(self.human_secret)
                else:
                    human, _, _ = create_dev_identities()

            # Generate scope int from scope string
            scope_int = int(hashlib.sha256(scope.encode()).hexdigest()[:16], 16)

            # Prove and verify handshake
            human_proof, agent_proof, nonce = prove_handshake(
                human, agent, scope=scope_int
            )
            result = verify_handshake(human_proof, agent_proof, nonce)

            if result.verified:
                # P1-1: Enforce required_permissions against agent bitmask
                # (CrewAI _run takes scope only; check self.permissions)
                from bolyra.identity import permissions_to_bitmask
                required_bitmask = permissions_to_bitmask(perm_enums)
                agent_bitmask = agent.permission_bitmask
                if (required_bitmask & agent_bitmask) != required_bitmask:
                    missing_bits = required_bitmask & ~agent_bitmask
                    missing_names = [
                        p.name.lower() for p in Permission
                        if (1 << int(p)) & missing_bits
                    ]
                    return (
                        f"Bolyra authentication FAILED: agent lacks required permissions: "
                        f"{missing_names}. Agent bitmask: {agent_bitmask}, "
                        f"required: {required_bitmask}."
                    )

                return (
                    f"Bolyra authentication VERIFIED with scope '{scope}'. "
                    f"Permissions: {', '.join(self.permissions)}. "
                    f"Session nonce: {result.session_nonce}. "
                    f"Scope commitment: {result.scope_commitment}. "
                    f"Human nullifier: {result.human_nullifier}. "
                    f"Agent nullifier: {result.agent_nullifier}."
                )
            else:
                return (
                    f"Bolyra authentication FAILED with scope '{scope}'. "
                    f"Verification returned false."
                )

        except ImportError as e:
            return (
                f"Bolyra authentication failed: Python SDK not installed ({e}). "
                "Install with: pip install bolyra"
            )
        except Exception as e:
            return (
                f"Bolyra authentication failed: {e}. "
                "Ensure Node.js >= 18 and @bolyra/sdk are installed: "
                "npm install @bolyra/sdk && npx bolyra setup"
            )
