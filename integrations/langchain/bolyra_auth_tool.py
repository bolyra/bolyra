"""LangChain tool for Bolyra mutual ZKP authentication.

Enables LangChain agents to perform mutual authentication with humans
or other agents before executing sensitive operations.

Usage:
    from bolyra.integrations.langchain import BolyraAuthTool

    tools = [BolyraAuthTool(agent_model_hash="gpt-4o", operator_key=key)]
    agent = create_react_agent(llm, tools)
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Optional, Type

from pydantic import BaseModel, Field


class BolyraAuthInput(BaseModel):
    """Input schema for BolyraAuthTool."""

    scope: str = Field(
        default="bolyra-handshake-v1",
        description="Authentication scope identifier. Same scope = same nullifier (Sybil detection).",
    )
    required_permissions: list[str] = Field(
        default_factory=lambda: ["read_data"],
        description=(
            "Permission flags to require from the counterparty. Options: "
            "read_data, write_data, financial_small, financial_medium, "
            "financial_unlimited, sign_on_behalf, sub_delegate, access_pii"
        ),
    )
    counterparty_type: str = Field(
        default="human",
        description="Type of counterparty to authenticate: 'human' or 'agent'",
    )


class BolyraAuthTool:
    """LangChain-compatible tool for mutual ZKP authentication.

    This tool enables an AI agent to cryptographically verify that its
    counterparty (human or another agent) satisfies required identity and
    permission policies -- without learning any private information beyond
    policy satisfaction.

    The tool wraps the Bolyra mutual handshake protocol:
    1. Agent generates a PLONK proof of its credential validity
    2. Counterparty generates a Groth16 proof of group membership
    3. Both proofs are verified (locally or on-chain)

    Example::

        from bolyra.integrations.langchain import BolyraAuthTool

        # Dev mode (uses fixed-seed dev identities -- never for production):
        auth_tool = BolyraAuthTool()

        # Production mode (inject human identity and operator key):
        auth_tool = BolyraAuthTool(
            agent_model_hash="gpt-4o",
            operator_key="0xdeadbeef...",
            permissions=["read_data", "write_data"],
            human_secret=12345,
        )

        # In a LangChain agent:
        result = auth_tool.invoke({"required_permissions": ["read_data"]})
        if result["verified"]:
            # Proceed with authenticated operation
            pass
    """

    name: str = "bolyra_authenticate"
    description: str = (
        "Perform mutual ZKP authentication with a human or AI agent. "
        "Verifies that both parties satisfy required identity and permission "
        "policies without revealing private information. Use this before "
        "executing any sensitive operation that requires verified identity."
    )
    args_schema: Type[BaseModel] = BolyraAuthInput

    def __init__(
        self,
        agent_model_hash: str = "default",
        operator_key: Optional[str] = None,
        permissions: Optional[list[str]] = None,
        expiry_seconds: int = 86400,
        human_secret: Optional[int] = None,
    ):
        """Initialize with agent credentials.

        Args:
            agent_model_hash: Hash identifying the AI model (e.g., "gpt-4o")
            operator_key: Hex-encoded EdDSA operator private key.
                If None, dev identities are used.
            permissions: List of permission flags for this agent
            expiry_seconds: Credential validity duration from now
            human_secret: Human secret for production mode. If None and
                operator_key is also None, dev identities are used.
        """
        self.agent_model_hash = agent_model_hash
        self.operator_key = operator_key
        self.permissions = permissions or ["read_data"]
        self.expiry_seconds = expiry_seconds
        self.human_secret = human_secret

    def invoke(self, input: dict[str, Any]) -> dict[str, Any]:
        """Execute mutual authentication.

        Returns a structured result with verification status, nullifiers,
        and scope commitment for downstream delegation.
        """
        try:
            from bolyra.identity import (
                create_agent_credential,
                create_dev_identities,
                create_human_identity,
            )
            from bolyra.handshake import prove_handshake, verify_handshake
            from bolyra.types import Permission

            scope = input.get("scope", "bolyra-handshake-v1")

            # Map string permission names to Permission enum values
            _perm_map = {p.name.lower(): p for p in Permission}
            perm_enums = []
            for p_str in self.permissions:
                key = p_str.strip().lower()
                if key not in _perm_map:
                    return {
                        "verified": False,
                        "status": "error",
                        "message": f"Unknown permission: '{p_str}'. "
                                   f"Valid: {list(_perm_map.keys())}",
                        "tool": "bolyra_authenticate",
                    }
                perm_enums.append(_perm_map[key])

            # Decide dev vs production mode
            use_dev = self.operator_key is None and self.human_secret is None

            if use_dev:
                human, agent, _op_key = create_dev_identities()
            else:
                # Production: create identities from provided keys
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
                    # Fallback: dev human identity with production agent
                    human, _, _ = create_dev_identities()

            # Generate scope int from scope string
            scope_int = int(hashlib.sha256(scope.encode()).hexdigest()[:16], 16)

            # Prove and verify handshake
            human_proof, agent_proof, nonce = prove_handshake(
                human, agent, scope=scope_int
            )
            result = verify_handshake(human_proof, agent_proof, nonce)

            return {
                "verified": result.verified,
                "status": "ok" if result.verified else "verification_failed",
                "human_nullifier": str(result.human_nullifier),
                "agent_nullifier": str(result.agent_nullifier),
                "session_nonce": str(result.session_nonce),
                "scope_commitment": str(result.scope_commitment),
                "scope": scope,
                "required_permissions": input.get("required_permissions", ["read_data"]),
                "counterparty_type": input.get("counterparty_type", "human"),
                "tool": "bolyra_authenticate",
                "protocol_version": "0.3.0",
            }

        except ImportError as e:
            return {
                "verified": False,
                "status": "error",
                "message": (
                    f"Bolyra Python SDK not installed: {e}. "
                    "Install with: pip install bolyra"
                ),
                "tool": "bolyra_authenticate",
            }
        except Exception as e:
            return {
                "verified": False,
                "status": "error",
                "message": (
                    f"Bolyra authentication failed: {e}. "
                    "Ensure Node.js >= 18 and @bolyra/sdk are installed: "
                    "npm install @bolyra/sdk && npx bolyra setup"
                ),
                "tool": "bolyra_authenticate",
            }

    async def ainvoke(self, input: dict[str, Any]) -> dict[str, Any]:
        """Async version of invoke."""
        return self.invoke(input)
