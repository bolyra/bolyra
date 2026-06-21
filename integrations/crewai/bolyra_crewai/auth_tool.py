"""CrewAI tool for Bolyra mutual ZKP authentication.

Proper BaseTool subclass with Pydantic v2 args_schema and CrewAI
string-return convention.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from bolyra_crewai._compat import BaseTool, check_crewai_available
from bolyra_crewai.types import AuthResult, is_dev_mode_allowed

check_crewai_available()


class BolyraAuthInput(BaseModel):
    """Input schema for BolyraAuthTool."""

    scope: str = Field(
        default="bolyra-handshake-v1",
        description="Authentication scope identifier. Same scope = same nullifier.",
    )
    required_permissions: list[str] = Field(
        default_factory=lambda: ["read_data"],
        description=(
            "Permission flags to require. Options: read_data, write_data, "
            "financial_small, financial_medium, financial_unlimited, "
            "sign_on_behalf, sub_delegate, access_pii"
        ),
    )


class BolyraAuthTool(BaseTool):
    """Mutual ZKP authentication tool for CrewAI agents.

    Performs a Bolyra mutual handshake: the agent generates a PLONK proof
    of credential validity, the counterparty generates a Groth16 proof of
    group membership, and both proofs are verified.

    Dev mode: when no operator_key and no human_secret are provided,
    uses fixed-seed dev identities (never for production).

    Example::

        from bolyra_crewai import BolyraAuthTool

        auth_tool = BolyraAuthTool()
        agent = Agent(
            role="Authenticated Analyst",
            tools=[auth_tool],
            goal="Authenticate before accessing data",
        )
    """

    name: str = "bolyra_authenticate"
    description: str = (
        "Perform mutual ZKP authentication with a human or AI agent. "
        "Verifies that both parties satisfy required identity and permission "
        "policies without revealing private information. Use this before "
        "executing any sensitive operation that requires verified identity."
    )
    args_schema: type[BaseModel] = BolyraAuthInput

    # Configuration
    agent_model_hash: str = "default"
    operator_key: Optional[str] = None
    permissions: list[str] = ["read_data"]
    expiry_seconds: int = 86400
    human_secret: Optional[int] = None

    def _run(
        self,
        scope: str = "bolyra-handshake-v1",
        required_permissions: list[str] | None = None,
    ) -> str:
        """Execute mutual ZKP authentication.

        Returns a JSON string with the auth result (CrewAI convention).
        """
        if required_permissions is None:
            required_permissions = ["read_data"]

        # Dev mode guard
        use_dev = self.operator_key is None and self.human_secret is None
        if use_dev and not is_dev_mode_allowed():
            return AuthResult(
                verified=False,
                status="error",
                message=(
                    "Dev mode is blocked when BOLYRA_ENV=production. "
                    "Provide operator_key and human_secret for production auth."
                ),
            ).to_json()

        try:
            from bolyra.identity import (
                create_agent_credential,
                create_dev_identities,
                create_human_identity,
                permissions_to_bitmask,
            )
            from bolyra.handshake import prove_handshake, verify_handshake
            from bolyra.types import Permission

            # Map permission strings
            _perm_map = {p.name.lower(): p for p in Permission}
            perm_enums = []
            for p_str in self.permissions:
                key = p_str.strip().lower()
                if key not in _perm_map:
                    return AuthResult(
                        verified=False,
                        status="error",
                        message=(
                            f"Unknown permission: '{p_str}'. "
                            f"Valid: {list(_perm_map.keys())}"
                        ),
                    ).to_json()
                perm_enums.append(_perm_map[key])

            if use_dev:
                bitmask = permissions_to_bitmask(perm_enums)
                human, agent, _op_key = create_dev_identities(
                    permission_bitmask=bitmask
                )
            else:
                model_hash_int = int(
                    hashlib.sha256(self.agent_model_hash.encode()).hexdigest()[:16], 16
                )
                operator_key_int = (
                    int(self.operator_key, 16) if self.operator_key else 0
                )
                expiry = int(time.time()) + self.expiry_seconds

                agent = create_agent_credential(
                    model_hash_int, operator_key_int, perm_enums, expiry
                )
                if self.human_secret is not None:
                    human = create_human_identity(self.human_secret)
                else:
                    human, _, _ = create_dev_identities()

            scope_int = int(
                hashlib.sha256(scope.encode()).hexdigest()[:16], 16
            )
            human_proof, agent_proof, nonce = prove_handshake(
                human, agent, scope=scope_int
            )
            result = verify_handshake(human_proof, agent_proof, nonce)

            # Check required permissions
            if result.verified:
                req_perm_enums = []
                for rp in required_permissions:
                    rp_key = rp.strip().lower()
                    if rp_key not in _perm_map:
                        return AuthResult(
                            verified=False,
                            status="error",
                            message=f"Unknown required permission: '{rp}'.",
                        ).to_json()
                    req_perm_enums.append(_perm_map[rp_key])

                required_bitmask = permissions_to_bitmask(req_perm_enums)
                agent_bitmask = agent.permission_bitmask
                if (required_bitmask & agent_bitmask) != required_bitmask:
                    missing_bits = required_bitmask & ~agent_bitmask
                    missing_names = [
                        p.name.lower()
                        for p in Permission
                        if (1 << int(p)) & missing_bits
                    ]
                    return AuthResult(
                        verified=False,
                        status="insufficient_permissions",
                        message=(
                            f"Agent lacks required permissions: {missing_names}."
                        ),
                    ).to_json()

            auth_result = AuthResult(
                verified=result.verified,
                status="ok" if result.verified else "verification_failed",
                human_nullifier=str(result.human_nullifier),
                agent_nullifier=str(result.agent_nullifier),
                session_nonce=str(result.session_nonce),
                scope_commitment=str(result.scope_commitment),
                scope=scope,
                required_permissions=required_permissions,
            )
            return auth_result.to_json()

        except ImportError as e:
            return AuthResult(
                verified=False,
                status="error",
                message=(
                    f"Bolyra Python SDK not installed: {e}. "
                    "Install with: pip install bolyra"
                ),
            ).to_json()
        except Exception as e:
            return AuthResult(
                verified=False,
                status="error",
                message=(
                    f"Bolyra authentication failed: {e}. "
                    "Ensure Node.js >= 18 and @bolyra/sdk are installed."
                ),
            ).to_json()
