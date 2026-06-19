"""LangChain tool for Bolyra SD-JWT delegation.

Lightweight delegation path that does not require the ZKP circuit
machinery or Node.js. Uses the pure-Python SD-JWT module from
the Bolyra SDK.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from pydantic import BaseModel, Field

from bolyra_langchain._compat import (
    BaseTool,
    CallbackManagerForToolRun,
    AsyncCallbackManagerForToolRun,
    check_langchain_available,
)
from bolyra_langchain.types import SDJWTResult

check_langchain_available()


class BolyraSDJWTInput(BaseModel):
    """Input schema for BolyraSDJWTTool."""

    action: str = Field(description="Action to authorize, e.g. 'checkout.charge'")
    audience: str = Field(description="Tool or service identifier")
    permission: str = Field(default="READ_DATA", description="Permission label")
    max_amount: float | None = Field(default=None, description="Cap per invocation")
    currency: str = Field(default="USD", description="Currency for max_amount")


class BolyraSDJWTTool(BaseTool):
    """SD-JWT delegation tool for LangChain agents.

    Issues SD-JWT delegation receipts authorizing this agent to perform
    a specific action. Lighter weight than ZKP auth -- no circuit proving
    required. Use for tool authorization in trusted environments.

    Dev mode: when no issuer_key is provided, auto-generates test
    credentials using Ed25519.

    Example::

        from bolyra_langchain import BolyraSDJWTTool

        # Dev mode (auto-generates keys)
        tool = BolyraSDJWTTool()
        result = tool.invoke({
            "action": "checkout.charge",
            "audience": "stripe.example.com",
            "permission": "FINANCIAL_SMALL",
        })

        # Production mode
        from bolyra.sd_jwt import generate_ed25519_keypair
        issuer_priv, issuer_pub = generate_ed25519_keypair()
        tool = BolyraSDJWTTool(
            issuer_private_key=issuer_priv,
            issuer_kid="my-key-1",
            issuer_id="did:example:issuer",
            agent_id="agent-alice",
        )
    """

    name: str = "bolyra_authorize"
    description: str = (
        "Issue an SD-JWT delegation receipt authorizing this agent to perform "
        "a specific action. Lighter weight than ZKP auth -- no circuit proving "
        "required. Use for tool authorization in trusted environments."
    )
    args_schema: type[BaseModel] = BolyraSDJWTInput

    # Configuration -- these are not Pydantic fields because CryptoKey
    # objects are not serializable. We use model_config to allow arbitrary types.
    model_config = {"arbitrary_types_allowed": True}

    issuer_private_key: Any = None
    issuer_kid: str = "dev-key-1"
    issuer_id: str = "did:bolyra:dev-issuer"
    agent_id: str = "dev-agent"
    agent_private_key: Any = None
    agent_public_key: Any = None
    ttl_seconds: int = 300

    def _ensure_keys(self) -> None:
        """Auto-generate dev keys if none provided."""
        if self.issuer_private_key is None or self.agent_private_key is None:
            from bolyra.sd_jwt import generate_ed25519_keypair
            if self.issuer_private_key is None:
                self.issuer_private_key, _ = generate_ed25519_keypair()
            if self.agent_private_key is None:
                self.agent_private_key, self.agent_public_key = generate_ed25519_keypair()
        if self.agent_public_key is None:
            self.agent_public_key = self.agent_private_key.public_key()

    def _run(
        self,
        action: str = "",
        audience: str = "",
        permission: str = "READ_DATA",
        max_amount: float | None = None,
        currency: str = "USD",
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> dict[str, Any]:
        """Issue an SD-JWT delegation receipt."""
        if run_manager:
            run_manager.on_text(f"Issuing SD-JWT for action={action}, audience={audience}")

        try:
            from bolyra.sd_jwt import AllowOptions, PresentOptions, allow, present

            self._ensure_keys()

            max_cap = None
            if max_amount is not None:
                max_cap = {"amount": max_amount, "currency": currency}

            opts = AllowOptions(
                iss=self.issuer_id,
                sub=self.agent_id,
                aud=audience,
                act=action,
                perm=permission,
                agent_pub_key=self.agent_public_key,
                max_amount=max_cap,
                ttl_seconds=self.ttl_seconds,
            )

            receipt = allow(opts, self.issuer_private_key, self.issuer_kid)

            # Auto-present with a generated nonce for immediate use
            import uuid
            nonce = str(uuid.uuid4())
            presented = present(
                receipt, self.agent_private_key,
                PresentOptions(nonce=nonce, audience=audience),
            )

            return SDJWTResult(
                success=True, status="ok",
                receipt=presented,
                action=action,
                audience=audience,
                permission=permission,
            ).to_dict()

        except ImportError as e:
            return SDJWTResult(
                success=False, status="error",
                message=f"Bolyra SD-JWT not available: {e}. Install: pip install bolyra",
            ).to_dict()
        except Exception as e:
            return SDJWTResult(
                success=False, status="error",
                message=f"SD-JWT issuance failed: {e}",
            ).to_dict()

    async def _arun(
        self,
        action: str = "",
        audience: str = "",
        permission: str = "READ_DATA",
        max_amount: float | None = None,
        currency: str = "USD",
        run_manager: AsyncCallbackManagerForToolRun | None = None,
    ) -> dict[str, Any]:
        """Async version."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._run, action, audience, permission, max_amount, currency, None
        )
