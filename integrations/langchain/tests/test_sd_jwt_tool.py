"""Tests for BolyraSDJWTTool (LangChain BaseTool subclass)."""

from __future__ import annotations

import pytest
from tests.conftest import requires_langchain, requires_sdk


@requires_langchain
class TestBolyraSDJWTToolMetadata:
    """Metadata tests -- no Node.js required."""

    def test_import(self):
        """Tool module is importable."""
        from bolyra_langchain import BolyraSDJWTTool  # noqa: F401

    def test_tool_name(self):
        """Tool has correct name."""
        from bolyra_langchain import BolyraSDJWTTool
        tool = BolyraSDJWTTool()
        assert tool.name == "bolyra_authorize"

    def test_args_schema(self):
        """Tool has correct args_schema."""
        from bolyra_langchain import BolyraSDJWTTool, BolyraSDJWTInput
        tool = BolyraSDJWTTool()
        assert tool.args_schema is BolyraSDJWTInput

    def test_is_base_tool(self):
        """Tool is a proper BaseTool subclass."""
        from langchain_core.tools import BaseTool
        from bolyra_langchain import BolyraSDJWTTool
        tool = BolyraSDJWTTool()
        assert isinstance(tool, BaseTool)


@requires_langchain
@requires_sdk
class TestBolyraSDJWTToolBehavior:
    """Behavior tests -- requires bolyra SDK (for sd_jwt module)."""

    def test_dev_mode_issuance(self):
        """Dev mode auto-generates keys and issues a receipt."""
        from bolyra_langchain import BolyraSDJWTTool
        tool = BolyraSDJWTTool()
        result = tool.invoke({
            "action": "checkout.charge",
            "audience": "stripe.example.com",
            "permission": "FINANCIAL_SMALL",
        })
        assert result["success"] is True
        assert result["status"] == "ok"
        assert result["action"] == "checkout.charge"
        assert result["audience"] == "stripe.example.com"
        assert result["permission"] == "FINANCIAL_SMALL"
        assert "~~" in result["receipt"]  # presented form

    def test_issued_receipt_is_presented(self):
        """Receipt returned is in presented form (jws~~kbjwt)."""
        from bolyra_langchain import BolyraSDJWTTool
        tool = BolyraSDJWTTool()
        result = tool.invoke({
            "action": "read",
            "audience": "api.example.com",
        })
        receipt = result["receipt"]
        parts = receipt.split("~")
        assert len(parts) == 3
        assert parts[1] == ""
        assert len(parts[0]) > 0  # jws
        assert len(parts[2]) > 0  # kb-jwt

    def test_max_amount_cap(self):
        """Max amount is included in the receipt when specified."""
        from bolyra_langchain import BolyraSDJWTTool
        from bolyra.sd_jwt import _decode_jws_payload
        tool = BolyraSDJWTTool()
        result = tool.invoke({
            "action": "purchase",
            "audience": "shop.example.com",
            "max_amount": 99.99,
            "currency": "EUR",
        })
        assert result["success"] is True
        # Verify the JWS payload contains the max claim
        jws = result["receipt"].split("~")[0]
        payload = _decode_jws_payload(jws)
        assert payload["max"] == {"amount": 99.99, "currency": "EUR"}

    def test_custom_keys(self):
        """Tool works with explicitly provided keys."""
        from bolyra_langchain import BolyraSDJWTTool
        from bolyra.sd_jwt import generate_ed25519_keypair
        issuer_priv, _ = generate_ed25519_keypair()
        agent_priv, agent_pub = generate_ed25519_keypair()
        tool = BolyraSDJWTTool(
            issuer_private_key=issuer_priv,
            issuer_kid="prod-key-1",
            issuer_id="did:example:prod",
            agent_id="agent-prod",
            agent_private_key=agent_priv,
            agent_public_key=agent_pub,
        )
        result = tool.invoke({
            "action": "test",
            "audience": "aud",
        })
        assert result["success"] is True
