"""Tests for BolyraSDJWTTool (CrewAI BaseTool subclass)."""

from __future__ import annotations

import json
import warnings

import pytest
from tests.conftest import requires_crewai, requires_sdk


@requires_crewai
class TestBolyraSDJWTToolMetadata:
    """Metadata tests -- no Node.js required."""

    def test_import(self):
        """Tool module is importable."""
        from bolyra_crewai import BolyraSDJWTTool  # noqa: F401

    def test_tool_name(self):
        """Tool has correct name."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        assert tool.name == "bolyra_authorize"

    def test_args_schema(self):
        """Tool has correct args_schema."""
        from bolyra_crewai import BolyraSDJWTTool, BolyraSDJWTInput

        tool = BolyraSDJWTTool()
        assert tool.args_schema is BolyraSDJWTInput

    def test_is_base_tool(self):
        """Tool is a proper BaseTool subclass."""
        from crewai.tools import BaseTool
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        assert isinstance(tool, BaseTool)

    def test_returns_string(self):
        """_run returns a string (CrewAI convention)."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        result = tool._run(action="test", audience="aud")
        assert isinstance(result, str)


@requires_crewai
@requires_sdk
class TestBolyraSDJWTToolBehavior:
    """Behavior tests -- requires bolyra SDK (for sd_jwt module)."""

    def test_dev_mode_issuance(self):
        """Dev mode auto-generates keys and issues a receipt."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        result = json.loads(
            tool._run(
                action="checkout.charge",
                audience="stripe.example.com",
                permission="FINANCIAL_SMALL",
            )
        )
        assert result["success"] is True
        assert result["status"] == "ok"
        assert result["action"] == "checkout.charge"
        assert result["audience"] == "stripe.example.com"
        assert result["permission"] == "FINANCIAL_SMALL"
        # C1: receipt is NOT in the output, only receipt_jti
        assert "receipt" not in result
        assert "receipt_jti" in result
        assert len(result["receipt_jti"]) > 0

    def test_receipt_vault(self):
        """Raw receipt is stored in the vault, retrievable by JTI."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        result = json.loads(tool._run(action="read", audience="api.example.com"))
        jti = result["receipt_jti"]
        receipt = tool.get_receipt(jti)
        assert receipt is not None
        # Presented form: jws~~kbjwt
        parts = receipt.split("~")
        assert len(parts) == 3
        assert parts[1] == ""
        assert len(parts[0]) > 0  # jws
        assert len(parts[2]) > 0  # kb-jwt

    def test_vault_unknown_jti_returns_none(self):
        """get_receipt returns None for unknown JTI."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        assert tool.get_receipt("nonexistent-jti") is None

    def test_max_amount_cap(self):
        """Max amount is included in the receipt when specified."""
        from bolyra_crewai import BolyraSDJWTTool
        from bolyra.sd_jwt import _decode_jws_payload

        tool = BolyraSDJWTTool()
        result = json.loads(
            tool._run(
                action="purchase",
                audience="shop.example.com",
                max_amount=99.99,
                currency="EUR",
            )
        )
        assert result["success"] is True
        receipt = tool.get_receipt(result["receipt_jti"])
        jws = receipt.split("~")[0]
        payload = _decode_jws_payload(jws)
        assert payload["max"] == {"amount": 99.99, "currency": "EUR"}

    def test_custom_keys(self):
        """Tool works with explicitly provided keys."""
        from bolyra_crewai import BolyraSDJWTTool
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
        result = json.loads(tool._run(action="test", audience="aud"))
        assert result["success"] is True

    def test_nonce_required_in_production_mode(self):
        """Production mode (dev_mode=False) requires an explicit nonce."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool(dev_mode=False)
        result = json.loads(tool._run(action="test", audience="aud"))
        assert result["success"] is False
        assert "Nonce is required" in result["message"]

    def test_nonce_accepted_in_production_mode(self):
        """Production mode works when nonce is provided."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool(dev_mode=False)
        result = json.loads(
            tool._run(
                action="test",
                audience="aud",
                nonce="verifier-challenge-123",
            )
        )
        assert result["success"] is True

    def test_dev_mode_nonce_warning(self):
        """Dev mode emits a warning when auto-generating a nonce."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool(dev_mode=True)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = json.loads(tool._run(action="test", audience="aud"))
            assert result["success"] is True
            nonce_warnings = [
                x for x in w if "auto-generated nonce" in str(x.message)
            ]
            assert len(nonce_warnings) >= 1

    def test_expiry_in_result(self):
        """Result includes expiry timestamp."""
        from bolyra_crewai import BolyraSDJWTTool

        tool = BolyraSDJWTTool()
        result = json.loads(tool._run(action="test", audience="aud"))
        assert result["success"] is True
        assert "expiry" in result
        assert isinstance(result["expiry"], int)
        assert result["expiry"] > 0

    def test_dev_mode_blocked_in_production(self, monkeypatch):
        """Dev mode is blocked when BOLYRA_ENV=production."""
        from bolyra_crewai import BolyraSDJWTTool

        monkeypatch.setenv("BOLYRA_ENV", "production")
        tool = BolyraSDJWTTool(dev_mode=True)
        result = json.loads(tool._run(action="test", audience="aud"))
        assert result["success"] is False
        assert "production" in result.get("message", "").lower()
