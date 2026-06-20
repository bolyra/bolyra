"""Tests for BolyraAuthGuardrail."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from bolyra_agents.guardrail import BolyraAuthGuardrail


@dataclass
class MockRunContext:
    """Minimal RunContextWrapper mock."""
    context: dict[str, Any] = field(default_factory=dict)


@pytest.mark.asyncio
async def test_guardrail_sd_jwt_pass(sd_jwt_context):
    """Guardrail should pass with valid SD-JWT credentials."""
    guardrail = BolyraAuthGuardrail(auth_context=sd_jwt_context)
    ctx = MockRunContext()
    agent = MagicMock()
    agent.name = "test-agent"

    result = await guardrail._check_auth(ctx, agent, "Hello")

    assert result.tripwire_triggered is False
    assert "bolyra_auth" in ctx.context
    assert ctx.context["bolyra_auth"].ok is True


@pytest.mark.asyncio
async def test_guardrail_sd_jwt_deny(holder_keypair, sd_jwt_receipt):
    """Guardrail should trip with wrong issuer key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from bolyra_agents.auth_context import BolyraAuthContext
    from bolyra_agents.types import AuthMode

    holder_priv, _ = holder_keypair
    wrong_key = Ed25519PrivateKey.generate().public_key()

    ctx_auth = BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        receipt=sd_jwt_receipt,
        holder_private_key=holder_priv,
        issuer_public_key=wrong_key,
        default_audience="bolyra-agents",
    )
    guardrail = BolyraAuthGuardrail(auth_context=ctx_auth)
    ctx = MockRunContext()
    agent = MagicMock()
    agent.name = "test-agent"

    result = await guardrail._check_auth(ctx, agent, "Hello")

    assert result.tripwire_triggered is True
    assert "bolyra_auth" not in ctx.context


@pytest.mark.asyncio
async def test_guardrail_dev_mode(dev_context):
    """Guardrail should pass in dev mode without real credentials."""
    guardrail = BolyraAuthGuardrail(auth_context=dev_context)
    ctx = MockRunContext()
    agent = MagicMock()
    agent.name = "dev-agent"

    result = await guardrail._check_auth(ctx, agent, "Hello")

    assert result.tripwire_triggered is False
    assert "bolyra_auth" in ctx.context
    assert ctx.context["bolyra_auth"].ok is True
    assert ctx.context["bolyra_auth"].claims == {"dev_mode": True}


@pytest.mark.asyncio
async def test_guardrail_gateway_pass(gateway_context):
    """Guardrail should pass with valid gateway token."""
    guardrail = BolyraAuthGuardrail(auth_context=gateway_context)
    ctx = MockRunContext()
    agent = MagicMock()
    agent.name = "gateway-agent"

    result = await guardrail._check_auth(ctx, agent, "Hello")

    assert result.tripwire_triggered is False


@pytest.mark.asyncio
async def test_guardrail_gateway_expired(expired_gateway_token):
    """Guardrail should trip with expired gateway token."""
    from bolyra_agents.auth_context import BolyraAuthContext
    from bolyra_agents.types import AuthMode

    ctx_auth = BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token=expired_gateway_token,
    )
    guardrail = BolyraAuthGuardrail(auth_context=ctx_auth)
    ctx = MockRunContext()
    agent = MagicMock()
    agent.name = "expired-agent"

    result = await guardrail._check_auth(ctx, agent, "Hello")

    assert result.tripwire_triggered is True


@pytest.mark.asyncio
async def test_guardrail_config_invalid():
    """Guardrail should trip when config is invalid."""
    from bolyra_agents.auth_context import BolyraAuthContext
    from bolyra_agents.types import AuthMode

    ctx_auth = BolyraAuthContext(mode=AuthMode.SD_JWT)
    guardrail = BolyraAuthGuardrail(auth_context=ctx_auth)
    ctx = MockRunContext()
    agent = MagicMock()
    agent.name = "invalid-agent"

    result = await guardrail._check_auth(ctx, agent, "Hello")

    assert result.tripwire_triggered is True


def test_guardrail_as_input_guardrail(sd_jwt_context):
    """as_input_guardrail() should return an InputGuardrail instance."""
    from agents import InputGuardrail

    guardrail = BolyraAuthGuardrail(auth_context=sd_jwt_context)
    ig = guardrail.as_input_guardrail()

    assert isinstance(ig, InputGuardrail)
    assert ig.name == "bolyra_auth"
