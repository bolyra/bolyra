"""Tests for shared verification logic."""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bolyra_agents._verify import verify_credentials
from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthMode


@pytest.mark.asyncio
async def test_sd_jwt_verify_success(sd_jwt_context):
    """Valid SD-JWT credentials should verify successfully."""
    result = await verify_credentials(sd_jwt_context)
    assert result.ok is True
    assert result.claims is not None
    assert result.reason is None


@pytest.mark.asyncio
async def test_sd_jwt_verify_wrong_permissions(sd_jwt_context):
    """SD-JWT with insufficient permissions should fail."""
    result = await verify_credentials(
        sd_jwt_context,
        required_permissions=["FINANCIAL_UNLIMITED"],
    )
    assert result.ok is False
    assert result.reason == "INSUFFICIENT_PERMISSIONS"


@pytest.mark.asyncio
async def test_sd_jwt_verify_no_receipt():
    """SD-JWT mode without receipt should fail."""
    ctx = BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        holder_private_key=Ed25519PrivateKey.generate(),
        issuer_public_key=Ed25519PrivateKey.generate().public_key(),
    )
    result = await verify_credentials(ctx)
    assert result.ok is False
    assert result.reason == "NO_RECEIPT"


@pytest.mark.asyncio
async def test_sd_jwt_verify_wrong_issuer_key(holder_keypair, sd_jwt_receipt):
    """SD-JWT verified with wrong issuer key should fail."""
    holder_priv, holder_pub = holder_keypair
    wrong_key = Ed25519PrivateKey.generate().public_key()

    ctx = BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        receipt=sd_jwt_receipt,
        holder_private_key=holder_priv,
        issuer_public_key=wrong_key,
        default_audience="bolyra-agents",
    )
    result = await verify_credentials(ctx)
    assert result.ok is False
    assert result.reason == "INVALID_SIGNATURE"


@pytest.mark.asyncio
async def test_gateway_verify_success(gateway_context):
    """Valid gateway token should verify successfully."""
    result = await verify_credentials(gateway_context)
    assert result.ok is True
    assert result.claims is not None


@pytest.mark.asyncio
async def test_gateway_verify_expired(expired_gateway_token):
    """Expired gateway token should fail."""
    ctx = BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token=expired_gateway_token,
    )
    result = await verify_credentials(ctx)
    assert result.ok is False
    assert result.reason == "TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_gateway_verify_no_token():
    """Gateway mode without token should fail."""
    ctx = BolyraAuthContext(mode=AuthMode.GATEWAY)
    result = await verify_credentials(ctx)
    assert result.ok is False
    assert result.reason == "NO_TOKEN"


@pytest.mark.asyncio
async def test_gateway_verify_malformed_token():
    """Malformed gateway token should fail."""
    ctx = BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token="not-a-jwt",
    )
    result = await verify_credentials(ctx)
    assert result.ok is False
    assert result.reason == "TOKEN_MALFORMED"


@pytest.mark.asyncio
async def test_gateway_verify_permission_check(gateway_token):
    """Gateway token with insufficient permissions should fail."""
    ctx = BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token=gateway_token,
        required_permissions=["FINANCIAL_UNLIMITED"],
    )
    result = await verify_credentials(ctx)
    assert result.ok is False
    assert result.reason == "INSUFFICIENT_PERMISSIONS"
