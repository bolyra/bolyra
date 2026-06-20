"""Tests for BolyraAuthContext validation."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthMode


def test_sd_jwt_context_valid(sd_jwt_context):
    """Valid SD-JWT context should have no validation errors."""
    errors = sd_jwt_context.validate()
    assert errors == []


def test_sd_jwt_context_missing_receipt():
    """SD-JWT context without receipt should fail validation."""
    ctx = BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        holder_private_key=Ed25519PrivateKey.generate(),
        issuer_public_key=Ed25519PrivateKey.generate().public_key(),
    )
    errors = ctx.validate()
    assert any("receipt" in e for e in errors)


def test_sd_jwt_context_missing_holder_key():
    """SD-JWT context without holder key should fail validation."""
    ctx = BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        receipt="test~",
        issuer_public_key=Ed25519PrivateKey.generate().public_key(),
    )
    errors = ctx.validate()
    assert any("holder_private_key" in e for e in errors)


def test_sd_jwt_context_missing_issuer_key():
    """SD-JWT context without issuer key should fail validation."""
    ctx = BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        receipt="test~",
        holder_private_key=Ed25519PrivateKey.generate(),
    )
    errors = ctx.validate()
    assert any("issuer_public_key" in e for e in errors)


def test_gateway_context_valid(gateway_context):
    """Valid gateway context should have no validation errors."""
    errors = gateway_context.validate()
    assert errors == []


def test_gateway_context_missing_token():
    """Gateway context without token should fail validation."""
    ctx = BolyraAuthContext(mode=AuthMode.GATEWAY)
    errors = ctx.validate()
    assert any("gateway_token" in e for e in errors)


def test_dev_context_no_validation(dev_context):
    """Dev context has SD-JWT mode but no real credentials -- validate() will report errors."""
    # dev_mode doesn't bypass validate(), but the guardrail/wrapper checks dev_mode first
    errors = dev_context.validate()
    assert len(errors) > 0  # Missing receipt, keys -- but dev_mode skips verification
