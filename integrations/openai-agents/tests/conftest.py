"""Shared fixtures for bolyra_agents tests."""

from __future__ import annotations

import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthMode


@pytest.fixture
def issuer_keypair():
    """Generate an Ed25519 keypair for the issuer (operator)."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public


@pytest.fixture
def holder_keypair():
    """Generate an Ed25519 keypair for the holder (agent)."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public


@pytest.fixture
def sd_jwt_receipt(issuer_keypair, holder_keypair):
    """Issue a test SD-JWT receipt."""
    from bolyra.sd_jwt import AllowOptions, allow

    issuer_priv, issuer_pub = issuer_keypair
    holder_priv, holder_pub = holder_keypair

    opts = AllowOptions(
        iss="did:bolyra:test-issuer",
        sub="test-agent",
        aud="bolyra-agents",
        act="test.action",
        perm="READ_DATA",
        agent_pub_key=holder_pub,
        ttl_seconds=300,
    )
    receipt = allow(opts, issuer_priv, "test-key-1")
    return receipt


@pytest.fixture
def sd_jwt_context(issuer_keypair, holder_keypair, sd_jwt_receipt):
    """Create an SD-JWT auth context with valid credentials."""
    issuer_priv, issuer_pub = issuer_keypair
    holder_priv, holder_pub = holder_keypair

    return BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        receipt=sd_jwt_receipt,
        holder_private_key=holder_priv,
        issuer_public_key=issuer_pub,
        agent_id="test-agent",
        default_audience="bolyra-agents",
        required_permissions=["READ_DATA"],
    )


@pytest.fixture
def gateway_token():
    """Create a valid gateway JWT token (unsigned, for local testing)."""
    import jwt

    payload = {
        "sub": "test-agent",
        "aud": "bolyra-agents",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "perm": ["READ_DATA", "WRITE_DATA"],
    }
    # Encode without signature for local testing
    return jwt.encode(payload, "test-secret", algorithm="HS256")


@pytest.fixture
def expired_gateway_token():
    """Create an expired gateway JWT token."""
    import jwt

    payload = {
        "sub": "test-agent",
        "aud": "bolyra-agents",
        "iat": int(time.time()) - 600,
        "exp": int(time.time()) - 300,
        "perm": ["READ_DATA"],
    }
    return jwt.encode(payload, "test-secret", algorithm="HS256")


@pytest.fixture
def gateway_context(gateway_token):
    """Create a gateway auth context with valid token."""
    return BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token=gateway_token,
        agent_id="test-agent",
        default_audience="bolyra-agents",
        required_permissions=["READ_DATA"],
    )


@pytest.fixture
def dev_context():
    """Create a dev-mode auth context (no real credentials needed)."""
    return BolyraAuthContext(
        mode=AuthMode.SD_JWT,
        agent_id="dev-agent",
        dev_mode=True,
    )
