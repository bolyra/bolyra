"""Tests for bolyra_mcp_auth MCP server wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from bolyra_agents.mcp_auth import bolyra_mcp_auth, _get_auth_token, _check_gateway_expiry
from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthMode


class MockMCPServerSse:
    """Mock MCPServerSse with _params."""
    __name__ = "MCPServerSse"

    def __init__(self, url: str, headers: dict[str, str] | None = None):
        self._params: dict[str, Any] = {"url": url}
        if headers:
            self._params["headers"] = headers

    # Make type(self).__name__ return MCPServerSse
    class __class_override:
        __name__ = "MCPServerSse"


# Override __class__ for isinstance-free type checking
MockMCPServerSse.__name__ = "MCPServerSse"
type.__setattr__(MockMCPServerSse, "__name__", "MCPServerSse")


class MockMCPServerStdio:
    """Mock MCPServerStdio with _params."""
    def __init__(self, command: str, env: dict[str, str] | None = None):
        self._params: dict[str, Any] = {"command": command}
        if env:
            self._params["env"] = env


type.__setattr__(MockMCPServerStdio, "__name__", "MCPServerStdio")


def test_mcp_auth_gateway_sse(gateway_context):
    """Gateway mode should inject Authorization header into SSE server."""
    server = MockMCPServerSse(url="https://example.com/sse")
    result = bolyra_mcp_auth(server, gateway_context)

    assert result is server
    assert "headers" in server._params
    assert server._params["headers"]["Authorization"].startswith("Bearer ")


def test_mcp_auth_gateway_stdio(gateway_context):
    """Gateway mode should inject env var into Stdio server."""
    server = MockMCPServerStdio(command="python server.py")
    result = bolyra_mcp_auth(server, gateway_context)

    assert result is server
    assert "env" in server._params
    assert "BOLYRA_AUTH_TOKEN" in server._params["env"]


def test_mcp_auth_sd_jwt_sse(sd_jwt_context):
    """SD-JWT mode should inject presented receipt as header into SSE server."""
    server = MockMCPServerSse(url="https://example.com/sse")
    result = bolyra_mcp_auth(server, sd_jwt_context)

    assert result is server
    assert "headers" in server._params
    auth_header = server._params["headers"]["Authorization"]
    assert auth_header.startswith("Bearer ")
    # SD-JWT presented form contains tildes
    token = auth_header[len("Bearer "):]
    assert "~" in token


def test_mcp_auth_sd_jwt_stdio(sd_jwt_context):
    """SD-JWT mode should inject presented receipt as env var into Stdio server."""
    server = MockMCPServerStdio(command="node server.js")
    result = bolyra_mcp_auth(server, sd_jwt_context)

    assert result is server
    assert "env" in server._params
    assert "BOLYRA_SD_JWT" in server._params["env"]
    assert "~" in server._params["env"]["BOLYRA_SD_JWT"]


def test_mcp_auth_dev_mode(dev_context):
    """Dev mode should return server unchanged."""
    server = MockMCPServerSse(url="https://example.com/sse")
    result = bolyra_mcp_auth(server, dev_context)

    assert result is server
    # No headers injected in dev mode
    assert "headers" not in server._params


def test_mcp_auth_expired_gateway():
    """Expired gateway token should raise ValueError."""
    import jwt
    import time

    expired_token = jwt.encode(
        {"sub": "test", "exp": int(time.time()) - 300},
        "secret",
        algorithm="HS256",
    )
    ctx = BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token=expired_token,
    )
    server = MockMCPServerSse(url="https://example.com/sse")

    with pytest.raises(ValueError, match="expired"):
        bolyra_mcp_auth(server, ctx)


def test_mcp_auth_invalid_config():
    """Invalid config (no token in gateway mode) should raise ValueError."""
    ctx = BolyraAuthContext(mode=AuthMode.GATEWAY)
    server = MockMCPServerSse(url="https://example.com/sse")

    with pytest.raises(ValueError, match="validation failed"):
        bolyra_mcp_auth(server, ctx)


def test_mcp_auth_unsupported_server_type(gateway_context):
    """Unsupported server type should raise ValueError."""

    class MockUnknownServer:
        _params = {}

    with pytest.raises(ValueError, match="Unsupported"):
        bolyra_mcp_auth(MockUnknownServer(), gateway_context)


def test_check_gateway_expiry_valid(gateway_token):
    """Valid token should not raise."""
    _check_gateway_expiry(gateway_token)


def test_check_gateway_expiry_expired(expired_gateway_token):
    """Expired token should raise ValueError."""
    with pytest.raises(ValueError, match="expired"):
        _check_gateway_expiry(expired_gateway_token)


def test_check_gateway_expiry_malformed():
    """Malformed token should raise ValueError."""
    with pytest.raises(ValueError, match="not a valid JWT"):
        _check_gateway_expiry("not-a-jwt")
