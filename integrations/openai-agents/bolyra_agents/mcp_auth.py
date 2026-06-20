"""MCP auth wrapper for the Bolyra OpenAI Agents SDK adapter.

Wraps MCPServerSse or MCPServerStdio to inject Bolyra auth credentials:

- **Gateway mode**: Injects ``Authorization: Bearer <token>`` header into
  MCPServerSse params. For MCPServerStdio, injects the token as a
  ``BOLYRA_AUTH_TOKEN`` environment variable.

- **SD-JWT mode**: Presents a fresh receipt on each connection and injects
  the presented SD-JWT as an ``Authorization: Bearer <sd-jwt>`` header
  (SSE) or ``BOLYRA_SD_JWT`` env var (stdio).

Usage::

    from agents.mcp import MCPServerSse
    from bolyra_agents import bolyra_mcp_auth, BolyraAuthContext, AuthMode

    server = MCPServerSse(params={"url": "https://my-server.com/sse"})
    authed = bolyra_mcp_auth(server, BolyraAuthContext(
        mode=AuthMode.GATEWAY,
        gateway_token="eyJ...",
    ))
    agent = Agent(name="mcp-agent", mcp_servers=[authed])
"""

from __future__ import annotations

import copy
import os
import time
import warnings
from typing import Any

from bolyra_agents._tracing import bolyra_auth_span, record_auth_result
from bolyra_agents._verify import generate_canonical_nonce
from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthMode, BolyraAuthError


def bolyra_mcp_auth(
    server: Any,
    auth_context: BolyraAuthContext,
) -> Any:
    """Add Bolyra auth credentials to an MCP server connection.

    For SSE servers: injects Authorization header into the params.
    For Stdio servers: injects auth token as an environment variable.

    Args:
        server: An MCPServerSse or MCPServerStdio instance.
        auth_context: Auth context with credentials.

    Returns:
        The same server instance with auth injected.

    Raises:
        ValueError: If auth context validation fails or server type is unsupported.
    """
    with bolyra_auth_span("mcp_auth", agent_id=auth_context.agent_id) as span:
        errors = auth_context.validate()
        if errors and not auth_context.dev_mode:
            record_auth_result(span, ok=False, reason="config_invalid")
            raise ValueError(f"Auth context validation failed: {'; '.join(errors)}")

        if auth_context.dev_mode:
            if os.environ.get("BOLYRA_ENV") == "production":
                raise BolyraAuthError("dev_mode=True is not allowed when BOLYRA_ENV=production")
            warnings.warn("Bolyra: dev_mode is active. Do not use in production.", stacklevel=2)
            record_auth_result(span, ok=True, reason="dev_mode")
            return server

        server_type = type(server).__name__

        if server_type == "MCPServerSse":
            _inject_sse_auth(server, auth_context)
            record_auth_result(span, ok=True)
        elif server_type == "MCPServerStdio":
            _inject_stdio_auth(server, auth_context)
            record_auth_result(span, ok=True)
        else:
            record_auth_result(span, ok=False, reason="unsupported_server_type")
            raise ValueError(
                f"Unsupported MCP server type: {server_type}. "
                "Expected MCPServerSse or MCPServerStdio."
            )

        return server


def _inject_sse_auth(server: Any, auth_context: BolyraAuthContext) -> None:
    """Inject auth headers into an MCPServerSse's params."""
    token = _get_auth_token(auth_context)

    # MCPServerSse stores params in server._params (MCPServerSseParams)
    # The params dict has an optional 'headers' key
    if hasattr(server, "_params"):
        params = server._params
        if "headers" not in params or params["headers"] is None:
            params["headers"] = {}
        params["headers"]["Authorization"] = f"Bearer {token}"
    else:
        raise ValueError("MCPServerSse instance does not have _params attribute")


def _inject_stdio_auth(server: Any, auth_context: BolyraAuthContext) -> None:
    """Inject auth as environment variables into an MCPServerStdio's params."""
    token = _get_auth_token(auth_context)

    if hasattr(server, "_params"):
        params = server._params
        if "env" not in params or params["env"] is None:
            params["env"] = {}
        if auth_context.mode == AuthMode.SD_JWT:
            params["env"]["BOLYRA_SD_JWT"] = token
        else:
            params["env"]["BOLYRA_AUTH_TOKEN"] = token
    else:
        raise ValueError("MCPServerStdio instance does not have _params attribute")


def _get_auth_token(auth_context: BolyraAuthContext) -> str:
    """Get the auth token string based on auth mode.

    For gateway mode: returns the gateway token directly.
    For SD-JWT mode: presents the receipt with a fresh KB-JWT and returns
    the presented SD-JWT string.
    """
    if auth_context.mode == AuthMode.GATEWAY:
        if not auth_context.gateway_token:
            raise ValueError("Gateway mode requires gateway_token")

        # Local expiry check before sending
        _check_gateway_expiry(auth_context.gateway_token)
        return auth_context.gateway_token

    elif auth_context.mode == AuthMode.SD_JWT:
        if not auth_context.receipt or not auth_context.holder_private_key:
            raise ValueError("SD-JWT mode requires receipt and holder_private_key")

        from bolyra.sd_jwt import PresentOptions, present

        nonce = generate_canonical_nonce()
        presented = present(
            auth_context.receipt,
            auth_context.holder_private_key,
            PresentOptions(nonce=nonce, audience=auth_context.default_audience),
        )
        return presented

    else:
        raise ValueError(f"Unsupported auth mode: {auth_context.mode}")


def _check_gateway_expiry(token: str) -> None:
    """Check if a gateway JWT token has expired locally.

    Raises ValueError if the token is expired.
    """
    try:
        import jwt
        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
            },
            algorithms=["EdDSA", "ES256", "RS256"],
        )
        exp = payload.get("exp")
        if exp is not None and exp < int(time.time()):
            raise ValueError(f"Gateway token expired at {exp}")
    except jwt.exceptions.DecodeError:
        raise ValueError("Gateway token is not a valid JWT")
