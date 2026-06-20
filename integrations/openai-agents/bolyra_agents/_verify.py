"""Shared verification logic for the Bolyra OpenAI Agents SDK adapter.

Both the guardrail and tool wrapper call into this module. Two auth paths:

1. **SD-JWT mode**: present the receipt with a fresh KB-JWT, then verify locally.
   Pure Python via ``bolyra.sd_jwt``. No Node.js, no gateway.

2. **Gateway mode**: validate token is present and not expired (local JWT decode).
   Full verification is deferred to the gateway.

Security invariants:
- Fresh nonce per presentation (canonical format) -- no nonce reuse
- No key material in AuthResult -- only verification status and claim metadata
- Permission enforcement is pre-flight -- checks happen before tool execution
"""

from __future__ import annotations

import os
import time
from typing import Any

from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthMode, AuthResult, check_permissions


def generate_canonical_nonce() -> str:
    """Generate a canonical Bolyra nonce: (unix_seconds << 64) | random_entropy."""
    unix_seconds = int(time.time())
    entropy = int.from_bytes(os.urandom(8), 'big')
    return str((unix_seconds << 64) | entropy)


async def verify_credentials(
    auth_context: BolyraAuthContext,
    required_permissions: list[str] | None = None,
    required_action: str | None = None,
    audience: str | None = None,
) -> AuthResult:
    """Verify credentials based on auth mode.

    Args:
        auth_context: The auth context containing credentials.
        required_permissions: Permissions required for this operation.
            Falls back to ``auth_context.required_permissions`` if not provided.
        required_action: Required action claim (SD-JWT only).
        audience: Required audience. Falls back to ``auth_context.default_audience``.

    Returns:
        AuthResult with verification outcome.
    """
    effective_permissions = required_permissions or auth_context.required_permissions
    effective_audience = audience or auth_context.default_audience

    if auth_context.mode == AuthMode.SD_JWT:
        return await _verify_sd_jwt(
            auth_context,
            effective_permissions,
            required_action,
            effective_audience,
        )
    elif auth_context.mode == AuthMode.GATEWAY:
        return await _verify_gateway(
            auth_context,
            effective_permissions,
            effective_audience,
        )
    else:
        return AuthResult(
            ok=False,
            reason="UNKNOWN_AUTH_MODE",
            detail=f"Unsupported auth mode: {auth_context.mode}",
        )


async def _verify_sd_jwt(
    ctx: BolyraAuthContext,
    required_permissions: list[str],
    required_action: str | None,
    audience: str,
) -> AuthResult:
    """Verify SD-JWT credentials locally.

    Flow:
    1. Present the receipt with a fresh KB-JWT (nonce = uuid4)
    2. Verify the presented receipt
    3. Check permission claims against requirements
    """
    try:
        from bolyra.sd_jwt import (
            PresentOptions,
            VerifyOptions,
            present,
            verify,
        )
    except ImportError:
        return AuthResult(
            ok=False,
            reason="SDK_UNAVAILABLE",
            detail="bolyra.sd_jwt not available. Install: pip install bolyra",
        )

    if not ctx.receipt:
        return AuthResult(ok=False, reason="NO_RECEIPT", detail="No SD-JWT receipt provided")
    if not ctx.holder_private_key:
        return AuthResult(ok=False, reason="NO_HOLDER_KEY", detail="No holder private key")
    if not ctx.issuer_public_key:
        return AuthResult(ok=False, reason="NO_ISSUER_KEY", detail="No issuer public key")

    # Step 1: Present with fresh nonce
    nonce = generate_canonical_nonce()
    try:
        presented = present(
            ctx.receipt,
            ctx.holder_private_key,
            PresentOptions(nonce=nonce, audience=audience),
        )
    except ValueError:
        return AuthResult(
            ok=False,
            reason="PRESENTATION_FAILED",
            detail="Failed to present SD-JWT receipt",
        )

    # Step 2: Verify the presented receipt
    verify_opts = VerifyOptions(
        expected_audience=audience,
        issuer_public_key=ctx.issuer_public_key,
        expected_nonce=nonce,
    )
    result = verify(presented, verify_opts)

    if not result.ok:
        return AuthResult(
            ok=False,
            reason=result.reason,
            detail=result.detail,
        )

    claims = result.claims or {}

    # Step 3: Check action if required
    if required_action and claims.get("act") != required_action:
        return AuthResult(
            ok=False,
            reason="WRONG_ACTION",
            detail=f"Expected action '{required_action}', got '{claims.get('act')}'",
        )

    # Step 4: Check permissions
    granted_perm = claims.get("perm", "")
    granted_list = [granted_perm] if isinstance(granted_perm, str) else granted_perm
    if not check_permissions(granted_list, required_permissions):
        return AuthResult(
            ok=False,
            reason="INSUFFICIENT_PERMISSIONS",
            detail=f"Required {required_permissions}, granted {granted_list}",
        )

    return AuthResult(
        ok=True,
        claims=claims,
        permissions=granted_list,
        agent_id=claims.get("sub", ctx.agent_id),
    )


async def _verify_gateway(
    ctx: BolyraAuthContext,
    required_permissions: list[str],
    audience: str,
) -> AuthResult:
    """Verify gateway token locally (expiry check).

    The gateway handles full verification. We only do a local JWT decode
    to check expiry before sending network requests with the token.
    """
    if not ctx.gateway_token:
        return AuthResult(ok=False, reason="NO_TOKEN", detail="No gateway token provided")

    try:
        import jwt
    except ImportError:
        return AuthResult(
            ok=False,
            reason="SDK_UNAVAILABLE",
            detail="PyJWT not available. Install: pip install PyJWT[crypto]",
        )

    # Decode without verification -- the gateway does full verification.
    # We only check structural validity and expiry locally.
    try:
        payload = jwt.decode(
            ctx.gateway_token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
            },
            algorithms=["EdDSA", "ES256", "RS256"],
        )
    except jwt.exceptions.DecodeError:
        return AuthResult(
            ok=False,
            reason="TOKEN_MALFORMED",
            detail="Gateway token is not a valid JWT",
        )

    # Check expiry locally
    exp = payload.get("exp")
    if exp is not None:
        now = int(time.time())
        if exp < now:
            return AuthResult(
                ok=False,
                reason="TOKEN_EXPIRED",
                detail=f"Token expired at {exp}, current time {now}",
            )

    # Check permissions if present in token
    token_perms = payload.get("perm", payload.get("permissions", []))
    if isinstance(token_perms, str):
        token_perms = [token_perms]
    if required_permissions:
        if not token_perms or not check_permissions(token_perms, required_permissions):
            return AuthResult(
                ok=False,
                reason="INSUFFICIENT_PERMISSIONS",
                detail=f"Required {required_permissions}, token grants {token_perms}",
            )

    return AuthResult(
        ok=True,
        claims=payload,
        permissions=token_perms if token_perms else [],
        agent_id=payload.get("sub", ctx.agent_id),
    )
