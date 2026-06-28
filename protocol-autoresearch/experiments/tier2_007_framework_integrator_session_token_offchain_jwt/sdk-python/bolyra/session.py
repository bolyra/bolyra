"""Off-chain session token (JWT) after on-chain handshake verification.

Uses EdDSA (Ed25519) via PyJWT + cryptography. Mirrors the TypeScript
``mintSessionToken`` / ``verifySessionToken`` API in ``@bolyra/sdk``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ── Types ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SessionClaims:
    """Decoded session token claims."""

    nullifier_hash: str
    scope_commitment: str
    session_nonce: str
    iat: int
    exp: int


@dataclass
class HandshakeVerifyResult:
    """Result of a verifyHandshake() call."""

    valid: bool
    nullifier_hash: str
    scope_commitment: str
    session_nonce: str


class BolyraSessionError(Exception):
    """Raised when session token minting or verification fails."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ── Constants ──────────────────────────────────────────────────────────────

DEFAULT_TTL_SECONDS = 300
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 900
DEFAULT_ISSUER = "bolyra.ai"


# ── Public API ─────────────────────────────────────────────────────────────


def mint_session_token(
    verify_result: HandshakeVerifyResult,
    signer_key: Ed25519PrivateKey,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    issuer: str = DEFAULT_ISSUER,
) -> str:
    """Mint a session JWT after a successful verifyHandshake().

    Args:
        verify_result: The handshake verification output.
        signer_key: An Ed25519 private key for signing.
        ttl_seconds: Token lifetime in seconds (60–900). Default: 300.
        issuer: JWT issuer claim. Default: 'bolyra.ai'.

    Returns:
        A signed JWT string.

    Raises:
        BolyraSessionError: If the handshake was invalid or TTL is out of range.
    """
    if not verify_result.valid:
        raise BolyraSessionError(
            "INVALID_TOKEN",
            "Cannot mint session token from invalid handshake result",
        )

    if ttl_seconds < MIN_TTL_SECONDS or ttl_seconds > MAX_TTL_SECONDS:
        raise BolyraSessionError(
            "INVALID_TOKEN",
            f"TTL must be between {MIN_TTL_SECONDS}s and {MAX_TTL_SECONDS}s, got {ttl_seconds}s",
        )

    now = int(time.time())

    payload = {
        "nullifierHash": verify_result.nullifier_hash,
        "scopeCommitment": verify_result.scope_commitment,
        "sessionNonce": verify_result.session_nonce,
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": issuer,
    }

    return jwt.encode(
        payload,
        signer_key,
        algorithm="EdDSA",
        headers={"typ": "JWT"},
    )


def verify_session_token(
    token: str,
    public_key: Ed25519PublicKey,
    *,
    expected_issuer: str = DEFAULT_ISSUER,
) -> SessionClaims:
    """Verify a session token off-chain.

    Args:
        token: The JWT string to verify.
        public_key: The Ed25519 public key corresponding to the signer.
        expected_issuer: Expected issuer claim. Default: 'bolyra.ai'.

    Returns:
        Decoded SessionClaims.

    Raises:
        BolyraSessionError: On invalid signature, expiry, or missing claims.
    """
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            issuer=expected_issuer,
            options={"require": ["exp", "iat", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise BolyraSessionError("TOKEN_EXPIRED", "Session token has expired")
    except jwt.InvalidSignatureError:
        raise BolyraSessionError("INVALID_SIGNATURE", "JWT signature verification failed")
    except jwt.PyJWTError as exc:
        raise BolyraSessionError("INVALID_TOKEN", f"JWT verification failed: {exc}")

    nullifier_hash = payload.get("nullifierHash")
    scope_commitment = payload.get("scopeCommitment")
    session_nonce = payload.get("sessionNonce")

    if not all(
        isinstance(v, str) for v in (nullifier_hash, scope_commitment, session_nonce)
    ):
        raise BolyraSessionError(
            "CLAIMS_TAMPERED",
            "Required claims (nullifierHash, scopeCommitment, sessionNonce) missing or invalid",
        )

    return SessionClaims(
        nullifier_hash=nullifier_hash,  # type: ignore[arg-type]
        scope_commitment=scope_commitment,  # type: ignore[arg-type]
        session_nonce=session_nonce,  # type: ignore[arg-type]
        iat=payload["iat"],
        exp=payload["exp"],
    )
