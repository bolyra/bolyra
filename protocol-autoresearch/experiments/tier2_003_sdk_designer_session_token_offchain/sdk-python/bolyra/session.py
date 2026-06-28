"""SD-JWT session token for off-chain proof reuse.

Mirrors the TypeScript ``issueSessionToken`` / ``verifySessionToken`` API
in ``@bolyra/sdk``. Uses HMAC-SHA256 for signing and SHA-256 for SD-JWT
disclosure digests.

Spec: spec/session-token-sd-jwt.md
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


# ── Types ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SessionClaims:
    """Decoded session token claims."""

    nullifier_hash: Optional[str] = None
    scope_commitment: Optional[str] = None
    human_merkle_root: Optional[str] = None
    agent_credential_hash: Optional[str] = None
    model_hash: Optional[str] = None
    operator_did: Optional[str] = None
    iat: int = 0
    exp: int = 0
    iss: str = ""


@dataclass
class HandshakeResult:
    """Minimal handshake result for session token minting."""

    verified: bool
    nullifier_hash: str
    human_merkle_root: str
    scope_commitment: str = "0x0"
    agent_credential_hash: str = "0x0"
    model_hash: Optional[str] = None
    operator_did: Optional[str] = None


class BolyraSessionError(Exception):
    """Raised when session token minting or verification fails."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ── Constants ──────────────────────────────────────────────────────────────

DEFAULT_TTL = 300
MIN_TTL = 60
MAX_TTL = 3600
DEFAULT_ISSUER = "bolyra.ai"
SD_ALG = "sha-256"

ALL_DISCLOSABLE = [
    "nullifierHash",
    "scopeCommitment",
    "humanMerkleRoot",
    "agentCredentialHash",
]


# ── Helpers ────────────────────────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return urlsafe_b64decode(s)


def _sha256(data: str) -> bytes:
    return hashlib.sha256(data.encode("utf-8")).digest()


def _hmac_sign(secret: bytes, data: str) -> str:
    return _b64url_encode(
        hmac.new(secret, data.encode("utf-8"), hashlib.sha256).digest()
    )


def _create_disclosure(claim_name: str, claim_value: str) -> dict:
    salt = _b64url_encode(os.urandom(16))
    arr = json.dumps([salt, claim_name, claim_value], separators=(",", ":"))
    encoded = _b64url_encode(arr.encode("utf-8"))
    digest = _b64url_encode(_sha256(encoded))
    return {
        "salt": salt,
        "claim_name": claim_name,
        "claim_value": claim_value,
        "encoded": encoded,
        "digest": digest,
    }


# ── Public API ─────────────────────────────────────────────────────────────


def issue_session_token(
    result: HandshakeResult,
    secret: bytes,
    *,
    ttl_seconds: int = DEFAULT_TTL,
    disclose: Optional[Sequence[str]] = None,
) -> str:
    """Mint an SD-JWT session token after a successful verify_handshake().

    Args:
        result: The handshake verification output.
        secret: 32-byte HMAC-SHA256 shared secret.
        ttl_seconds: Token lifetime in seconds (60-3600). Default: 300.
        disclose: Claims to include as selective disclosures.
                  Default: all four core claims.

    Returns:
        SD-JWT compact serialization.

    Raises:
        BolyraSessionError: If the handshake was invalid or TTL is out of range.
    """
    if not result.verified:
        raise BolyraSessionError(
            "INVALID_HANDSHAKE",
            "Cannot mint session token from unverified handshake",
        )

    if ttl_seconds < MIN_TTL or ttl_seconds > MAX_TTL:
        raise BolyraSessionError(
            "INVALID_TOKEN",
            f"TTL must be between {MIN_TTL}s and {MAX_TTL}s, got {ttl_seconds}s",
        )

    disclose_claims = list(disclose) if disclose is not None else ALL_DISCLOSABLE

    # Build claim values from the handshake result
    claim_values: Dict[str, str] = {
        "nullifierHash": result.nullifier_hash,
        "scopeCommitment": result.scope_commitment,
        "humanMerkleRoot": result.human_merkle_root,
        "agentCredentialHash": result.agent_credential_hash,
    }
    if result.model_hash:
        claim_values["modelHash"] = result.model_hash
    if result.operator_did:
        claim_values["operatorDID"] = result.operator_did

    # Create disclosures
    disclosures = []
    for name in disclose_claims:
        if name in claim_values:
            disclosures.append(_create_disclosure(name, claim_values[name]))

    now = int(time.time())

    payload = {
        "iss": DEFAULT_ISSUER,
        "iat": now,
        "exp": now + ttl_seconds,
        "_sd_alg": SD_ALG,
        "_sd": [d["digest"] for d in disclosures],
    }

    # Build JWT
    header = {"alg": "HS256", "typ": "sd+jwt"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = _hmac_sign(secret, signing_input)
    jwt_str = f"{signing_input}.{signature}"

    # SD-JWT: jwt~disclosure1~disclosure2~...~
    disc_parts = "~".join(d["encoded"] for d in disclosures)
    return f"{jwt_str}~{disc_parts}~"


def verify_session_token(
    token: str,
    secret: bytes,
    *,
    required_claims: Optional[Sequence[str]] = None,
    clock_tolerance_sec: int = 0,
) -> SessionClaims:
    """Verify an SD-JWT session token off-chain.

    Args:
        token: SD-JWT compact serialization.
        secret: 32-byte HMAC-SHA256 shared secret.
        required_claims: Claims that MUST be disclosed.
        clock_tolerance_sec: Clock tolerance in seconds. Default: 0.

    Returns:
        Decoded SessionClaims.

    Raises:
        BolyraSessionError: On invalid signature, expiry, or missing claims.
    """
    parts = token.split("~")
    jwt_part = parts[0]
    disclosure_parts = [p for p in parts[1:] if p]

    # Verify JWT signature
    jwt_segments = jwt_part.split(".")
    if len(jwt_segments) != 3:
        raise BolyraSessionError("INVALID_TOKEN", "Malformed JWT: expected 3 parts")

    header_b64, payload_b64, signature_b64 = jwt_segments
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = _hmac_sign(secret, signing_input)

    if not hmac.compare_digest(expected_sig, signature_b64):
        raise BolyraSessionError(
            "INVALID_SIGNATURE", "JWT signature verification failed"
        )

    payload = json.loads(_b64url_decode(payload_b64))

    # Check expiry
    now = int(time.time())
    exp = payload["exp"]
    if exp <= now - clock_tolerance_sec:
        raise BolyraSessionError("TOKEN_EXPIRED", "Session token has expired")

    # Verify disclosures against _sd digests
    sd_digests = set(payload.get("_sd", []))
    claims: Dict[str, str] = {}

    for disc in disclosure_parts:
        digest = _b64url_encode(_sha256(disc))
        if digest not in sd_digests:
            raise BolyraSessionError(
                "INVALID_TOKEN",
                "Disclosure digest does not match any _sd entry",
            )
        decoded = json.loads(_b64url_decode(disc))
        _, claim_name, claim_value = decoded
        claims[claim_name] = claim_value

    # Check required claims
    if required_claims:
        for req in required_claims:
            if req not in claims:
                raise BolyraSessionError(
                    "CLAIMS_MISSING",
                    f"Required claim '{req}' was not disclosed",
                )

    return SessionClaims(
        nullifier_hash=claims.get("nullifierHash"),
        scope_commitment=claims.get("scopeCommitment"),
        human_merkle_root=claims.get("humanMerkleRoot"),
        agent_credential_hash=claims.get("agentCredentialHash"),
        model_hash=claims.get("modelHash"),
        operator_did=claims.get("operatorDID"),
        iat=payload["iat"],
        exp=exp,
        iss=payload["iss"],
    )
