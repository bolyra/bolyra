"""Pure-Python SD-JWT delegation receipts.

Implements the Bolyra SD-JWT delegation surface (v0.2) using PyJWT + cryptography
for Ed25519. Wire format matches ``@bolyra/delegation`` exactly:

- ``allow()``: Issue an SD-JWT receipt (issuer-form: ``jws~``)
- ``present()``: Append a KB-JWT for holder binding (``jws~~kbjwt``)
- ``verify()``: Verify issuer signature, claims, cnf binding, and KB-JWT

No Node.js or subprocess bridge required -- this is the "lightweight" delegation
path for environments where the ZKP circuit machinery is not available.

Wire format details (must match TS):
- JWS header: ``{"alg": "EdDSA", "typ": "bolyra-delegation+sd-jwt", "kid": "...", "_sd_alg": "sha-256"}``
- Body claims: iss, sub, aud, act, perm, iat, exp, jti, cnf, _sd
- Issuer-form: ``<jws>~``
- Presented form: ``<jws>~~<kbjwt>``
- KB-JWT header: ``{"alg": "EdDSA", "typ": "kb+jwt"}``
- KB-JWT body: aud, nonce, sd_hash, iat
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class AllowOptions:
    """Options for issuing an SD-JWT delegation receipt."""

    iss: str
    """Issuer DID/URL."""
    sub: str
    """Subject (agent identifier)."""
    aud: str
    """Audience (RP/merchant)."""
    act: str
    """Action label, e.g. 'checkout.charge'."""
    perm: str
    """Permission label, e.g. 'READ_DATA'."""
    agent_pub_key: Ed25519PublicKey
    """Agent's holder public key for cnf binding."""
    max_amount: dict[str, Any] | None = None
    """Optional per-invocation cap: {"amount": 50, "currency": "USD"}."""
    ttl_seconds: int = 300
    """Receipt lifetime in seconds."""
    jti: str | None = None
    """Optional explicit JTI (for deterministic flows/tests)."""
    status_list: dict[str, Any] | None = None
    """Optional IETF status-list slot: {"uri": "https://...", "idx": 0}."""
    parent_jti: str | None = None
    """Optional parent JTI for delegation chaining."""


@dataclass
class PresentOptions:
    """Options for presenting an SD-JWT receipt."""

    nonce: str
    """Challenge nonce from the verifier."""
    audience: str
    """Audience the KB-JWT is presented to."""


@dataclass
class VerifyOptions:
    """Options for verifying an SD-JWT receipt."""

    expected_audience: str
    """Required audience claim."""
    expected_issuer: str | None = None
    """If set, iss must match."""
    issuer_public_key: Ed25519PublicKey | None = None
    """Issuer's Ed25519 public key for signature verification."""
    expected_nonce: str | None = None
    """Required KB-JWT nonce."""
    max_kb_iat_skew_seconds: int = 60
    """Maximum KB-JWT age in seconds."""
    clock_skew_seconds: int = 30
    """Clock tolerance in seconds."""


@dataclass
class VerifyResult:
    """Result of SD-JWT verification."""

    ok: bool
    claims: dict[str, Any] | None = None
    reason: str | None = None
    detail: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _ed25519_pub_to_jwk(pub_key: Ed25519PublicKey) -> dict[str, str]:
    """Export Ed25519 public key to JWK format (kty, crv, x)."""
    raw = pub_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(raw),
    }


def _sign_jws(header: dict, payload: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign a JWS (compact serialization) with Ed25519."""
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _verify_jws_signature(jws: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Verify JWS signature and return decoded payload.

    Raises ValueError on invalid signature or malformed JWS.
    """
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWS: expected 3 dot-separated parts")

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = _b64url_decode(parts[2])

    # This raises InvalidSignature on failure
    public_key.verify(signature, signing_input)

    payload_bytes = _b64url_decode(parts[1])
    return json.loads(payload_bytes)


def _decode_jws_header(jws: str) -> dict[str, Any]:
    """Decode JWS protected header without verification."""
    parts = jws.split(".")
    if len(parts) < 3:
        raise ValueError("Malformed JWS")
    return json.loads(_b64url_decode(parts[0]))


def _decode_jws_payload(jws: str) -> dict[str, Any]:
    """Decode JWS payload without verification."""
    parts = jws.split(".")
    if len(parts) < 3:
        raise ValueError("Malformed JWS")
    return json.loads(_b64url_decode(parts[1]))


def _jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 JWK thumbprint for Ed25519 keys."""
    # For OKP keys, the required members in lexicographic order are: crv, kty, x
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return _b64url_encode(digest)


# ---------------------------------------------------------------------------
# Key generation (dev mode)
# ---------------------------------------------------------------------------

def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair for delegation receipts.

    Returns (private_key, public_key). For dev/test only -- production
    systems should use a proper key management system.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


# ---------------------------------------------------------------------------
# allow()
# ---------------------------------------------------------------------------

def allow(
    opts: AllowOptions,
    issuer_private_key: Ed25519PrivateKey,
    issuer_kid: str,
) -> str:
    """Issue an SD-JWT delegation receipt (issuer-form).

    Returns the receipt as a string in issuer-form: ``<jws>~``

    The wire format matches ``@bolyra/delegation``'s ``allow()`` exactly:
    - Header: ``{"alg":"EdDSA","typ":"bolyra-delegation+sd-jwt","kid":"...","_sd_alg":"sha-256"}``
    - Body: iss, sub, aud, act, perm, iat, exp, jti, cnf (with Ed25519 JWK), _sd: []

    Args:
        opts: Issuance options (see AllowOptions).
        issuer_private_key: Issuer's Ed25519 private key.
        issuer_kid: Key ID for the issuer key.

    Returns:
        SD-JWT issuer-form string (``<jws>~``).

    Raises:
        ValueError: If issuer_kid is empty or agent_pub_key is not Ed25519.
    """
    if not issuer_kid:
        raise ValueError("allow: issuer_kid must not be empty")

    cnf_jwk = _ed25519_pub_to_jwk(opts.agent_pub_key)

    now = int(time.time())
    exp = now + opts.ttl_seconds

    header = {
        "alg": "EdDSA",
        "typ": "bolyra-delegation+sd-jwt",
        "kid": issuer_kid,
        "_sd_alg": "sha-256",
    }

    payload: dict[str, Any] = {
        "iss": opts.iss,
        "sub": opts.sub,
        "aud": opts.aud,
        "act": opts.act,
        "perm": opts.perm,
        "iat": now,
        "exp": exp,
        "jti": opts.jti or str(uuid.uuid4()),
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": cnf_jwk["x"]}},
        "_sd": [],
    }
    if opts.max_amount:
        payload["max"] = opts.max_amount
    if opts.status_list:
        payload["status"] = {"status_list": opts.status_list}
    if opts.parent_jti:
        payload["parent_jti"] = opts.parent_jti

    jws = _sign_jws(header, payload, issuer_private_key)
    return f"{jws}~"


# ---------------------------------------------------------------------------
# present()
# ---------------------------------------------------------------------------

def present(
    receipt: str,
    holder_private_key: Ed25519PrivateKey,
    opts: PresentOptions,
) -> str:
    """Present an SD-JWT receipt by appending a KB-JWT.

    Takes an issuer-form receipt (``<jws>~``) and appends a Key Binding JWT
    signed by the holder's private key. The KB-JWT binds the presentation
    to a specific audience and nonce.

    Returns the presented form: ``<jws>~~<kbjwt>``

    Args:
        receipt: Issuer-form SD-JWT (must end with ``~``).
        holder_private_key: Holder's Ed25519 private key (must match cnf.jwk).
        opts: Presentation options (nonce, audience).

    Returns:
        Presented SD-JWT string (``<jws>~~<kbjwt>``).

    Raises:
        ValueError: If receipt is malformed or holder key doesn't match cnf.
    """
    if "~" not in receipt:
        raise ValueError("present: receipt is not SD-JWT shaped (missing '~')")

    parts = receipt.split("~")
    if len(parts) == 3 and parts[1] == "" and len(parts[2]) > 0:
        raise ValueError("present: receipt already presented")
    if len(parts) != 2 or parts[1] != "":
        raise ValueError("present: receipt malformed")

    jws = parts[0]

    # Decode claims (no verification -- holder doesn't necessarily have issuer key)
    claims = _decode_jws_payload(jws)

    cnf = claims.get("cnf")
    if not cnf or not isinstance(cnf, dict) or "jwk" not in cnf:
        raise ValueError("present: receipt has no cnf.jwk")

    # Verify holder key matches cnf.jwk
    holder_pub = holder_private_key.public_key()
    holder_jwk = _ed25519_pub_to_jwk(holder_pub)
    tp_holder = _jwk_thumbprint(holder_jwk)
    tp_cnf = _jwk_thumbprint(cnf["jwk"])
    if tp_holder != tp_cnf:
        raise ValueError("present: holder key thumbprint does not match cnf.jwk")

    # Compute sd_hash = base64url(SHA-256("<jws>~"))
    sd_hash_bytes = hashlib.sha256(f"{jws}~".encode()).digest()
    sd_hash = _b64url_encode(sd_hash_bytes)

    # Build and sign KB-JWT
    kb_header = {"alg": "EdDSA", "typ": "kb+jwt"}
    kb_payload = {
        "aud": opts.audience,
        "nonce": opts.nonce,
        "sd_hash": sd_hash,
        "iat": int(time.time()),
    }
    kb_jwt = _sign_jws(kb_header, kb_payload, holder_private_key)

    return f"{jws}~~{kb_jwt}"


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------

def verify(
    receipt: str,
    opts: VerifyOptions,
) -> VerifyResult:
    """Verify an SD-JWT delegation receipt.

    Implements the Bolyra SD-JWT verification flow:
    1. Structural triage (count tildes)
    2. Header check (alg, typ, kid)
    3. Issuer signature verification
    4. Claim checks (exp, iat, aud, iss)
    5. cnf + KB-JWT verification

    Args:
        receipt: SD-JWT receipt string.
        opts: Verification options.

    Returns:
        VerifyResult with ok=True and claims on success, or ok=False with reason.
    """
    from cryptography.exceptions import InvalidSignature

    # Step 1: structural triage
    tilde_count = receipt.count("~")
    if tilde_count == 0:
        return VerifyResult(ok=False, reason="LEGACY_V01_REJECTED")
    if tilde_count == 1 and receipt.endswith("~"):
        return VerifyResult(ok=False, reason="KB_MISSING")
    if tilde_count != 2:
        return VerifyResult(ok=False, reason="SD_JWT_MALFORMED")

    parts = receipt.split("~")
    jws = parts[0]
    kb_jwt = parts[2]
    if not jws or not kb_jwt:
        return VerifyResult(ok=False, reason="SD_JWT_MALFORMED")

    # Step 2: header introspection
    try:
        hdr = _decode_jws_header(jws)
    except Exception:
        return VerifyResult(ok=False, reason="SD_JWT_MALFORMED")

    if hdr.get("alg") != "EdDSA":
        return VerifyResult(ok=False, reason="UNSUPPORTED_ALG")
    if hdr.get("typ") != "bolyra-delegation+sd-jwt":
        return VerifyResult(ok=False, reason="TYP_MISMATCH")
    kid = hdr.get("kid", "")
    if not kid:
        return VerifyResult(ok=False, reason="KID_MISSING")

    # Step 3: issuer key resolution + signature verification
    if not opts.issuer_public_key:
        return VerifyResult(
            ok=False,
            reason="KID_RESOLVER_ERROR",
            detail="issuer_public_key is required for verification",
        )

    try:
        claims = _verify_jws_signature(jws, opts.issuer_public_key)
    except (InvalidSignature, Exception):
        return VerifyResult(ok=False, reason="INVALID_SIGNATURE")

    now = int(time.time())
    skew = opts.clock_skew_seconds

    # Step 4: claim checks
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp + skew < now:
        return VerifyResult(ok=False, reason="EXPIRED")

    iat = claims.get("iat")
    if isinstance(iat, (int, float)) and iat - skew > now:
        return VerifyResult(ok=False, reason="FUTURE_NBF")

    if claims.get("aud") != opts.expected_audience:
        return VerifyResult(ok=False, reason="WRONG_AUDIENCE")

    if opts.expected_issuer and claims.get("iss") != opts.expected_issuer:
        return VerifyResult(ok=False, reason="WRONG_ISSUER")

    # Step 5: cnf + KB-JWT verification
    cnf = claims.get("cnf")
    if not cnf or not isinstance(cnf, dict) or "jwk" not in cnf:
        return VerifyResult(ok=False, reason="CNF_MISSING")

    if opts.expected_nonce is None:
        return VerifyResult(ok=False, reason="KB_NONCE_REQUIRED")

    # Verify KB-JWT
    kb_result = _verify_kb_jwt(kb_jwt, jws, cnf["jwk"], opts, now)
    if kb_result is not None:
        return VerifyResult(ok=False, reason=kb_result)

    return VerifyResult(ok=True, claims=claims)


def _verify_kb_jwt(
    kb_jwt: str,
    issuer_jws: str,
    cnf_jwk: dict[str, str],
    opts: VerifyOptions,
    now: int,
) -> str | None:
    """Verify KB-JWT. Returns None on success, or a failure reason string."""
    from cryptography.exceptions import InvalidSignature

    # Decode KB-JWT header
    try:
        kb_hdr = _decode_jws_header(kb_jwt)
    except Exception:
        return "KB_BAD_FORMAT"

    if kb_hdr.get("typ") != "kb+jwt":
        return "KB_TYP_INVALID"
    if kb_hdr.get("alg") != "EdDSA":
        return "KB_ALG_UNSUPPORTED"

    # Import cnf.jwk as Ed25519PublicKey
    try:
        x_bytes = _b64url_decode(cnf_jwk["x"])
        holder_pub = Ed25519PublicKey.from_public_bytes(x_bytes)
    except Exception:
        return "CNF_JWK_INVALID"

    # Verify KB-JWT signature
    try:
        kb_payload = _verify_jws_signature(kb_jwt, holder_pub)
    except (InvalidSignature, Exception):
        return "KB_INVALID_SIGNATURE"

    # Check audience
    if kb_payload.get("aud") != opts.expected_audience:
        return "KB_WRONG_AUDIENCE"

    # Check nonce
    if kb_payload.get("nonce") != opts.expected_nonce:
        return "KB_WRONG_NONCE"

    # Check sd_hash
    expected_hash = _b64url_encode(
        hashlib.sha256(f"{issuer_jws}~".encode()).digest()
    )
    if kb_payload.get("sd_hash") != expected_hash:
        return "KB_WRONG_SD_HASH"

    # Check iat
    kb_iat = kb_payload.get("iat")
    if not isinstance(kb_iat, (int, float)):
        return "KB_BAD_FORMAT"

    skew = opts.clock_skew_seconds
    max_age = opts.max_kb_iat_skew_seconds
    if kb_iat - skew > now:
        return "KB_IAT_FUTURE"
    if now - kb_iat > max_age + skew:
        return "KB_IAT_TOO_OLD"

    return None
