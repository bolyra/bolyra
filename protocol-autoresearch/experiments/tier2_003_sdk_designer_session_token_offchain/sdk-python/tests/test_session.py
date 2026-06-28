"""Tests for SD-JWT session token (off-chain proof reuse)."""

import json
import hashlib
import hmac as _hmac
import os
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

import pytest

from bolyra.session import (
    HandshakeResult,
    SessionClaims,
    BolyraSessionError,
    issue_session_token,
    verify_session_token,
)


def _make_secret() -> bytes:
    return os.urandom(32)


def _make_handshake(**kwargs) -> HandshakeResult:
    defaults = dict(
        verified=True,
        nullifier_hash="0xaabbccdd11223344",
        human_merkle_root="0x1111111111111111",
        scope_commitment="0x3333333333333333",
        agent_credential_hash="0x4444444444444444",
    )
    defaults.update(kwargs)
    return HandshakeResult(**defaults)


class TestIssueSessionToken:
    def test_produces_sd_jwt_format(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret)
        parts = token.split("~")
        # JWT + at least 1 disclosure + trailing empty
        assert len(parts) > 2
        # JWT has 3 dot-separated segments
        assert len(parts[0].split(".")) == 3

    def test_rejects_unverified_handshake(self):
        secret = _make_secret()
        result = _make_handshake(verified=False)
        with pytest.raises(BolyraSessionError, match="unverified"):
            issue_session_token(result, secret)

    def test_rejects_ttl_below_minimum(self):
        secret = _make_secret()
        result = _make_handshake()
        with pytest.raises(BolyraSessionError, match="60"):
            issue_session_token(result, secret, ttl_seconds=30)

    def test_rejects_ttl_above_maximum(self):
        secret = _make_secret()
        result = _make_handshake()
        with pytest.raises(BolyraSessionError, match="3600"):
            issue_session_token(result, secret, ttl_seconds=7200)


class TestVerifySessionToken:
    def test_round_trip(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret)
        claims = verify_session_token(token, secret)
        assert claims.nullifier_hash == "0xaabbccdd11223344"
        assert claims.iss == "bolyra.ai"
        assert claims.exp - claims.iat == 300

    def test_custom_ttl(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret, ttl_seconds=120)
        claims = verify_session_token(token, secret)
        assert claims.exp - claims.iat == 120

    def test_rejects_expired_token(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret, ttl_seconds=60)

        # Tamper to set exp in the past, re-sign
        parts = token.split("~")
        jwt_parts = parts[0].split(".")
        payload_bytes = urlsafe_b64decode(jwt_parts[1] + "===")
        payload = json.loads(payload_bytes)
        payload["exp"] = int(time.time()) - 100

        new_payload_b64 = (
            urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )
        signing_input = f"{jwt_parts[0]}.{new_payload_b64}"
        sig = urlsafe_b64encode(
            _hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        expired_jwt = f"{signing_input}.{sig}"
        expired_token = f"{expired_jwt}~{'~'.join(parts[1:])}"

        with pytest.raises(BolyraSessionError, match="expired"):
            verify_session_token(expired_token, secret)

    def test_rejects_wrong_secret(self):
        secret = _make_secret()
        wrong_secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret)
        with pytest.raises(BolyraSessionError, match="signature"):
            verify_session_token(token, wrong_secret)

    def test_selective_disclosure_nullifier_only(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(
            result, secret, disclose=["nullifierHash"]
        )
        claims = verify_session_token(token, secret)
        assert claims.nullifier_hash == "0xaabbccdd11223344"
        assert claims.scope_commitment is None
        assert claims.human_merkle_root is None
        assert claims.agent_credential_hash is None

    def test_required_claims_enforcement(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(
            result, secret, disclose=["nullifierHash"]
        )
        with pytest.raises(BolyraSessionError, match="scopeCommitment"):
            verify_session_token(
                token, secret, required_claims=["scopeCommitment"]
            )

    def test_clock_tolerance(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret, ttl_seconds=60)
        claims = verify_session_token(
            token, secret, clock_tolerance_sec=5
        )
        assert claims.iss == "bolyra.ai"

    def test_rejects_tampered_disclosure(self):
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret)
        fake_disc = urlsafe_b64encode(
            json.dumps(["fakesalt", "fakeKey", "fakeVal"]).encode()
        ).rstrip(b"=").decode()
        tampered = token.rstrip("~") + "~" + fake_disc + "~"
        with pytest.raises(BolyraSessionError, match="digest"):
            verify_session_token(tampered, secret)

    def test_cross_language_claim_names(self):
        """Verify camelCase claim names in wire format match TS SDK."""
        secret = _make_secret()
        result = _make_handshake()
        token = issue_session_token(result, secret)
        # Parse raw disclosures to check claim names
        parts = token.split("~")
        disclosure_parts = [p for p in parts[1:] if p]
        claim_names = []
        for disc in disclosure_parts:
            decoded = json.loads(urlsafe_b64decode(disc + "==="))
            claim_names.append(decoded[1])
        # All should be camelCase
        for name in claim_names:
            assert name[0].islower(), f"Claim '{name}' should be camelCase"
