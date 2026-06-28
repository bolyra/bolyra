"""Tests for off-chain session tokens (JWT + EdDSA)."""

import time
from unittest.mock import patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bolyra.session import (
    BolyraSessionError,
    HandshakeVerifyResult,
    SessionClaims,
    mint_session_token,
    verify_session_token,
)


@pytest.fixture()
def ed25519_keys():
    """Generate an Ed25519 key pair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def make_verify_result(**overrides) -> HandshakeVerifyResult:
    defaults = dict(
        valid=True,
        nullifier_hash="0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
        scope_commitment="0x1122334455667788112233445566778811223344556677881122334455667788",
        session_nonce="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    )
    defaults.update(overrides)
    return HandshakeVerifyResult(**defaults)


class TestMintSessionToken:
    def test_produces_valid_jwt(self, ed25519_keys):
        private_key, _ = ed25519_keys
        result = make_verify_result()
        token = mint_session_token(result, private_key)
        parts = token.split(".")
        assert len(parts) == 3

    def test_rejects_invalid_handshake(self, ed25519_keys):
        private_key, _ = ed25519_keys
        result = make_verify_result(valid=False)
        with pytest.raises(BolyraSessionError, match="invalid handshake"):
            mint_session_token(result, private_key)

    def test_rejects_ttl_below_minimum(self, ed25519_keys):
        private_key, _ = ed25519_keys
        result = make_verify_result()
        with pytest.raises(BolyraSessionError, match="60"):
            mint_session_token(result, private_key, ttl_seconds=30)

    def test_rejects_ttl_above_maximum(self, ed25519_keys):
        private_key, _ = ed25519_keys
        result = make_verify_result()
        with pytest.raises(BolyraSessionError, match="900"):
            mint_session_token(result, private_key, ttl_seconds=1800)


class TestVerifySessionToken:
    def test_round_trip(self, ed25519_keys):
        private_key, public_key = ed25519_keys
        result = make_verify_result()
        token = mint_session_token(result, private_key)
        claims = verify_session_token(token, public_key)

        assert claims.nullifier_hash == result.nullifier_hash
        assert claims.scope_commitment == result.scope_commitment
        assert claims.session_nonce == result.session_nonce

    def test_default_ttl_300s(self, ed25519_keys):
        private_key, public_key = ed25519_keys
        result = make_verify_result()
        token = mint_session_token(result, private_key)
        claims = verify_session_token(token, public_key)

        assert claims.exp - claims.iat == 300

    def test_custom_ttl(self, ed25519_keys):
        private_key, public_key = ed25519_keys
        result = make_verify_result()
        token = mint_session_token(result, private_key, ttl_seconds=120)
        claims = verify_session_token(token, public_key)

        assert claims.exp - claims.iat == 120

    def test_rejects_expired_token(self, ed25519_keys):
        private_key, public_key = ed25519_keys
        result = make_verify_result()

        # Mint with minimum TTL, then advance time past expiry
        token = mint_session_token(result, private_key, ttl_seconds=60)

        with patch("jwt.api_jwt.datetime") as mock_dt:
            import datetime

            future = datetime.datetime.fromtimestamp(
                time.time() + 120, tz=datetime.timezone.utc
            )
            mock_dt.now.return_value = future
            # PyJWT checks utcnow or now(tz=utc); either way we need timedelta
            mock_dt.side_effect = lambda *a, **kw: datetime.datetime(*a, **kw)

        # Simpler approach: decode with leeway=-999 won't work.
        # Instead, forge a token that is already expired.
        now = int(time.time())
        expired_payload = {
            "nullifierHash": result.nullifier_hash,
            "scopeCommitment": result.scope_commitment,
            "sessionNonce": result.session_nonce,
            "iat": now - 600,
            "exp": now - 300,
            "iss": "bolyra.ai",
        }
        expired_token = pyjwt.encode(
            expired_payload, private_key, algorithm="EdDSA", headers={"typ": "JWT"}
        )

        with pytest.raises(BolyraSessionError) as exc_info:
            verify_session_token(expired_token, public_key)
        assert exc_info.value.code == "TOKEN_EXPIRED"

    def test_rejects_tampered_claims(self, ed25519_keys):
        private_key, public_key = ed25519_keys
        result = make_verify_result()
        token = mint_session_token(result, private_key)

        # Flip a character in the payload
        parts = token.split(".")
        p = parts[1]
        parts[1] = p[:-1] + ("B" if p[-1] == "A" else "A")
        tampered = ".".join(parts)

        with pytest.raises(BolyraSessionError) as exc_info:
            verify_session_token(tampered, public_key)
        assert exc_info.value.code == "INVALID_SIGNATURE"

    def test_rejects_wrong_key(self, ed25519_keys):
        private_key, _ = ed25519_keys
        other_private = Ed25519PrivateKey.generate()
        other_public = other_private.public_key()

        result = make_verify_result()
        token = mint_session_token(result, private_key)

        # Verify with the wrong public key
        with pytest.raises(BolyraSessionError) as exc_info:
            verify_session_token(token, other_public)
        assert exc_info.value.code == "INVALID_SIGNATURE"

    def test_returns_session_claims_type(self, ed25519_keys):
        private_key, public_key = ed25519_keys
        result = make_verify_result()
        token = mint_session_token(result, private_key)
        claims = verify_session_token(token, public_key)

        assert isinstance(claims, SessionClaims)
        assert isinstance(claims.iat, int)
        assert isinstance(claims.exp, int)
