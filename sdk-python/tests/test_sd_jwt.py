"""Tests for the pure-Python SD-JWT delegation module.

No Node.js required -- all tests use Ed25519 keys generated via cryptography.
"""

from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bolyra.sd_jwt import (
    AllowOptions,
    PresentOptions,
    VerifyOptions,
    VerifyResult,
    allow,
    generate_ed25519_keypair,
    present,
    verify,
    _b64url_decode,
    _b64url_encode,
    _decode_jws_header,
    _decode_jws_payload,
    _ed25519_pub_to_jwk,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def issuer_keys():
    """Generate issuer keypair."""
    return generate_ed25519_keypair()


@pytest.fixture
def holder_keys():
    """Generate holder (agent) keypair."""
    return generate_ed25519_keypair()


@pytest.fixture
def allow_opts(issuer_keys, holder_keys):
    """Standard AllowOptions for testing."""
    _, holder_pub = holder_keys
    return AllowOptions(
        iss="did:example:issuer",
        sub="agent-alice",
        aud="tool.example.com",
        act="checkout.charge",
        perm="FINANCIAL_SMALL",
        agent_pub_key=holder_pub,
        ttl_seconds=300,
        jti="test-jti-001",
    )


@pytest.fixture
def issued_receipt(allow_opts, issuer_keys):
    """Issue a receipt for testing."""
    priv, _ = issuer_keys
    return allow(allow_opts, priv, "issuer-key-1")


# ---------------------------------------------------------------------------
# allow() tests
# ---------------------------------------------------------------------------

class TestAllow:
    def test_returns_issuer_form(self, issued_receipt):
        """Receipt ends with ~ (issuer-form)."""
        assert issued_receipt.endswith("~")
        parts = issued_receipt.split("~")
        assert len(parts) == 2
        assert parts[1] == ""

    def test_header_fields(self, issued_receipt):
        """Header has correct alg, typ, kid, _sd_alg."""
        jws = issued_receipt.rstrip("~")
        hdr = _decode_jws_header(jws)
        assert hdr["alg"] == "EdDSA"
        assert hdr["typ"] == "bolyra-delegation+sd-jwt"
        assert hdr["kid"] == "issuer-key-1"
        assert hdr["_sd_alg"] == "sha-256"

    def test_payload_claims(self, issued_receipt, allow_opts):
        """Payload contains all required claims."""
        jws = issued_receipt.rstrip("~")
        payload = _decode_jws_payload(jws)
        assert payload["iss"] == "did:example:issuer"
        assert payload["sub"] == "agent-alice"
        assert payload["aud"] == "tool.example.com"
        assert payload["act"] == "checkout.charge"
        assert payload["perm"] == "FINANCIAL_SMALL"
        assert payload["jti"] == "test-jti-001"
        assert isinstance(payload["iat"], int)
        assert isinstance(payload["exp"], int)
        assert payload["exp"] - payload["iat"] == 300

    def test_cnf_claim(self, issued_receipt, holder_keys):
        """cnf.jwk matches the holder's public key."""
        _, holder_pub = holder_keys
        jws = issued_receipt.rstrip("~")
        payload = _decode_jws_payload(jws)
        cnf = payload["cnf"]
        assert cnf["jwk"]["kty"] == "OKP"
        assert cnf["jwk"]["crv"] == "Ed25519"
        expected_jwk = _ed25519_pub_to_jwk(holder_pub)
        assert cnf["jwk"]["x"] == expected_jwk["x"]

    def test_sd_array_empty(self, issued_receipt):
        """_sd is an empty array (no selective disclosures in v0.2)."""
        jws = issued_receipt.rstrip("~")
        payload = _decode_jws_payload(jws)
        assert payload["_sd"] == []

    def test_max_amount_included(self, issuer_keys, holder_keys):
        """max claim is included when specified."""
        priv, _ = issuer_keys
        _, holder_pub = holder_keys
        opts = AllowOptions(
            iss="issuer", sub="agent", aud="aud", act="act", perm="READ_DATA",
            agent_pub_key=holder_pub,
            max_amount={"amount": 50, "currency": "USD"},
        )
        receipt = allow(opts, priv, "kid-1")
        jws = receipt.rstrip("~")
        payload = _decode_jws_payload(jws)
        assert payload["max"] == {"amount": 50, "currency": "USD"}

    def test_empty_kid_raises(self, issuer_keys, holder_keys):
        """Empty issuer_kid raises ValueError."""
        priv, _ = issuer_keys
        _, holder_pub = holder_keys
        opts = AllowOptions(
            iss="issuer", sub="agent", aud="aud", act="act", perm="READ_DATA",
            agent_pub_key=holder_pub,
        )
        with pytest.raises(ValueError, match="issuer_kid must not be empty"):
            allow(opts, priv, "")

    def test_auto_jti(self, issuer_keys, holder_keys):
        """When jti is not specified, a UUID is generated."""
        priv, _ = issuer_keys
        _, holder_pub = holder_keys
        opts = AllowOptions(
            iss="issuer", sub="agent", aud="aud", act="act", perm="READ_DATA",
            agent_pub_key=holder_pub,
        )
        receipt = allow(opts, priv, "kid-1")
        jws = receipt.rstrip("~")
        payload = _decode_jws_payload(jws)
        assert len(payload["jti"]) > 0


# ---------------------------------------------------------------------------
# present() tests
# ---------------------------------------------------------------------------

class TestPresent:
    def test_presented_form(self, issued_receipt, holder_keys):
        """Presented receipt has form jws~~kbjwt."""
        priv, _ = holder_keys
        presented = present(
            issued_receipt, priv, PresentOptions(nonce="challenge-1", audience="tool.example.com")
        )
        parts = presented.split("~")
        assert len(parts) == 3
        assert parts[1] == ""
        assert len(parts[0]) > 0  # jws
        assert len(parts[2]) > 0  # kb-jwt

    def test_kb_jwt_header(self, issued_receipt, holder_keys):
        """KB-JWT has correct header."""
        priv, _ = holder_keys
        presented = present(
            issued_receipt, priv, PresentOptions(nonce="n", audience="aud")
        )
        kb_jwt = presented.split("~")[2]
        hdr = _decode_jws_header(kb_jwt)
        assert hdr["alg"] == "EdDSA"
        assert hdr["typ"] == "kb+jwt"

    def test_kb_jwt_payload(self, issued_receipt, holder_keys):
        """KB-JWT payload contains aud, nonce, sd_hash, iat."""
        priv, _ = holder_keys
        presented = present(
            issued_receipt, priv, PresentOptions(nonce="test-nonce", audience="tool.example.com")
        )
        kb_jwt = presented.split("~")[2]
        payload = _decode_jws_payload(kb_jwt)
        assert payload["aud"] == "tool.example.com"
        assert payload["nonce"] == "test-nonce"
        assert "sd_hash" in payload
        assert isinstance(payload["iat"], int)

    def test_sd_hash_matches(self, issued_receipt, holder_keys):
        """sd_hash in KB-JWT matches SHA-256 of <jws>~."""
        import hashlib
        priv, _ = holder_keys
        presented = present(
            issued_receipt, priv, PresentOptions(nonce="n", audience="aud")
        )
        jws = presented.split("~")[0]
        kb_jwt = presented.split("~")[2]
        payload = _decode_jws_payload(kb_jwt)
        expected = _b64url_encode(hashlib.sha256(f"{jws}~".encode()).digest())
        assert payload["sd_hash"] == expected

    def test_wrong_holder_key_rejected(self, issued_receipt):
        """Presenting with a different holder key raises ValueError."""
        wrong_priv, _ = generate_ed25519_keypair()
        with pytest.raises(ValueError, match="holder key thumbprint does not match"):
            present(
                issued_receipt, wrong_priv, PresentOptions(nonce="n", audience="aud")
            )

    def test_already_presented_rejected(self, issued_receipt, holder_keys):
        """Cannot present an already-presented receipt."""
        priv, _ = holder_keys
        presented = present(
            issued_receipt, priv, PresentOptions(nonce="n", audience="aud")
        )
        with pytest.raises(ValueError, match="already presented"):
            present(presented, priv, PresentOptions(nonce="n", audience="aud"))

    def test_non_sd_jwt_rejected(self):
        """Cannot present a plain JWS (no tilde)."""
        priv, _ = generate_ed25519_keypair()
        with pytest.raises(ValueError, match="not SD-JWT shaped"):
            present("not.an.sdjwt", priv, PresentOptions(nonce="n", audience="aud"))


# ---------------------------------------------------------------------------
# verify() tests
# ---------------------------------------------------------------------------

class TestVerify:
    def _full_roundtrip(self, issuer_keys, holder_keys, **allow_kwargs):
        """Helper: allow -> present -> verify."""
        issuer_priv, issuer_pub = issuer_keys
        holder_priv, holder_pub = holder_keys
        opts = AllowOptions(
            iss="did:example:issuer",
            sub="agent-alice",
            aud="tool.example.com",
            act="checkout.charge",
            perm="FINANCIAL_SMALL",
            agent_pub_key=holder_pub,
            ttl_seconds=300,
            jti="test-jti-roundtrip",
            **allow_kwargs,
        )
        receipt = allow(opts, issuer_priv, "kid-1")
        presented = present(
            receipt, holder_priv,
            PresentOptions(nonce="verify-nonce", audience="tool.example.com"),
        )
        return presented, issuer_pub

    def test_roundtrip_success(self, issuer_keys, holder_keys):
        """Full allow -> present -> verify succeeds."""
        presented, issuer_pub = self._full_roundtrip(issuer_keys, holder_keys)
        result = verify(presented, VerifyOptions(
            expected_audience="tool.example.com",
            issuer_public_key=issuer_pub,
            expected_nonce="verify-nonce",
        ))
        assert result.ok is True
        assert result.claims is not None
        assert result.claims["sub"] == "agent-alice"
        assert result.claims["act"] == "checkout.charge"

    def test_wrong_issuer_key(self, issuer_keys, holder_keys):
        """Verification fails with wrong issuer key."""
        presented, _ = self._full_roundtrip(issuer_keys, holder_keys)
        _, wrong_pub = generate_ed25519_keypair()
        result = verify(presented, VerifyOptions(
            expected_audience="tool.example.com",
            issuer_public_key=wrong_pub,
            expected_nonce="verify-nonce",
        ))
        assert result.ok is False
        assert result.reason == "INVALID_SIGNATURE"

    def test_wrong_audience(self, issuer_keys, holder_keys):
        """Verification fails with wrong audience."""
        presented, issuer_pub = self._full_roundtrip(issuer_keys, holder_keys)
        result = verify(presented, VerifyOptions(
            expected_audience="wrong.audience.com",
            issuer_public_key=issuer_pub,
            expected_nonce="verify-nonce",
        ))
        assert result.ok is False
        assert result.reason == "WRONG_AUDIENCE"

    def test_wrong_nonce(self, issuer_keys, holder_keys):
        """Verification fails with wrong nonce."""
        presented, issuer_pub = self._full_roundtrip(issuer_keys, holder_keys)
        result = verify(presented, VerifyOptions(
            expected_audience="tool.example.com",
            issuer_public_key=issuer_pub,
            expected_nonce="wrong-nonce",
        ))
        assert result.ok is False
        assert result.reason == "KB_WRONG_NONCE"

    def test_no_nonce_fails(self, issuer_keys, holder_keys):
        """Verification fails when nonce is not provided."""
        presented, issuer_pub = self._full_roundtrip(issuer_keys, holder_keys)
        result = verify(presented, VerifyOptions(
            expected_audience="tool.example.com",
            issuer_public_key=issuer_pub,
            # expected_nonce deliberately omitted
        ))
        assert result.ok is False
        assert result.reason == "KB_NONCE_REQUIRED"

    def test_issuer_form_rejected(self, issued_receipt, issuer_keys):
        """Issuer-form receipt (no KB-JWT) is rejected."""
        _, issuer_pub = issuer_keys
        result = verify(issued_receipt, VerifyOptions(
            expected_audience="tool.example.com",
            issuer_public_key=issuer_pub,
            expected_nonce="n",
        ))
        assert result.ok is False
        assert result.reason == "KB_MISSING"

    def test_plain_jws_rejected(self, issuer_keys):
        """Plain JWS (no tilde) is rejected as legacy."""
        _, issuer_pub = issuer_keys
        result = verify("not.a.sdjwt", VerifyOptions(
            expected_audience="aud",
            issuer_public_key=issuer_pub,
            expected_nonce="n",
        ))
        assert result.ok is False
        assert result.reason == "LEGACY_V01_REJECTED"

    def test_expected_issuer_mismatch(self, issuer_keys, holder_keys):
        """Verification fails when expected_issuer doesn't match."""
        presented, issuer_pub = self._full_roundtrip(issuer_keys, holder_keys)
        result = verify(presented, VerifyOptions(
            expected_audience="tool.example.com",
            issuer_public_key=issuer_pub,
            expected_nonce="verify-nonce",
            expected_issuer="did:example:wrong",
        ))
        assert result.ok is False
        assert result.reason == "WRONG_ISSUER"

    def test_no_issuer_key_fails(self, issuer_keys, holder_keys):
        """Verification fails when no issuer key provided."""
        presented, _ = self._full_roundtrip(issuer_keys, holder_keys)
        result = verify(presented, VerifyOptions(
            expected_audience="tool.example.com",
            expected_nonce="verify-nonce",
            # issuer_public_key deliberately omitted
        ))
        assert result.ok is False
        assert result.reason == "KID_RESOLVER_ERROR"


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------

class TestKeyGeneration:
    def test_generate_keypair(self):
        """generate_ed25519_keypair returns valid key pair."""
        priv, pub = generate_ed25519_keypair()
        assert isinstance(priv, Ed25519PrivateKey)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        assert isinstance(pub, Ed25519PublicKey)

    def test_jwk_export(self):
        """Ed25519 public key exports to valid JWK."""
        _, pub = generate_ed25519_keypair()
        jwk = _ed25519_pub_to_jwk(pub)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert len(jwk["x"]) > 0
