"""Tests for bolyra.types — dataclass construction and field access."""

import pytest

from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    DelegationResult,
    EdDSASignature,
    HandshakeResult,
    HumanIdentity,
    Permission,
    Point,
    Proof,
)


class TestPoint:
    def test_construction(self):
        p = Point(x=1, y=2)
        assert p.x == 1
        assert p.y == 2

    def test_immutable(self):
        p = Point(x=1, y=2)
        with pytest.raises(AttributeError):
            p.x = 3  # type: ignore[misc]

    def test_equality(self):
        assert Point(x=1, y=2) == Point(x=1, y=2)
        assert Point(x=1, y=2) != Point(x=1, y=3)


class TestHumanIdentity:
    def test_construction(self):
        pk = Point(x=100, y=200)
        identity = HumanIdentity(secret=42, public_key=pk, commitment=999)
        assert identity.secret == 42
        assert identity.public_key.x == 100
        assert identity.commitment == 999

    def test_immutable(self):
        pk = Point(x=100, y=200)
        identity = HumanIdentity(secret=42, public_key=pk, commitment=999)
        with pytest.raises(AttributeError):
            identity.secret = 0  # type: ignore[misc]

    def test_large_values(self):
        """Identities use BN254 field elements which are ~254-bit integers."""
        big = 2**253 + 7
        pk = Point(x=big, y=big + 1)
        identity = HumanIdentity(secret=big - 1, public_key=pk, commitment=big + 2)
        assert identity.secret == big - 1


class TestAgentCredential:
    def test_construction(self):
        pk = Point(x=10, y=20)
        sig = EdDSASignature(r8=Point(x=30, y=40), s=50)
        cred = AgentCredential(
            model_hash=123,
            operator_public_key=pk,
            permission_bitmask=0b111,
            expiry_timestamp=1700000000,
            signature=sig,
            commitment=456,
        )
        assert cred.model_hash == 123
        assert cred.operator_public_key == pk
        assert cred.permission_bitmask == 0b111
        assert cred.expiry_timestamp == 1700000000
        assert cred.signature.s == 50
        assert cred.commitment == 456

    def test_immutable(self):
        pk = Point(x=10, y=20)
        sig = EdDSASignature(r8=Point(x=30, y=40), s=50)
        cred = AgentCredential(
            model_hash=123,
            operator_public_key=pk,
            permission_bitmask=0b111,
            expiry_timestamp=1700000000,
            signature=sig,
            commitment=456,
        )
        with pytest.raises(AttributeError):
            cred.permission_bitmask = 0  # type: ignore[misc]


class TestHandshakeResult:
    def test_construction(self):
        result = HandshakeResult(
            human_nullifier=111,
            agent_nullifier=222,
            session_nonce=333,
            scope_commitment=444,
            verified=True,
        )
        assert result.human_nullifier == 111
        assert result.verified is True

    def test_not_verified(self):
        result = HandshakeResult(
            human_nullifier=0,
            agent_nullifier=0,
            session_nonce=0,
            scope_commitment=0,
            verified=False,
        )
        assert result.verified is False


class TestDelegationResult:
    def test_construction(self):
        result = DelegationResult(
            new_scope_commitment=555,
            delegation_nullifier=666,
            hop_index=0,
        )
        assert result.hop_index == 0
        assert result.new_scope_commitment == 555


class TestProof:
    def test_construction(self):
        proof = Proof(
            proof={"pi_a": [1, 2], "pi_b": [[3, 4], [5, 6]], "pi_c": [7, 8]},
            public_signals=["100", "200", "300"],
        )
        assert proof.public_signals == ["100", "200", "300"]
        assert proof.proof["pi_a"] == [1, 2]


class TestBolyraConfig:
    def test_defaults(self):
        config = BolyraConfig()
        assert config.rpc_url is None
        assert config.registry_address is None
        assert config.circuit_dir is None
        assert config.zkey_dir is None
        assert config.node_sdk_path is None

    def test_custom_values(self):
        config = BolyraConfig(
            rpc_url="https://sepolia.base.org",
            registry_address="0x1234",
            circuit_dir="/path/to/circuits",
            node_sdk_path="/path/to/sdk",
        )
        assert config.rpc_url == "https://sepolia.base.org"
        assert config.registry_address == "0x1234"

    def test_mutable(self):
        """BolyraConfig is mutable (not frozen) for easy reconfiguration."""
        config = BolyraConfig()
        config.rpc_url = "https://mainnet.base.org"
        assert config.rpc_url == "https://mainnet.base.org"


class TestPermissionEnum:
    def test_values(self):
        assert Permission.READ_DATA == 0
        assert Permission.WRITE_DATA == 1
        assert Permission.FINANCIAL_SMALL == 2
        assert Permission.FINANCIAL_MEDIUM == 3
        assert Permission.FINANCIAL_UNLIMITED == 4
        assert Permission.SIGN_ON_BEHALF == 5
        assert Permission.SUB_DELEGATE == 6
        assert Permission.ACCESS_PII == 7

    def test_is_int(self):
        assert isinstance(Permission.READ_DATA, int)

    def test_iteration(self):
        all_perms = list(Permission)
        assert len(all_perms) == 8
