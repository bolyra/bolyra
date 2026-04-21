"""Core types for the Bolyra SDK.

All types are plain dataclasses with no external dependencies.
Mirrors the TypeScript SDK's type definitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Permission(IntEnum):
    """Permission bits using cumulative encoding.

    Financial permissions are cumulative:
    - FINANCIAL_MEDIUM implies FINANCIAL_SMALL
    - FINANCIAL_UNLIMITED implies FINANCIAL_MEDIUM and FINANCIAL_SMALL
    """

    READ_DATA = 0
    WRITE_DATA = 1
    FINANCIAL_SMALL = 2       # < $100
    FINANCIAL_MEDIUM = 3      # < $10,000 (implies SMALL)
    FINANCIAL_UNLIMITED = 4   # unlimited (implies MEDIUM + SMALL)
    SIGN_ON_BEHALF = 5
    SUB_DELEGATE = 6
    ACCESS_PII = 7


@dataclass(frozen=True)
class Point:
    """Baby Jubjub curve point (public key coordinates)."""

    x: int
    y: int


@dataclass(frozen=True)
class EdDSASignature:
    """EdDSA signature components."""

    r8: Point
    s: int


@dataclass(frozen=True)
class HumanIdentity:
    """EdDSA identity for a human participant.

    Attributes:
        secret: EdDSA secret scalar (KEEP PRIVATE).
        public_key: Baby Jubjub public key coordinates.
        commitment: Poseidon2(Ax, Ay) -- leaf in humanTree.
    """

    secret: int
    public_key: Point
    commitment: int


@dataclass(frozen=True)
class AgentCredential:
    """AI agent credential signed by an operator.

    Attributes:
        model_hash: Hash of the model identifier (e.g., sha256("gpt-4o")).
        operator_public_key: Operator's Baby Jubjub public key.
        permission_bitmask: Encoded permission flags.
        expiry_timestamp: Unix timestamp when the credential expires.
        signature: EdDSA signature of operator over credential commitment.
        commitment: Poseidon5(modelHash, Ax, Ay, bitmask, expiry) -- leaf in agentTree.
    """

    model_hash: int
    operator_public_key: Point
    permission_bitmask: int
    expiry_timestamp: int
    signature: EdDSASignature
    commitment: int


@dataclass(frozen=True)
class HandshakeResult:
    """Result of a mutual handshake verification.

    Attributes:
        human_nullifier: Human's nullifier (unique per scope).
        agent_nullifier: Agent's nullifier (unique per session).
        session_nonce: Session nonce used.
        scope_commitment: Agent's scope commitment (chain seed for delegation).
        verified: Whether the handshake was verified.
    """

    human_nullifier: int
    agent_nullifier: int
    session_nonce: int
    scope_commitment: int
    verified: bool


@dataclass(frozen=True)
class DelegationResult:
    """Result of a delegation.

    Attributes:
        new_scope_commitment: New scope commitment for the next hop.
        delegation_nullifier: Unique per delegation per session.
        hop_index: Hop number in the chain (0-indexed).
    """

    new_scope_commitment: int
    delegation_nullifier: int
    hop_index: int


@dataclass(frozen=True)
class Proof:
    """ZK proof with public signals, ready for on-chain verification."""

    proof: dict[str, Any]
    public_signals: list[str]


@dataclass
class BolyraConfig:
    """Configuration for the Bolyra SDK.

    Attributes:
        rpc_url: RPC URL for the target chain (default: Base Sepolia).
        registry_address: Address of the IdentityRegistry contract.
        circuit_dir: Path to circuit WASM files (default: bundled with Node SDK).
        zkey_dir: Path to zkey files (default: bundled with Node SDK).
        node_sdk_path: Path to the Bolyra Node.js SDK package root.
            Required for prove_handshake/verify_handshake. Defaults to
            looking for ../sdk relative to this package.
    """

    rpc_url: str | None = None
    registry_address: str | None = None
    circuit_dir: str | None = None
    zkey_dir: str | None = None
    node_sdk_path: str | None = None
