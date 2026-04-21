"""Bolyra Python SDK — unified ZKP identity for humans and AI agents."""

from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    DelegationResult,
    HandshakeResult,
    HumanIdentity,
    Permission,
)
from bolyra.identity import (
    BN254_FIELD_ORDER,
    create_agent_credential,
    create_human_identity,
    permissions_to_bitmask,
    validate_cumulative_bit_encoding,
)
from bolyra.handshake import prove_handshake, verify_handshake
from bolyra.errors import (
    BolyraError,
    CircuitArtifactNotFoundError,
    ConfigurationError,
    ExpiredCredentialError,
    InvalidPermissionError,
    InvalidSecretError,
    MerkleTreeError,
    ProofGenerationError,
    ScopeEscalationError,
    StaleProofError,
    VerificationError,
)

__version__ = "0.1.0"

__all__ = [
    # Types
    "AgentCredential",
    "BolyraConfig",
    "DelegationResult",
    "HandshakeResult",
    "HumanIdentity",
    "Permission",
    # Identity
    "BN254_FIELD_ORDER",
    "create_agent_credential",
    "create_human_identity",
    "permissions_to_bitmask",
    "validate_cumulative_bit_encoding",
    # Handshake
    "prove_handshake",
    "verify_handshake",
    # Errors
    "BolyraError",
    "CircuitArtifactNotFoundError",
    "ConfigurationError",
    "ExpiredCredentialError",
    "InvalidPermissionError",
    "InvalidSecretError",
    "MerkleTreeError",
    "ProofGenerationError",
    "ScopeEscalationError",
    "StaleProofError",
    "VerificationError",
]
