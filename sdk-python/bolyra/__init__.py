"""Bolyra Python SDK — unified ZKP identity for humans and AI agents."""

from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    DelegateeMerkleProof,
    DelegationResult,
    HandshakeResult,
    HumanIdentity,
    Permission,
)
from bolyra.identity import (
    BN254_FIELD_ORDER,
    create_agent_credential,
    create_dev_identities,
    create_human_identity,
    permissions_to_bitmask,
    validate_cumulative_bit_encoding,
)
from bolyra.handshake import prove_handshake, verify_handshake
from bolyra.delegation import delegate, verify_delegation
from bolyra.sd_jwt import (
    AllowOptions as SDJWTAllowOptions,
    PresentOptions as SDJWTPresentOptions,
    VerifyOptions as SDJWTVerifyOptions,
    VerifyResult as SDJWTVerifyResult,
    allow as sd_jwt_allow,
    present as sd_jwt_present,
    verify as sd_jwt_verify,
    generate_ed25519_keypair,
)
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

__version__ = "0.4.0"

__all__ = [
    # Types
    "AgentCredential",
    "BolyraConfig",
    "DelegateeMerkleProof",
    "DelegationResult",
    "HandshakeResult",
    "HumanIdentity",
    "Permission",
    # Identity
    "BN254_FIELD_ORDER",
    "create_agent_credential",
    "create_dev_identities",
    "create_human_identity",
    "permissions_to_bitmask",
    "validate_cumulative_bit_encoding",
    # Handshake
    "prove_handshake",
    "verify_handshake",
    # Delegation
    "delegate",
    "verify_delegation",
    # SD-JWT
    "SDJWTAllowOptions",
    "SDJWTPresentOptions",
    "SDJWTVerifyOptions",
    "SDJWTVerifyResult",
    "sd_jwt_allow",
    "sd_jwt_present",
    "sd_jwt_verify",
    "generate_ed25519_keypair",
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
