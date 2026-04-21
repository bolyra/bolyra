"""Error hierarchy for the Bolyra SDK.

Mirrors the TypeScript SDK's error classes. Every error carries a
machine-readable ``code`` and optional ``details`` dict for structured
error handling in LangChain/CrewAI pipelines.
"""

from __future__ import annotations

from typing import Any


class BolyraError(Exception):
    """Base error for all Bolyra SDK operations."""

    def __init__(
        self,
        message: str,
        code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class ProofGenerationError(BolyraError):
    """Raised when ZK proof generation fails."""

    def __init__(self, circuit: str, reason: str) -> None:
        super().__init__(
            f"Failed to generate {circuit} proof: {reason}",
            "PROOF_GENERATION_FAILED",
            {"circuit": circuit, "reason": reason},
        )


class VerificationError(BolyraError):
    """Raised when proof verification fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"On-chain verification failed: {reason}",
            "VERIFICATION_FAILED",
            {"reason": reason},
        )


class InvalidPermissionError(BolyraError):
    """Raised when permission bitmask violates cumulative encoding rules."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "INVALID_PERMISSION")


class ExpiredCredentialError(BolyraError):
    """Raised when an agent credential has expired."""

    def __init__(self, expiry_timestamp: int) -> None:
        super().__init__(
            f"Agent credential expired at {expiry_timestamp}",
            "CREDENTIAL_EXPIRED",
            {"expiry_timestamp": str(expiry_timestamp)},
        )


class ScopeEscalationError(BolyraError):
    """Raised when a delegation attempts scope escalation."""

    def __init__(self, delegator_scope: int, requested_scope: int) -> None:
        super().__init__(
            f"Delegation scope escalation: delegatee scope ({requested_scope}) "
            f"is not a subset of delegator scope ({delegator_scope})",
            "SCOPE_ESCALATION",
            {
                "delegator_scope": str(delegator_scope),
                "requested_scope": str(requested_scope),
            },
        )


class StaleProofError(BolyraError):
    """Raised when a Merkle root is stale (tree updated after proof generation)."""

    def __init__(self, root_type: str) -> None:
        super().__init__(
            f"{root_type} Merkle root is stale -- the tree was updated after "
            "proof generation. Regenerate the proof.",
            "STALE_MERKLE_ROOT",
            {"root_type": root_type},
        )


class InvalidSecretError(BolyraError):
    """Raised when a human secret is invalid (zero, negative, or out of field)."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid secret: {reason}. Provide a non-zero int less than "
            "the BN254 scalar field order (approx 2^254).",
            "INVALID_SECRET",
            {"reason": reason},
        )


class CircuitArtifactNotFoundError(ProofGenerationError):
    """Raised when a circuit artifact (wasm/zkey/vkey) is missing."""

    def __init__(self, artifact_path: str, artifact_type: str) -> None:
        circuit_label = "verification" if artifact_type == "vkey" else "proof generation"
        super().__init__(
            circuit_label,
            f"Circuit artifact not found: {artifact_path}. "
            f"Ensure the {artifact_type} file exists at this path. "
            "If using a custom circuit_dir, verify it contains the compiled circuit outputs. "
            "Run the circuit build script or download trusted artifacts from the Bolyra release.",
        )
        self.code = "CIRCUIT_ARTIFACT_NOT_FOUND"
        self.details = {**self.details, "artifact_path": artifact_path, "artifact_type": artifact_type}


class MerkleTreeError(BolyraError):
    """Raised when a Merkle tree operation fails."""

    def __init__(self, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            f"Merkle tree operation failed: {reason}. "
            "Check that the tree is properly initialized and the leaf index is within bounds.",
            "MERKLE_TREE_ERROR",
            {"reason": reason, **(details or {})},
        )


class ConfigurationError(BolyraError):
    """Raised when the SDK configuration is invalid."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(
            f'Invalid SDK configuration for "{field}": {reason}. '
            "Review the BolyraConfig dataclass and ensure all required fields are set correctly.",
            "CONFIGURATION_ERROR",
            {"field": field, "reason": reason},
        )
