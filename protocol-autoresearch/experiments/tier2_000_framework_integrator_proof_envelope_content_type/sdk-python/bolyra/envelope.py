"""Bolyra proof envelope — canonical wire format for HTTP transport.

Mirrors the TypeScript SDK's envelope.ts schema exactly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Literal

from pydantic import BaseModel, field_validator

CONTENT_TYPE: str = "application/bolyra-proof+json"
ENVELOPE_VERSION: str = "1.0"

_SUPPORTED_MAJOR = int(ENVELOPE_VERSION.split(".")[0])


class ProofData(BaseModel):
    """Proof fields matching snarkjs Groth16/PLONK output."""

    pi_a: List[str]
    pi_b: List[List[str]]
    pi_c: List[str]
    protocol: Literal["groth16", "plonk"]


class ProofMetadata(BaseModel):
    """Metadata attached to every proof envelope."""

    prover: str
    timestamp: str  # ISO 8601

    @field_validator("prover")
    @classmethod
    def prover_not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("prover must not be empty")
        return v


class ProofEnvelope(BaseModel):
    """Canonical proof envelope for HTTP transport."""

    version: str
    circuit: str
    publicSignals: List[str]  # noqa: N815 — matches wire format
    proof: ProofData
    metadata: ProofMetadata

    @field_validator("circuit")
    @classmethod
    def circuit_not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("circuit must not be empty")
        return v

    def to_json(self) -> str:
        """Serialize to canonical JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str) -> "ProofEnvelope":
        """Deserialize and validate from JSON string.

        Raises ValueError on unsupported major version.
        """
        envelope = cls.model_validate_json(raw)
        _assert_supported_version(envelope.version)
        return envelope


def _parse_major_version(version: str) -> int:
    try:
        return int(version.split(".")[0])
    except (ValueError, IndexError) as exc:
        raise ValueError(f"Invalid version string: {version}") from exc


def _assert_supported_version(version: str) -> None:
    major = _parse_major_version(version)
    if major != _SUPPORTED_MAJOR:
        raise ValueError(
            f"Unsupported envelope major version {major}; expected {_SUPPORTED_MAJOR}"
        )


def envelope_from_snarkjs_proof(
    circuit: str,
    proof: dict,
    public_signals: List[str],
    prover: str = "bolyra-python",
) -> ProofEnvelope:
    """Wrap raw snarkjs proof output into a ProofEnvelope."""
    return ProofEnvelope(
        version=ENVELOPE_VERSION,
        circuit=circuit,
        publicSignals=public_signals,
        proof=ProofData(
            pi_a=proof["pi_a"],
            pi_b=proof["pi_b"],
            pi_c=proof["pi_c"],
            protocol=proof["protocol"],
        ),
        metadata=ProofMetadata(
            prover=prover,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
