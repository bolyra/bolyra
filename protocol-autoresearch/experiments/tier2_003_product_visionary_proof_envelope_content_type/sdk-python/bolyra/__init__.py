"""Bolyra — unified ZKP identity protocol for humans and AI agents."""

from bolyra.proof_envelope import (
    ProofEnvelope,
    ProofEnvelopeError,
    DelegationChainEntry,
    CONTENT_TYPE,
    ENVELOPE_VERSION,
    build_content_type,
    decode,
    encode,
)

__all__ = [
    "ProofEnvelope",
    "ProofEnvelopeError",
    "DelegationChainEntry",
    "CONTENT_TYPE",
    "ENVELOPE_VERSION",
    "build_content_type",
    "decode",
    "encode",
]
