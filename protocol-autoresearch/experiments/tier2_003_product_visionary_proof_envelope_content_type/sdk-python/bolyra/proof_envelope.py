"""
Bolyra Proof Envelope — CBOR encode/decode.

Media type: application/bolyra-proof+cbor
Spec: spec/proof-envelope-content-type.md
CDDL: spec/proof-envelope.cddl
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

import cbor2

# ── Constants ────────────────────────────────────────────────────────

CONTENT_TYPE = "application/bolyra-proof+cbor"
ENVELOPE_VERSION = 1

# CDDL integer keys
_KEY_VERSION = 1
_KEY_CIRCUIT_ID = 2
_KEY_PROVING_SYSTEM = 3
_KEY_PROOF_BYTES = 4
_KEY_PUBLIC_SIGNALS = 5
_KEY_DELEGATION_CHAIN = 6

VALID_CIRCUIT_IDS = frozenset({"HumanUniqueness", "AgentPolicy", "Delegation"})
VALID_PROVING_SYSTEMS = frozenset({"groth16", "plonk"})

MAX_ENVELOPE_BYTES = 65536  # 64 KiB
MAX_DELEGATION_DEPTH = 8


# ── Error ────────────────────────────────────────────────────────────


class ProofEnvelopeError(Exception):
    """Raised on encode/decode failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


# ── Data Classes ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class DelegationChainEntry:
    """A single entry in the delegation chain."""

    data: bytes


@dataclass(frozen=True)
class ProofEnvelope:
    """Self-describing proof envelope for the application/bolyra-proof+cbor format."""

    version: int
    circuit_id: str
    proving_system: str
    proof_bytes: bytes
    public_signals: List[str]
    delegation_chain: Optional[List[DelegationChainEntry]] = field(default=None)


# ── Encoder ──────────────────────────────────────────────────────────


def encode(envelope: ProofEnvelope) -> bytes:
    """Encode a ProofEnvelope to CBOR bytes using integer keys.

    Raises:
        ProofEnvelopeError: on constraint violations
    """
    _validate(envelope)

    cbor_map = {
        _KEY_VERSION: envelope.version,
        _KEY_CIRCUIT_ID: envelope.circuit_id,
        _KEY_PROVING_SYSTEM: envelope.proving_system,
        _KEY_PROOF_BYTES: envelope.proof_bytes,
        _KEY_PUBLIC_SIGNALS: list(envelope.public_signals),
    }

    if envelope.delegation_chain:
        cbor_map[_KEY_DELEGATION_CHAIN] = [e.data for e in envelope.delegation_chain]

    encoded = cbor2.dumps(cbor_map)
    if len(encoded) > MAX_ENVELOPE_BYTES:
        raise ProofEnvelopeError(
            "ENVELOPE_TOO_LARGE",
            f"Encoded envelope is {len(encoded)} bytes, exceeds max {MAX_ENVELOPE_BYTES}",
        )
    return encoded


# ── Decoder ──────────────────────────────────────────────────────────


def decode(data: bytes) -> ProofEnvelope:
    """Decode CBOR bytes into a ProofEnvelope with full validation.

    Unknown integer keys are silently ignored for forward compatibility.

    Raises:
        ProofEnvelopeError: on invalid CBOR or constraint violations
    """
    if not data:
        raise ProofEnvelopeError("EMPTY_INPUT", "Cannot decode empty buffer")
    if len(data) > MAX_ENVELOPE_BYTES:
        raise ProofEnvelopeError(
            "ENVELOPE_TOO_LARGE",
            f"Input is {len(data)} bytes, exceeds max {MAX_ENVELOPE_BYTES}",
        )

    try:
        raw = cbor2.loads(data)
    except Exception as e:
        raise ProofEnvelopeError("CBOR_DECODE_FAILED", f"Failed to decode CBOR: {e}") from e

    if not isinstance(raw, dict):
        raise ProofEnvelopeError("INVALID_STRUCTURE", "Envelope must be a CBOR map")

    # version
    version = raw.get(_KEY_VERSION)
    if not isinstance(version, int) or version < 0:
        raise ProofEnvelopeError("INVALID_VERSION", "Missing or invalid 'version' field")
    if version != ENVELOPE_VERSION:
        raise ProofEnvelopeError(
            "UNSUPPORTED_VERSION",
            f"Unsupported envelope version {version} (expected {ENVELOPE_VERSION})",
        )

    # circuit_id
    circuit_id = raw.get(_KEY_CIRCUIT_ID)
    if not isinstance(circuit_id, str):
        raise ProofEnvelopeError("INVALID_CIRCUIT_ID", "Missing or invalid 'circuitId' field")
    if circuit_id not in VALID_CIRCUIT_IDS:
        raise ProofEnvelopeError(
            "UNKNOWN_CIRCUIT_ID",
            f"Unknown circuit ID '{circuit_id}'. Valid: {', '.join(sorted(VALID_CIRCUIT_IDS))}",
        )

    # proving_system
    proving_system = raw.get(_KEY_PROVING_SYSTEM)
    if not isinstance(proving_system, str):
        raise ProofEnvelopeError("INVALID_PROVING_SYSTEM", "Missing or invalid 'provingSystem' field")
    if proving_system not in VALID_PROVING_SYSTEMS:
        raise ProofEnvelopeError(
            "UNKNOWN_PROVING_SYSTEM",
            f"Unknown proving system '{proving_system}'. Valid: {', '.join(sorted(VALID_PROVING_SYSTEMS))}",
        )

    # proof_bytes
    proof_bytes = raw.get(_KEY_PROOF_BYTES)
    if not isinstance(proof_bytes, bytes):
        raise ProofEnvelopeError("INVALID_PROOF_BYTES", "Missing or invalid 'proofBytes' (expected bstr)")
    if len(proof_bytes) == 0:
        raise ProofEnvelopeError("EMPTY_PROOF", "proofBytes must not be empty")

    # public_signals
    public_signals = raw.get(_KEY_PUBLIC_SIGNALS)
    if not isinstance(public_signals, list):
        raise ProofEnvelopeError("INVALID_PUBLIC_SIGNALS", "Missing or invalid 'publicSignals' (expected array)")
    for i, sig in enumerate(public_signals):
        if not isinstance(sig, str):
            raise ProofEnvelopeError(
                "INVALID_SIGNAL_TYPE",
                f"publicSignals[{i}] must be a string, got {type(sig).__name__}",
            )

    # delegation_chain (optional)
    delegation_chain: Optional[List[DelegationChainEntry]] = None
    raw_chain = raw.get(_KEY_DELEGATION_CHAIN)
    if raw_chain is not None:
        if not isinstance(raw_chain, list):
            raise ProofEnvelopeError("INVALID_DELEGATION_CHAIN", "delegationChain must be an array")
        if len(raw_chain) > MAX_DELEGATION_DEPTH:
            raise ProofEnvelopeError(
                "DELEGATION_TOO_DEEP",
                f"Delegation chain has {len(raw_chain)} entries, max is {MAX_DELEGATION_DEPTH}",
            )
        delegation_chain = []
        for i, entry in enumerate(raw_chain):
            if not isinstance(entry, bytes):
                raise ProofEnvelopeError(
                    "INVALID_DELEGATION_ENTRY",
                    f"delegationChain[{i}] must be bstr",
                )
            delegation_chain.append(DelegationChainEntry(data=entry))

    return ProofEnvelope(
        version=version,
        circuit_id=circuit_id,
        proving_system=proving_system,
        proof_bytes=proof_bytes,
        public_signals=public_signals,
        delegation_chain=delegation_chain,
    )


def build_content_type(circuit_id: str, proving_system: str) -> str:
    """Build the Content-Type header value for a proof envelope."""
    return f"{CONTENT_TYPE}; circuit={circuit_id}; ps={proving_system}; v={ENVELOPE_VERSION}"


# ── Validation ───────────────────────────────────────────────────────


def _validate(envelope: ProofEnvelope) -> None:
    if envelope.version != ENVELOPE_VERSION:
        raise ProofEnvelopeError("UNSUPPORTED_VERSION", f"Unsupported version: {envelope.version}")
    if envelope.circuit_id not in VALID_CIRCUIT_IDS:
        raise ProofEnvelopeError("UNKNOWN_CIRCUIT_ID", f"Unknown circuit ID: {envelope.circuit_id}")
    if envelope.proving_system not in VALID_PROVING_SYSTEMS:
        raise ProofEnvelopeError("UNKNOWN_PROVING_SYSTEM", f"Unknown proving system: {envelope.proving_system}")
    if len(envelope.proof_bytes) == 0:
        raise ProofEnvelopeError("EMPTY_PROOF", "proofBytes must not be empty")
    if envelope.delegation_chain and len(envelope.delegation_chain) > MAX_DELEGATION_DEPTH:
        raise ProofEnvelopeError(
            "DELEGATION_TOO_DEEP",
            f"Delegation chain has {len(envelope.delegation_chain)} entries, max is {MAX_DELEGATION_DEPTH}",
        )
