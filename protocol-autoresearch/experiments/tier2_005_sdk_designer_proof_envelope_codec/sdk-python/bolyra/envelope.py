"""
BolyraEnvelope — self-describing proof envelope with named public signals.

Python mirror of sdk/src/envelope.ts.  Serialises/deserialises via standard
json with string-encoded bigints (no Python-specific types in the wire format).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .signals import SIGNAL_MAPS, VALID_CIRCUITS, VALID_PROVING_SYSTEMS

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

ENVELOPE_VERSION = "1.0.0"
_SUPPORTED_MAJOR = 1


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EnvelopeError(Exception):
    """Raised on encode/decode validation failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BolyraEnvelope:
    """Self-describing proof envelope."""

    version: str
    circuit: str
    proving_system: str
    signals: Dict[str, str]
    proof: Dict[str, Any]

    # -- JSON serialisation --------------------------------------------------

    def to_json(self) -> str:
        """Serialise to canonical JSON (camelCase keys on the wire)."""
        return json.dumps(
            {
                "version": self.version,
                "circuit": self.circuit,
                "provingSystem": self.proving_system,
                "signals": self.signals,
                "proof": self.proof,
            },
            separators=(",", ":"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-compatible dict (camelCase keys)."""
        return {
            "version": self.version,
            "circuit": self.circuit,
            "provingSystem": self.proving_system,
            "signals": dict(self.signals),
            "proof": dict(self.proof),
        }

    @staticmethod
    def from_json(raw: str) -> "BolyraEnvelope":
        """Deserialise from JSON, validating version and circuit."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EnvelopeError("INVALID_JSON", f"Cannot parse JSON: {exc}") from exc
        return BolyraEnvelope.from_dict(data)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "BolyraEnvelope":
        """Construct from a dict (camelCase keys), validating fields."""
        version = data.get("version", "")
        _validate_version(version)

        circuit = data.get("circuit", "")
        if circuit not in VALID_CIRCUITS:
            raise EnvelopeError(
                "UNKNOWN_CIRCUIT",
                f'Unknown circuit "{circuit}". '
                f"Expected one of: {', '.join(sorted(VALID_CIRCUITS))}",
            )

        proving_system = data.get("provingSystem", "")
        if proving_system not in VALID_PROVING_SYSTEMS:
            raise EnvelopeError(
                "UNKNOWN_PROVING_SYSTEM",
                f'Unknown proving system "{proving_system}". '
                f"Expected one of: groth16, plonk",
            )

        signals = data.get("signals", {})
        expected_names = set(SIGNAL_MAPS[circuit])
        actual_names = set(signals.keys())
        if actual_names != expected_names:
            missing = expected_names - actual_names
            extra = actual_names - expected_names
            parts = []
            if missing:
                parts.append(f"missing={missing}")
            if extra:
                parts.append(f"extra={extra}")
            raise EnvelopeError(
                "SIGNAL_MISMATCH",
                f"Signal keys do not match {circuit}: {'; '.join(parts)}",
            )

        return BolyraEnvelope(
            version=version,
            circuit=circuit,
            proving_system=proving_system,
            signals={k: str(v) for k, v in signals.items()},
            proof=data.get("proof", {}),
        )


# ---------------------------------------------------------------------------
# encode / decode / from_raw
# ---------------------------------------------------------------------------


def encode(
    circuit: str,
    proving_system: str,
    raw_proof: Dict[str, Any],
    raw_signals: List[str],
) -> BolyraEnvelope:
    """Encode raw snarkjs output into a BolyraEnvelope."""
    if circuit not in VALID_CIRCUITS:
        raise EnvelopeError(
            "UNKNOWN_CIRCUIT",
            f'Unknown circuit "{circuit}". '
            f"Expected one of: {', '.join(sorted(VALID_CIRCUITS))}",
        )
    if proving_system not in VALID_PROVING_SYSTEMS:
        raise EnvelopeError(
            "UNKNOWN_PROVING_SYSTEM",
            f'Unknown proving system "{proving_system}". Expected one of: groth16, plonk',
        )

    names = SIGNAL_MAPS[circuit]
    if len(raw_signals) != len(names):
        raise EnvelopeError(
            "SIGNAL_COUNT_MISMATCH",
            f"Expected {len(names)} signals for {circuit}, got {len(raw_signals)}",
        )

    signals = {names[i]: str(raw_signals[i]) for i in range(len(names))}

    return BolyraEnvelope(
        version=ENVELOPE_VERSION,
        circuit=circuit,
        proving_system=proving_system,
        signals=signals,
        proof=raw_proof,
    )


def decode(envelope: BolyraEnvelope) -> Dict[str, Any]:
    """Decode a BolyraEnvelope back to positional { proof, publicSignals }."""
    _validate_version(envelope.version)

    if envelope.circuit not in VALID_CIRCUITS:
        raise EnvelopeError(
            "UNKNOWN_CIRCUIT",
            f'Unknown circuit "{envelope.circuit}".',
        )

    names = SIGNAL_MAPS[envelope.circuit]
    public_signals: List[str] = []
    for name in names:
        val = envelope.signals.get(name)
        if val is None:
            raise EnvelopeError(
                "MISSING_SIGNAL",
                f'Signal "{name}" missing from envelope for circuit {envelope.circuit}',
            )
        public_signals.append(str(val))

    return {"proof": envelope.proof, "publicSignals": public_signals}


def from_raw(
    circuit: str,
    proving_system: str,
    raw_proof: Dict[str, Any],
    raw_signals: List[str],
) -> BolyraEnvelope:
    """Convenience alias for encode() — migration entry point."""
    return encode(circuit, proving_system, raw_proof, raw_signals)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_version(version: str) -> None:
    """Validate that version string has a supported major version."""
    try:
        major = int(version.split(".")[0])
    except (ValueError, IndexError) as exc:
        raise EnvelopeError(
            "INVALID_VERSION", f"Cannot parse version: {version}"
        ) from exc

    if major != _SUPPORTED_MAJOR:
        raise EnvelopeError(
            "UNSUPPORTED_VERSION",
            f"Envelope version {version} (major {major}) is not supported. "
            f"Expected major {_SUPPORTED_MAJOR}.",
        )
