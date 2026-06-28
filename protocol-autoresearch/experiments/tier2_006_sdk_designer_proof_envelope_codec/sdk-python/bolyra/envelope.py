"""BolyraEnvelope — self-describing proof envelope with named public signals.

Python mirror of the TypeScript envelope codec. Produces and consumes
the same JSON wire format so envelopes are cross-SDK compatible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Signal maps (must match sdk/src/circuits/signal-maps.ts)
# ---------------------------------------------------------------------------

HUMAN_UNIQUENESS_SIGNALS = (
    "humanMerkleRoot",
    "nullifierHash",
    "nonceBinding",
)

AGENT_POLICY_SIGNALS = (
    "credentialCommitment",
    "permissionsBitmask",
    "scopeCommitment",
    "expiryTimestamp",
)

DELEGATION_SIGNALS = (
    "delegatorCredCommitment",
    "delegateeCredCommitment",
    "narrowedPermissionsBitmask",
    "delegationNullifier",
)

SIGNAL_MAPS: dict[str, tuple[str, ...]] = {
    "HumanUniqueness": HUMAN_UNIQUENESS_SIGNALS,
    "AgentPolicy": AGENT_POLICY_SIGNALS,
    "Delegation": DELEGATION_SIGNALS,
}

VALID_PROVING_SYSTEMS: dict[str, tuple[str, ...]] = {
    "HumanUniqueness": ("groth16",),
    "AgentPolicy": ("groth16", "plonk"),
    "Delegation": ("groth16", "plonk"),
}

ENVELOPE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EnvelopeVersionError(ValueError):
    """Raised when the envelope version is unsupported."""


class UnknownCircuitError(ValueError):
    """Raised when the circuit name is not recognised."""


class SignalCountMismatch(ValueError):
    """Raised when signal count does not match the circuit's expected count."""


class InvalidProvingSystemError(ValueError):
    """Raised when the proving system is not valid for the circuit."""


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BolyraEnvelope:
    """Self-describing proof envelope with named public signals."""

    version: str
    circuit: str
    proving_system: str
    signals: dict[str, str]
    proof: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict matching the TS wire format."""
        return {
            "version": self.version,
            "circuit": self.circuit,
            "provingSystem": self.proving_system,
            "signals": dict(self.signals),
            "proof": self.proof,
        }

    def to_public_signals(self) -> list[int]:
        """Reconstruct the ordered positional public signals as ints."""
        signal_names = SIGNAL_MAPS.get(self.circuit)
        if signal_names is None:
            raise UnknownCircuitError(f"Unknown circuit: {self.circuit}")
        return [int(self.signals[name]) for name in signal_names]


# ---------------------------------------------------------------------------
# encode()
# ---------------------------------------------------------------------------


def encode(
    circuit: str,
    proving_system: str,
    raw_proof: dict[str, Any],
    raw_signals: list[str],
) -> BolyraEnvelope:
    """Encode raw proof and positional signals into a BolyraEnvelope."""
    signal_names = SIGNAL_MAPS.get(circuit)
    if signal_names is None:
        raise UnknownCircuitError(f"Unknown circuit: {circuit}")

    valid_systems = VALID_PROVING_SYSTEMS[circuit]
    if proving_system not in valid_systems:
        raise InvalidProvingSystemError(
            f"Invalid proving system '{proving_system}' for circuit '{circuit}'"
        )

    if len(raw_signals) != len(signal_names):
        raise SignalCountMismatch(
            f"Signal count mismatch for {circuit}: "
            f"expected {len(signal_names)}, got {len(raw_signals)}"
        )

    signals = {name: raw_signals[i] for i, name in enumerate(signal_names)}

    return BolyraEnvelope(
        version=ENVELOPE_VERSION,
        circuit=circuit,
        proving_system=proving_system,
        signals=signals,
        proof=raw_proof,
    )


# ---------------------------------------------------------------------------
# decode()
# ---------------------------------------------------------------------------


def decode(data: dict[str, Any]) -> BolyraEnvelope:
    """Decode and validate a BolyraEnvelope from a JSON-compatible dict."""
    version = data.get("version")
    if not isinstance(version, str):
        raise EnvelopeVersionError(f"Unsupported envelope version: {version}")

    parts = version.split(".")
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        raise EnvelopeVersionError(f"Unsupported envelope version: {version}")

    if major > 1:
        raise EnvelopeVersionError(f"Unsupported envelope version: {version}")

    circuit = data.get("circuit", "")
    if circuit not in SIGNAL_MAPS:
        raise UnknownCircuitError(f"Unknown circuit: {circuit}")

    proving_system = data.get("provingSystem", "")
    valid_systems = VALID_PROVING_SYSTEMS[circuit]
    if proving_system not in valid_systems:
        raise InvalidProvingSystemError(
            f"Invalid proving system '{proving_system}' for circuit '{circuit}'"
        )

    signal_names = SIGNAL_MAPS[circuit]
    signals = data.get("signals", {})
    if not isinstance(signals, dict):
        raise SignalCountMismatch(
            f"Signal count mismatch for {circuit}: "
            f"expected {len(signal_names)}, got 0"
        )

    if len(signals) != len(signal_names):
        raise SignalCountMismatch(
            f"Signal count mismatch for {circuit}: "
            f"expected {len(signal_names)}, got {len(signals)}"
        )

    for name in signal_names:
        if name not in signals:
            raise SignalCountMismatch(
                f"Missing signal '{name}' for circuit {circuit}"
            )

    return BolyraEnvelope(
        version=version,
        circuit=circuit,
        proving_system=proving_system,
        signals=signals,
        proof=data.get("proof", {}),
    )


# ---------------------------------------------------------------------------
# fromRaw() — migration helper
# ---------------------------------------------------------------------------


def from_raw(
    circuit: str,
    proving_system: str,
    raw_proof: dict[str, Any],
    raw_signals: list[str],
) -> BolyraEnvelope:
    """Migration helper: alias for encode().

    Provides a clear upgrade path for integrators using positional arrays.
    """
    return encode(circuit, proving_system, raw_proof, raw_signals)
