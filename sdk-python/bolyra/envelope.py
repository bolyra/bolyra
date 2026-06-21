"""Proof envelope wire format: application/vnd.bolyra.proof+json

Self-describing envelope for ZKP proofs with typed fields,
circuit identity binding, and version negotiation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

CONTENT_TYPE = "application/vnd.bolyra.proof+json"
ENVELOPE_VERSION = "1.0.0"

# BN254 scalar field modulus
BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617

VALID_CIRCUITS = frozenset({"HumanUniqueness", "AgentPolicy", "Delegation"})
VALID_PROOF_TYPES = frozenset({"groth16"})  # v1: groth16 only


def _validate_field_element(s: str, label: str) -> None:
    if not isinstance(s, str):
        raise ValueError(f"{label}: must be a string, got {type(s).__name__}")
    if len(s) > 78:
        raise ValueError(f"{label}: string too long ({len(s)} chars, max 78)")
    if not re.match(r"^(0|[1-9]\d*)$", s):
        raise ValueError(f"{label}: must be a decimal string without leading zeros, got {s!r}")
    n = int(s)
    if n >= BN254_FIELD_ORDER:
        raise ValueError(f"{label}: value >= BN254 field modulus")


def _parse_semver(v: str) -> tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v)
    if not m:
        raise ValueError(f"Invalid semver: {v}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _check_version(version: str) -> None:
    major, _, _ = _parse_semver(version)
    current_major, _, _ = _parse_semver(ENVELOPE_VERSION)
    if major != current_major:
        raise ValueError(
            f"Incompatible envelope version: {version} "
            f"(current: {ENVELOPE_VERSION}). Major version mismatch."
        )


@dataclass
class CircuitIdentity:
    name: str
    version: str
    vkey_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "version": self.version}
        if self.vkey_hash:
            d["vkeyHash"] = self.vkey_hash
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CircuitIdentity:
        return cls(
            name=d["name"],
            version=d["version"],
            vkey_hash=d.get("vkeyHash"),
        )


@dataclass
class ProofData:
    pi_a: list[str]
    pi_b: list[list[str]]
    pi_c: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"pi_a": self.pi_a, "pi_b": self.pi_b, "pi_c": self.pi_c}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProofData:
        return cls(pi_a=d["pi_a"], pi_b=d["pi_b"], pi_c=d["pi_c"])


@dataclass
class ProofEnvelope:
    version: str
    circuit: CircuitIdentity
    proof_type: str
    public_signals: list[str]
    proof: ProofData
    metadata: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "version": self.version,
            "circuit": self.circuit.to_dict(),
            "proofType": self.proof_type,
            "publicSignals": self.public_signals,
            "proof": self.proof.to_dict(),
        }
        if self.metadata:
            d["metadata"] = self.metadata
        d.update(self.extra)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProofEnvelope:
        known_keys = {"version", "circuit", "proofType", "publicSignals", "proof", "metadata"}
        extra = {k: v for k, v in d.items() if k not in known_keys}
        return cls(
            version=d["version"],
            circuit=CircuitIdentity.from_dict(d["circuit"]),
            proof_type=d["proofType"],
            public_signals=d["publicSignals"],
            proof=ProofData.from_dict(d["proof"]),
            metadata=d.get("metadata", {}),
            extra=extra,
        )

    @classmethod
    def from_json(cls, raw: str) -> ProofEnvelope:
        d = json.loads(raw)
        return validate_envelope(d)


def validate_envelope(d: dict[str, Any]) -> ProofEnvelope:
    """Validate a raw dict and return a ProofEnvelope. Raises ValueError on invalid input."""
    if not isinstance(d.get("version"), str):
        raise ValueError("Missing or invalid version")
    _check_version(d["version"])

    circuit = d.get("circuit")
    if not isinstance(circuit, dict):
        raise ValueError("Missing or invalid circuit")
    if circuit.get("name") not in VALID_CIRCUITS:
        raise ValueError(f"Invalid circuit.name: {circuit.get('name')}")
    if not isinstance(circuit.get("version"), str):
        raise ValueError("Missing circuit.version")

    if d.get("proofType") not in VALID_PROOF_TYPES:
        raise ValueError(f"Invalid proofType: {d.get('proofType')}")

    signals = d.get("publicSignals")
    if not isinstance(signals, list) or len(signals) == 0:
        raise ValueError("publicSignals must be a non-empty array")
    for i, s in enumerate(signals):
        _validate_field_element(s, f"publicSignals[{i}]")

    proof = d.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Missing proof")
    for coord in ("pi_a", "pi_c"):
        arr = proof.get(coord)
        if not isinstance(arr, list) or len(arr) != 2:
            raise ValueError(f"proof.{coord} must be [string, string]")
        for i, s in enumerate(arr):
            _validate_field_element(s, f"{coord}[{i}]")
    pi_b = proof.get("pi_b")
    if not isinstance(pi_b, list) or len(pi_b) != 2:
        raise ValueError("proof.pi_b must be [[s,s],[s,s]]")
    for r, row in enumerate(pi_b):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError(f"proof.pi_b[{r}] must be [string, string]")
        for c, s in enumerate(row):
            _validate_field_element(s, f"pi_b[{r}][{c}]")

    return ProofEnvelope.from_dict(d)


def envelope_from_proof(
    circuit_name: str,
    proof: dict[str, Any],
    public_signals: list[str],
    *,
    circuit_version: str = "0.4.0",
    vkey_hash: str | None = None,
) -> ProofEnvelope:
    """Wrap raw proof output into a ProofEnvelope."""
    return ProofEnvelope(
        version=ENVELOPE_VERSION,
        circuit=CircuitIdentity(
            name=circuit_name,
            version=circuit_version,
            vkey_hash=vkey_hash,
        ),
        proof_type="groth16",
        public_signals=public_signals,
        proof=ProofData(
            pi_a=[proof["pi_a"][0], proof["pi_a"][1]],
            pi_b=[
                [proof["pi_b"][0][0], proof["pi_b"][0][1]],
                [proof["pi_b"][1][0], proof["pi_b"][1][1]],
            ],
            pi_c=[proof["pi_c"][0], proof["pi_c"][1]],
        ),
        metadata={
            "prover": "bolyra@0.5.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )
