"""Canonical proof envelope for HTTP transport.

MIME type: application/bolyra-proof+json

This module mirrors the TypeScript ProofEnvelope class in @bolyra/sdk,
producing byte-for-byte identical JSON output for the shared test vectors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional


BOLYRA_PROOF_CONTENT_TYPE = "application/bolyra-proof+json"
ENVELOPE_VERSION = "1"

VALID_CIRCUITS = frozenset({"HumanUniqueness", "AgentPolicy", "Delegation"})


class BolyraEnvelopeError(Exception):
    """Raised when a proof envelope is malformed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True)
class DelegationLink:
    delegator_commitment: str
    delegate_commitment: str
    scope_mask: int
    expiry: int


@dataclass(frozen=True)
class SnarkProof:
    pi_a: List[str]
    pi_b: List[List[str]]
    pi_c: List[str]


@dataclass(frozen=True)
class ProofEnvelope:
    version: str
    circuit: str
    public_signals: List[str]
    proof: SnarkProof
    session_token: Optional[str] = None
    delegation_chain: Optional[List[DelegationLink]] = field(default=None)

    def __post_init__(self) -> None:
        _validate(self)

    def serialize(self) -> str:
        """Serialize to canonical JSON with stable key order."""
        obj: dict = {
            "version": self.version,
            "circuit": self.circuit,
            "publicSignals": list(self.public_signals),
            "proof": {
                "pi_a": list(self.proof.pi_a),
                "pi_b": [list(row) for row in self.proof.pi_b],
                "pi_c": list(self.proof.pi_c),
            },
        }
        if self.session_token is not None:
            obj["sessionToken"] = self.session_token
        if self.delegation_chain is not None:
            obj["delegationChain"] = [
                {
                    "delegatorCommitment": link.delegator_commitment,
                    "delegateCommitment": link.delegate_commitment,
                    "scopeMask": link.scope_mask,
                    "expiry": link.expiry,
                }
                for link in self.delegation_chain
            ]
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def parse(raw: str) -> "ProofEnvelope":
        """Parse a JSON string into a ProofEnvelope."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BolyraEnvelopeError("INVALID_JSON", "Input is not valid JSON") from exc

        if not isinstance(data, dict):
            raise BolyraEnvelopeError(
                "INVALID_ENVELOPE", "Envelope must be a JSON object"
            )

        proof_raw = data.get("proof", {})
        if not isinstance(proof_raw, dict):
            raise BolyraEnvelopeError(
                "INVALID_PROOF", "proof must be an object with pi_a, pi_b, pi_c"
            )

        delegation_chain = None
        if "delegationChain" in data and data["delegationChain"] is not None:
            delegation_chain = [
                DelegationLink(
                    delegator_commitment=link["delegatorCommitment"],
                    delegate_commitment=link["delegateCommitment"],
                    scope_mask=link["scopeMask"],
                    expiry=link["expiry"],
                )
                for link in data["delegationChain"]
            ]

        return ProofEnvelope(
            version=data.get("version", ""),
            circuit=data.get("circuit", ""),
            public_signals=data.get("publicSignals", []),
            proof=SnarkProof(
                pi_a=proof_raw.get("pi_a", []),
                pi_b=proof_raw.get("pi_b", []),
                pi_c=proof_raw.get("pi_c", []),
            ),
            session_token=data.get("sessionToken"),
            delegation_chain=delegation_chain,
        )


def _validate(envelope: ProofEnvelope) -> None:
    """Validate envelope fields. Raises BolyraEnvelopeError on failure."""
    if envelope.version != ENVELOPE_VERSION:
        raise BolyraEnvelopeError(
            "UNSUPPORTED_VERSION",
            f'Expected version "{ENVELOPE_VERSION}", got "{envelope.version}"',
        )

    if envelope.circuit not in VALID_CIRCUITS:
        raise BolyraEnvelopeError(
            "UNKNOWN_CIRCUIT",
            f'Unknown circuit "{envelope.circuit}". '
            f"Expected one of: {', '.join(sorted(VALID_CIRCUITS))}",
        )

    if not isinstance(envelope.public_signals, list) or len(envelope.public_signals) == 0:
        raise BolyraEnvelopeError(
            "INVALID_PUBLIC_SIGNALS",
            "publicSignals must be a non-empty array of strings",
        )
    for s in envelope.public_signals:
        if not isinstance(s, str):
            raise BolyraEnvelopeError(
                "INVALID_PUBLIC_SIGNALS", "Each public signal must be a string"
            )

    if not isinstance(envelope.proof, SnarkProof):
        raise BolyraEnvelopeError(
            "INVALID_PROOF", "proof must be a SnarkProof instance"
        )

    if len(envelope.proof.pi_a) != 3:
        raise BolyraEnvelopeError(
            "INVALID_PROOF", "proof.pi_a must be an array of 3 strings"
        )
    if len(envelope.proof.pi_b) != 3:
        raise BolyraEnvelopeError(
            "INVALID_PROOF", "proof.pi_b must be an array of 3 two-element arrays"
        )
    for row in envelope.proof.pi_b:
        if len(row) != 2:
            raise BolyraEnvelopeError(
                "INVALID_PROOF",
                "Each element of proof.pi_b must be a 2-element array",
            )
    if len(envelope.proof.pi_c) != 3:
        raise BolyraEnvelopeError(
            "INVALID_PROOF", "proof.pi_c must be an array of 3 strings"
        )

    if envelope.delegation_chain is not None:
        if not isinstance(envelope.delegation_chain, list) or len(envelope.delegation_chain) == 0:
            raise BolyraEnvelopeError(
                "INVALID_DELEGATION_CHAIN",
                "delegationChain must be a non-empty array if present",
            )
        for link in envelope.delegation_chain:
            if not isinstance(link.delegator_commitment, str) or not isinstance(
                link.delegate_commitment, str
            ):
                raise BolyraEnvelopeError(
                    "INVALID_DELEGATION_CHAIN",
                    "Each delegation link must have string delegatorCommitment and delegateCommitment",
                )
            if (
                not isinstance(link.scope_mask, int)
                or link.scope_mask < 0
                or link.scope_mask > 255
            ):
                raise BolyraEnvelopeError(
                    "INVALID_DELEGATION_CHAIN",
                    "scopeMask must be an integer in [0, 255]",
                )
            if not isinstance(link.expiry, int) or link.expiry <= 0:
                raise BolyraEnvelopeError(
                    "INVALID_DELEGATION_CHAIN",
                    "expiry must be a positive integer",
                )
