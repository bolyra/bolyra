"""Identity creation and permission utilities.

Pure Python implementations for:
- Human identity creation (EdDSA keypair + Poseidon commitment)
- Agent credential creation (operator-signed)
- Permission bitmask encoding with cumulative validation

Note: ``create_human_identity`` and ``create_agent_credential`` are
placeholder stubs that raise ``NotImplementedError`` because the
cryptographic primitives (Baby Jubjub scalar multiply, Poseidon hash,
EdDSA sign) require either a native Rust binding or the Node.js SDK.
The bitmask and validation functions are fully implemented in pure Python.
"""

from __future__ import annotations

from bolyra.errors import InvalidPermissionError, InvalidSecretError
from bolyra.types import Permission

# BN254 scalar field order (Baby Jubjub subgroup order)
BN254_FIELD_ORDER = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


def validate_human_secret(secret: int) -> None:
    """Validate a secret value for use with ``create_human_identity``.

    Raises :class:`InvalidSecretError` if the secret is zero, negative,
    or exceeds the BN254 scalar field.
    """
    if secret == 0:
        raise InvalidSecretError(
            "secret must be non-zero -- a zero secret produces a trivial "
            "identity that cannot generate valid proofs"
        )
    if secret < 0:
        raise InvalidSecretError(
            "secret must be positive -- negative values are not valid field elements"
        )
    if secret >= BN254_FIELD_ORDER:
        raise InvalidSecretError(
            f"secret exceeds BN254 scalar field order "
            f"(got {str(secret)[:20]}..., max is ~2^254). "
            f"Use a value less than {BN254_FIELD_ORDER}"
        )


def validate_agent_expiry(expiry_timestamp: int) -> None:
    """Validate an expiry timestamp for use with ``create_agent_credential``.

    Raises :class:`InvalidPermissionError` if the timestamp is in the past.
    """
    import time

    now_seconds = int(time.time())
    if expiry_timestamp <= now_seconds:
        raise InvalidPermissionError(
            f"expiry_timestamp ({expiry_timestamp}) is not in the future "
            f"(current time: {now_seconds}). Set expiry_timestamp to a Unix "
            "timestamp after the current time, e.g. int(time.time()) + 86400 for +1 day."
        )


def permissions_to_bitmask(permissions: list[Permission]) -> int:
    """Convert a list of Permission flags to a 64-bit bitmask.

    Example::

        >>> permissions_to_bitmask([Permission.READ_DATA, Permission.WRITE_DATA])
        3
    """
    bitmask = 0
    for p in permissions:
        bitmask |= 1 << int(p)
    return bitmask


def validate_cumulative_bit_encoding(bitmask: int) -> None:
    """Validate cumulative bit encoding for financial permissions.

    Rules:
    - FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)
    - FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_SMALL (bit 2)
    - FINANCIAL_MEDIUM (bit 3) requires FINANCIAL_SMALL (bit 2)

    Raises :class:`InvalidPermissionError` on violation.
    """
    bit2 = (bitmask >> 2) & 1
    bit3 = (bitmask >> 3) & 1
    bit4 = (bitmask >> 4) & 1

    if bit4 and not bit3:
        raise InvalidPermissionError(
            "FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)"
        )
    if bit4 and not bit2:
        raise InvalidPermissionError(
            "FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_SMALL (bit 2)"
        )
    if bit3 and not bit2:
        raise InvalidPermissionError(
            "FINANCIAL_MEDIUM (bit 3) requires FINANCIAL_SMALL (bit 2)"
        )


def create_human_identity(secret: int):
    """Create a human identity (EdDSA keypair + Poseidon commitment).

    This is a stub. The cryptographic primitives (Baby Jubjub scalar
    multiply, Poseidon2 hash) require either:
    - A native Rust binding (e.g., py_poseidon_hash, babyjubjub-rs), or
    - Shelling out to the Node.js SDK via subprocess.

    Use ``prove_handshake()`` for the full workflow, which delegates to
    the Node.js SDK.

    Args:
        secret: A secret value (random int or derived from a seed phrase).

    Raises:
        InvalidSecretError: If the secret is invalid.
        NotImplementedError: Always (crypto primitives not yet available in pure Python).
    """
    validate_human_secret(secret)
    raise NotImplementedError(
        "create_human_identity requires Baby Jubjub + Poseidon primitives. "
        "Use the Node.js SDK via prove_handshake() or install a native crypto binding."
    )


def create_agent_credential(
    model_hash: int,
    operator_private_key: int,
    permissions: list[Permission],
    expiry_timestamp: int,
):
    """Create an AI agent credential signed by the operator.

    This is a stub. The cryptographic primitives (EdDSA sign, Poseidon5,
    derivePublicKey) require either:
    - A native Rust binding, or
    - Shelling out to the Node.js SDK via subprocess.

    Args:
        model_hash: Hash of the model identifier.
        operator_private_key: Operator's EdDSA private key.
        permissions: List of Permission flags.
        expiry_timestamp: Unix timestamp when the credential expires.

    Raises:
        InvalidPermissionError: If permissions violate cumulative encoding or expiry is past.
        NotImplementedError: Always (crypto primitives not yet available in pure Python).
    """
    validate_agent_expiry(expiry_timestamp)
    bitmask = permissions_to_bitmask(permissions)
    validate_cumulative_bit_encoding(bitmask)
    raise NotImplementedError(
        "create_agent_credential requires EdDSA + Poseidon primitives. "
        "Use the Node.js SDK via prove_handshake() or install a native crypto binding."
    )
