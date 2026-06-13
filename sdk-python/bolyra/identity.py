"""Identity creation and permission utilities.

Subprocess bridge to the Node.js SDK for:
- Human identity creation (EdDSA keypair + Poseidon commitment)
- Agent credential creation (operator-signed)
- Dev-mode identity fixtures

Permission bitmask encoding and validation are pure Python with zero
external dependencies.
"""

from __future__ import annotations

from bolyra._bridge import resolve_node_sdk, run_node_script
from bolyra.errors import InvalidPermissionError, InvalidSecretError
from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    EdDSASignature,
    HumanIdentity,
    Permission,
    Point,
)

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


def create_human_identity(
    secret: int,
    config: BolyraConfig | None = None,
) -> HumanIdentity:
    """Create a human identity (EdDSA keypair + Poseidon commitment).

    Shells out to the Node.js SDK for Baby Jubjub scalar multiply and
    Poseidon2 hash.

    Args:
        secret: A secret value (random int or derived from a seed phrase).
                KEEP THIS PRIVATE.
        config: SDK configuration (optional).

    Returns:
        HumanIdentity with secret, public_key, and commitment.

    Raises:
        InvalidSecretError: If the secret is invalid.
        ConfigurationError: If the Node.js SDK is not found.
        ProofGenerationError: If the Node.js subprocess fails.
    """
    secret = int(secret)  # Normalize before embedding in JS
    validate_human_secret(secret)
    sdk_path = resolve_node_sdk(config)

    script = f"""
const {{ createHumanIdentity }} = require('./dist/index.js');
async function main() {{
    const human = await createHumanIdentity({secret}n);
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize(human));
}}
main().catch(e => {{ console.error(e.message); process.exit(1); }});
"""
    data = run_node_script(script, sdk_path, op="identity")
    return HumanIdentity(
        secret=int(data["secret"]),
        public_key=Point(x=int(data["publicKey"]["x"]), y=int(data["publicKey"]["y"])),
        commitment=int(data["commitment"]),
    )


def create_agent_credential(
    model_hash: int,
    operator_private_key: int,
    permissions: list[Permission],
    expiry_timestamp: int,
    config: BolyraConfig | None = None,
) -> AgentCredential:
    """Create an AI agent credential signed by the operator.

    Shells out to the Node.js SDK for EdDSA signing, Poseidon5 hash,
    and public key derivation.

    Args:
        model_hash: Hash of the model identifier.
        operator_private_key: Operator's EdDSA private key (int).
        permissions: List of Permission flags.
        expiry_timestamp: Unix timestamp when the credential expires.
        config: SDK configuration (optional).

    Returns:
        AgentCredential with all fields, operator signature, and commitment.

    Raises:
        InvalidPermissionError: If permissions violate cumulative encoding or expiry is past.
        ConfigurationError: If the Node.js SDK is not found.
        ProofGenerationError: If the Node.js subprocess fails.
    """
    validate_agent_expiry(expiry_timestamp)
    bitmask = permissions_to_bitmask(permissions)
    validate_cumulative_bit_encoding(bitmask)

    # Validate inputs before embedding in JS script (injection prevention)
    model_hash = int(model_hash)
    operator_private_key = int(operator_private_key)
    expiry_timestamp = int(expiry_timestamp)

    if operator_private_key < 0 or operator_private_key >= 2**256:
        raise InvalidSecretError(
            "operator_private_key must be in range [0, 2^256) for a 32-byte key"
        )

    sdk_path = resolve_node_sdk(config)

    # Convert int private key to exactly 32-byte hex for JS Buffer.from(hex, 'hex')
    key_hex = format(operator_private_key, '064x')

    # Build permission array for TS SDK (which expects Permission[] enum values)
    perm_values = [int(p) for p in permissions]

    script = f"""
const {{ createAgentCredential }} = require('./dist/index.js');
async function main() {{
    const opKey = Buffer.from('{key_hex}', 'hex');
    const agent = await createAgentCredential(
        {model_hash}n, opKey, {perm_values}, {expiry_timestamp}n
    );
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize(agent));
}}
main().catch(e => {{ console.error(e.message); process.exit(1); }});
"""
    data = run_node_script(script, sdk_path, op="identity")
    return AgentCredential(
        model_hash=int(data["modelHash"]),
        operator_public_key=Point(
            x=int(data["operatorPublicKey"]["x"]),
            y=int(data["operatorPublicKey"]["y"]),
        ),
        permission_bitmask=int(data["permissionBitmask"]),
        expiry_timestamp=int(data["expiryTimestamp"]),
        signature=EdDSASignature(
            r8=Point(
                x=int(data["signature"]["R8"]["x"]),
                y=int(data["signature"]["R8"]["y"]),
            ),
            s=int(data["signature"]["S"]),
        ),
        commitment=int(data["commitment"]),
    )


def create_dev_identities(
    permission_bitmask: int = 0xFF,
    expiry_timestamp: int | None = None,
    config: BolyraConfig | None = None,
) -> tuple[HumanIdentity, AgentCredential, int]:
    """Create fixed-seed dev identities via the Node.js SDK.

    Wraps the TS ``createDevIdentities()`` function. Uses deterministic
    seeds -- NEVER use these in production.

    Args:
        permission_bitmask: Permission bitmask (default: 0xFF, all 8 bits set).
        expiry_timestamp: Unix timestamp for credential expiry
            (default: 2099-12-31 00:00:00 UTC = 4102358400).
        config: SDK configuration (optional).

    Returns:
        Tuple of (human_identity, agent_credential, operator_private_key_int).
        The operator key is the fixed dev key as an int.

    Raises:
        ConfigurationError: If the Node.js SDK is not found.
        ProofGenerationError: If the Node.js subprocess fails.
    """
    sdk_path = resolve_node_sdk(config)

    # Build options object for createDevIdentities
    opts_parts = []
    opts_parts.append(f"permissionBitmask: {permission_bitmask}n")
    if expiry_timestamp is not None:
        opts_parts.append(f"expiryTimestamp: {expiry_timestamp}n")
    opts_str = ", ".join(opts_parts)

    script = f"""
const {{ createDevIdentities }} = require('./dist/index.js');
async function main() {{
    const {{ human, agent, operatorKey }} = await createDevIdentities({{ {opts_str} }});
    const opKeyHex = operatorKey.toString('hex');
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize({{ human, agent, operatorKeyHex: opKeyHex }}));
}}
main().catch(e => {{ console.error(e.message); process.exit(1); }});
"""
    data = run_node_script(script, sdk_path, op="dev_identities")

    human = HumanIdentity(
        secret=int(data["human"]["secret"]),
        public_key=Point(
            x=int(data["human"]["publicKey"]["x"]),
            y=int(data["human"]["publicKey"]["y"]),
        ),
        commitment=int(data["human"]["commitment"]),
    )
    agent = AgentCredential(
        model_hash=int(data["agent"]["modelHash"]),
        operator_public_key=Point(
            x=int(data["agent"]["operatorPublicKey"]["x"]),
            y=int(data["agent"]["operatorPublicKey"]["y"]),
        ),
        permission_bitmask=int(data["agent"]["permissionBitmask"]),
        expiry_timestamp=int(data["agent"]["expiryTimestamp"]),
        signature=EdDSASignature(
            r8=Point(
                x=int(data["agent"]["signature"]["R8"]["x"]),
                y=int(data["agent"]["signature"]["R8"]["y"]),
            ),
            s=int(data["agent"]["signature"]["S"]),
        ),
        commitment=int(data["agent"]["commitment"]),
    )
    operator_key_int = int(data["operatorKeyHex"], 16)

    return human, agent, operator_key_int
