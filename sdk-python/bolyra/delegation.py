"""Delegation proof generation and verification.

Thin subprocess bridge to ``@bolyra/sdk``'s ``delegate()`` and
``verifyDelegation()`` -- mirrors :mod:`bolyra.handshake`. ZK proving lives
in Node.js (snarkjs / rapidsnark); Python owns types, pre-flight validation,
and structured error mapping.

Scope narrowing is one-way: the underlying circuit and contract reject any
delegatee scope that is not a subset of the delegator's, and any expiry past
the delegator's. The cumulative-bit invariants (bit 4 implies 2+3, bit 3
implies 2) are enforced on the delegatee scope by the circuit.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from bolyra.errors import (
    BolyraError,
    ConfigurationError,
    ProofGenerationError,
    ScopeEscalationError,
    VerificationError,
)
from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    DelegateeMerkleProof,
    DelegationResult,
    Proof,
)

# Delegation circuit MAX_DEPTH -- must match circuits/src/Delegation.circom.
DELEGATION_MAX_DEPTH = 20


def _resolve_node_sdk(config: BolyraConfig | None) -> Path:
    """Resolve the path to the Bolyra Node.js SDK (mirrors handshake module)."""
    if config and config.node_sdk_path:
        p = Path(config.node_sdk_path)
    else:
        p = Path(__file__).resolve().parent.parent.parent / "sdk"
    if not (p / "package.json").exists():
        raise ConfigurationError(
            "node_sdk_path",
            f"Bolyra Node.js SDK not found at {p}. "
            "Install @bolyra/sdk or set config.node_sdk_path.",
        )
    return p


def _run_node_script(script: str, sdk_path: Path, op: str) -> dict[str, Any]:
    """Run a Node.js script and return parsed JSON output.

    ``op`` is the operation name used in ProofGenerationError ("delegation"
    or "delegation_verify").
    """
    try:
        result = subprocess.run(
            ["node", "-e", script],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(sdk_path),
        )
    except FileNotFoundError:
        raise ConfigurationError(
            "node",
            "Node.js not found on PATH. Install Node.js >= 18 to use proof generation.",
        )
    except subprocess.TimeoutExpired:
        raise ProofGenerationError(op, "Node.js subprocess timed out after 120s")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Try to surface a typed BolyraError if the TS bridge emitted one.
        try:
            payload = json.loads(stderr.splitlines()[-1])
            if isinstance(payload, dict) and "code" in payload:
                code = payload["code"]
                msg = payload.get("message", stderr)
                if code == "SCOPE_ESCALATION":
                    raise ScopeEscalationError(
                        payload.get("details", {}).get("delegator_scope", 0),
                        payload.get("details", {}).get("delegatee_scope", 0),
                    )
                if code == "VERIFICATION_FAILED":
                    raise VerificationError(msg)
                raise BolyraError(msg, code, payload.get("details"))
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
        raise ProofGenerationError(op, f"Node.js subprocess failed: {stderr}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ProofGenerationError(op, f"Failed to parse Node.js output as JSON: {e}")


def delegate(
    delegator: AgentCredential,
    delegator_operator_private_key: int,
    delegatee_commitment: int,
    delegatee_scope: int,
    delegatee_expiry: int,
    previous_scope_commitment: int,
    session_nonce: int,
    *,
    current_timestamp: int | None = None,
    delegatee_merkle_proof: DelegateeMerkleProof | None = None,
    hop_index: int = 0,
    config: BolyraConfig | None = None,
) -> tuple[Proof, DelegationResult]:
    """Generate a single-hop Delegation proof.

    Shells out to ``@bolyra/sdk``'s ``delegate()``. The Python side handles
    cheap pre-flight checks (scope escalation, expiry escalation, Merkle
    proof shape) so callers do not pay subprocess overhead for trivial
    rejections.

    Args:
        delegator: The delegating agent's credential.
        delegator_operator_private_key: EdDSA private key of the operator
            who minted ``delegator``. Used to sign the delegation token.
        delegatee_commitment: Identity commitment of the recipient.
        delegatee_scope: Narrowed permission bitmask being granted.
        delegatee_expiry: Expiry timestamp (must be <= delegator expiry).
        previous_scope_commitment: Chain link from the prior hop. For hop 1
            this is the handshake's ``scope_commitment``.
        session_nonce: Session nonce of the originating handshake.
        current_timestamp: Proof binding timestamp (defaults to now).
        delegatee_merkle_proof: Optional Merkle inclusion proof. Defaults to
            the single-leaf pattern (``length=1, index=0, siblings=[0]*20``).
        hop_index: Informational hop number; not consumed by the circuit.
        config: SDK configuration.

    Returns:
        Tuple of ``(Proof, DelegationResult)`` matching the TS SDK.

    Raises:
        ScopeEscalationError: If ``delegatee_scope`` is not a subset of
            ``delegator.permission_bitmask``.
        BolyraError: ``EXPIRY_ESCALATION`` if expiry is extended;
            ``INVALID_MERKLE_PROOF`` if siblings length is wrong.
        ProofGenerationError: If the Node.js bridge fails.
    """
    # Pre-flight in Python -- avoids the subprocess for obvious rejections.
    if (delegatee_scope & ~delegator.permission_bitmask) != 0:
        raise ScopeEscalationError(delegator.permission_bitmask, delegatee_scope)
    if delegatee_expiry > delegator.expiry_timestamp:
        raise BolyraError(
            f"Delegatee expiry ({delegatee_expiry}) exceeds delegator expiry "
            f"({delegator.expiry_timestamp}). Delegations may only narrow expiry.",
            "EXPIRY_ESCALATION",
            {
                "delegatee_expiry": str(delegatee_expiry),
                "delegator_expiry": str(delegator.expiry_timestamp),
            },
        )
    if delegatee_merkle_proof is not None and (
        len(delegatee_merkle_proof.siblings) != DELEGATION_MAX_DEPTH
    ):
        raise BolyraError(
            f"Delegatee Merkle proof must have exactly {DELEGATION_MAX_DEPTH} "
            f"siblings (got {len(delegatee_merkle_proof.siblings)}).",
            "INVALID_MERKLE_PROOF",
        )

    if current_timestamp is None:
        current_timestamp = int(time.time())

    merkle = delegatee_merkle_proof or DelegateeMerkleProof(
        length=1, index=0, siblings=[0] * DELEGATION_MAX_DEPTH
    )
    siblings_literal = "[" + ",".join(f"{s}n" for s in merkle.siblings) + "]"

    sdk_path = _resolve_node_sdk(config)

    script = f"""
const {{ delegate }} = require('./dist/index.js');

async function main() {{
    const delegator = {{
        modelHash: {delegator.model_hash}n,
        operatorPublicKey: {{ x: {delegator.operator_public_key.x}n, y: {delegator.operator_public_key.y}n }},
        permissionBitmask: {delegator.permission_bitmask}n,
        expiryTimestamp: {delegator.expiry_timestamp}n,
        signature: {{
            R8: {{ x: {delegator.signature.r8.x}n, y: {delegator.signature.r8.y}n }},
            S: {delegator.signature.s}n,
        }},
        commitment: {delegator.commitment}n,
    }};
    const {{ proof, result }} = await delegate({{
        delegator,
        delegatorOperatorPrivateKey: {delegator_operator_private_key}n,
        delegateeCommitment: {delegatee_commitment}n,
        delegateeScope: {delegatee_scope}n,
        delegateeExpiry: {delegatee_expiry}n,
        previousScopeCommitment: {previous_scope_commitment}n,
        sessionNonce: {session_nonce}n,
        currentTimestamp: {current_timestamp}n,
        delegateeMerkleProof: {{
            length: {merkle.length},
            index: {merkle.index},
            siblings: {siblings_literal},
        }},
        hopIndex: {hop_index},
    }});
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize({{ proof, result }}));
}}
main().catch(e => {{
    // Try to emit a structured error the Python side can recover.
    const payload = {{
        code: e.code || 'UNKNOWN_ERROR',
        message: e.message || String(e),
        details: e.details || {{}},
    }};
    console.error(JSON.stringify(payload));
    process.exit(1);
}});
"""

    data = _run_node_script(script, sdk_path, op="delegation")
    proof = Proof(
        proof=data["proof"]["proof"],
        public_signals=data["proof"]["publicSignals"],
    )
    result_data = data["result"]
    result = DelegationResult(
        new_scope_commitment=int(result_data["newScopeCommitment"]),
        delegation_nullifier=int(result_data["delegationNullifier"]),
        delegatee_merkle_root=int(result_data["delegateeMerkleRoot"]),
        hop_index=int(result_data["hopIndex"]),
    )
    return proof, result


def verify_delegation(
    proof: Proof,
    previous_scope_commitment: int,
    session_nonce: int,
    current_timestamp: int,
    config: BolyraConfig | None = None,
) -> DelegationResult:
    """Verify a Delegation proof off-chain via snarkjs Groth16 verify.

    For on-chain enforcement, submit ``proof`` and ``proof.public_signals``
    to ``IdentityRegistry.verifyDelegation(proof, pubSignals, sessionNonce)``
    -- the contract additionally checks chain state, max-hops, expiry
    binding, and nullifier replay. Off-chain verify here only confirms the
    proof itself is mathematically valid and that the public signals match
    the expected chain context.

    Args:
        proof: The Delegation proof.
        previous_scope_commitment: Expected ``pubSignals[3]``.
        session_nonce: Expected ``pubSignals[4]``.
        current_timestamp: Expected ``pubSignals[5]``.
        config: SDK configuration.

    Returns:
        DelegationResult with ``hop_index=0`` (verification cannot infer it).

    Raises:
        VerificationError: If the public signals do not match or Groth16
            verification fails.
        ConfigurationError: If Node.js SDK is not found.
    """
    if not proof or not isinstance(proof.proof, dict) or not isinstance(
        proof.public_signals, list
    ):
        raise VerificationError(
            "Invalid Delegation proof structure: expected proof: dict, public_signals: list."
        )
    if len(proof.public_signals) < 6:
        raise VerificationError(
            f"Delegation proof has {len(proof.public_signals)} public signals, expected 6."
        )

    sdk_path = _resolve_node_sdk(config)

    proof_json = json.dumps(proof.proof)
    signals_json = json.dumps(proof.public_signals)

    script = f"""
const {{ verifyDelegation }} = require('./dist/index.js');

async function main() {{
    const proof = {{
        proof: {proof_json},
        publicSignals: {signals_json},
    }};
    const result = await verifyDelegation(
        proof,
        {previous_scope_commitment}n,
        {session_nonce}n,
        {current_timestamp}n,
    );
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize(result));
}}
main().catch(e => {{
    const payload = {{
        code: e.code || 'UNKNOWN_ERROR',
        message: e.message || String(e),
        details: e.details || {{}},
    }};
    console.error(JSON.stringify(payload));
    process.exit(1);
}});
"""

    data = _run_node_script(script, sdk_path, op="delegation_verify")
    return DelegationResult(
        new_scope_commitment=int(data["newScopeCommitment"]),
        delegation_nullifier=int(data["delegationNullifier"]),
        delegatee_merkle_root=int(data["delegateeMerkleRoot"]),
        hop_index=0,
    )
