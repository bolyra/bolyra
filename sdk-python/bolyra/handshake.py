"""Handshake proof generation and verification.

Design Choice -- subprocess bridge to Node.js SDK
==================================================

ZK proof generation in Bolyra uses snarkjs (Groth16 + PLONK), which is
a JavaScript-only library with no production-quality Python port. Rather
than reimplementing snarkjs in Python (fragile, hard to audit, divergent
from the canonical implementation), this module shells out to the Bolyra
Node.js SDK via ``subprocess``.

This means:
- Node.js (>=18) and the ``@bolyra/sdk`` npm package must be installed.
- Proof generation runs in a child process; the Python SDK handles
  serialization, error mapping, and type conversion.
- Everything else (types, validation, error handling, permission logic)
  is pure Python with zero external dependencies.

For LangChain/CrewAI developers, this is transparent: call
``prove_handshake()`` / ``verify_handshake()`` and get back typed
Python dataclasses. The Node.js bridge is an implementation detail.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from bolyra.errors import ConfigurationError, ProofGenerationError, VerificationError
from bolyra.types import (
    AgentCredential,
    BolyraConfig,
    HandshakeResult,
    HumanIdentity,
    Proof,
)


def _resolve_node_sdk(config: BolyraConfig | None) -> Path:
    """Resolve the path to the Bolyra Node.js SDK."""
    if config and config.node_sdk_path:
        p = Path(config.node_sdk_path)
    else:
        # Default: sibling directory ../sdk relative to sdk-python
        p = Path(__file__).resolve().parent.parent.parent / "sdk"
    if not (p / "package.json").exists():
        raise ConfigurationError(
            "node_sdk_path",
            f"Bolyra Node.js SDK not found at {p}. "
            "Install @bolyra/sdk or set config.node_sdk_path.",
        )
    return p


def _run_node_script(script: str, sdk_path: Path) -> dict[str, Any]:
    """Run a Node.js script in the SDK directory and return parsed JSON output."""
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
        raise ProofGenerationError("handshake", "Node.js subprocess timed out after 120s")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ProofGenerationError("handshake", f"Node.js subprocess failed: {stderr}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ProofGenerationError(
            "handshake",
            f"Failed to parse Node.js output as JSON: {e}",
        )


def prove_handshake(
    human: HumanIdentity,
    agent: AgentCredential,
    *,
    scope: int = 1,
    nonce: int | None = None,
    config: BolyraConfig | None = None,
) -> tuple[Proof, Proof, int]:
    """Generate a mutual handshake proof (human + agent).

    Shells out to the Node.js SDK for snarkjs proof generation.
    Returns (human_proof, agent_proof, nonce).

    Args:
        human: The human's identity.
        agent: The agent's credential.
        scope: Scope identifier (default: 1).
        nonce: Session nonce (default: current timestamp in ms).
        config: SDK configuration.

    Returns:
        Tuple of (human_proof, agent_proof, session_nonce).

    Raises:
        ConfigurationError: If Node.js SDK is not found.
        ProofGenerationError: If proof generation fails.
    """
    import time

    if nonce is None:
        nonce = int(time.time() * 1000)

    sdk_path = _resolve_node_sdk(config)

    # Build a Node.js script that imports the SDK and generates proofs
    script = f"""
const {{ proveHandshake }} = require('./dist/index.js');

async function main() {{
    const human = {{
        secret: {human.secret}n,
        publicKey: {{ x: {human.public_key.x}n, y: {human.public_key.y}n }},
        commitment: {human.commitment}n,
    }};
    const agent = {{
        modelHash: {agent.model_hash}n,
        operatorPublicKey: {{ x: {agent.operator_public_key.x}n, y: {agent.operator_public_key.y}n }},
        permissionBitmask: {agent.permission_bitmask}n,
        expiryTimestamp: {agent.expiry_timestamp}n,
        signature: {{
            R8: {{ x: {agent.signature.r8.x}n, y: {agent.signature.r8.y}n }},
            S: {agent.signature.s}n,
        }},
        commitment: {agent.commitment}n,
    }};
    const result = await proveHandshake(human, agent, {{
        scope: {scope}n,
        nonce: {nonce}n,
    }});
    // Serialize BigInts as strings for JSON
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize({{
        humanProof: result.humanProof,
        agentProof: result.agentProof,
        nonce: result.nonce,
    }}));
}}
main().catch(e => {{ console.error(e.message); process.exit(1); }});
"""

    data = _run_node_script(script, sdk_path)

    human_proof = Proof(
        proof=data["humanProof"]["proof"],
        public_signals=data["humanProof"]["publicSignals"],
    )
    agent_proof = Proof(
        proof=data["agentProof"]["proof"],
        public_signals=data["agentProof"]["publicSignals"],
    )
    return human_proof, agent_proof, int(data["nonce"])


def verify_handshake(
    human_proof: Proof,
    agent_proof: Proof,
    nonce: int,
    config: BolyraConfig | None = None,
) -> HandshakeResult:
    """Verify a handshake result (check proof validity off-chain).

    Shells out to the Node.js SDK for snarkjs verification.
    For on-chain verification, submit proofs to IdentityRegistry.verifyHandshake().

    Args:
        human_proof: The human's ZK proof.
        agent_proof: The agent's ZK proof.
        nonce: The session nonce used during proof generation.
        config: SDK configuration.

    Returns:
        HandshakeResult with nullifiers and verification status.

    Raises:
        ConfigurationError: If Node.js SDK is not found.
        VerificationError: If verification fails.
    """
    sdk_path = _resolve_node_sdk(config)

    human_proof_json = json.dumps(human_proof.proof)
    human_signals_json = json.dumps(human_proof.public_signals)
    agent_proof_json = json.dumps(agent_proof.proof)
    agent_signals_json = json.dumps(agent_proof.public_signals)

    script = f"""
const {{ verifyHandshake }} = require('./dist/index.js');

async function main() {{
    const humanProof = {{
        proof: {human_proof_json},
        publicSignals: {human_signals_json},
    }};
    const agentProof = {{
        proof: {agent_proof_json},
        publicSignals: {agent_signals_json},
    }};
    const result = await verifyHandshake(humanProof, agentProof, {nonce}n);
    const serialize = (obj) => JSON.stringify(obj, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    );
    console.log(serialize(result));
}}
main().catch(e => {{ console.error(e.message); process.exit(1); }});
"""

    data = _run_node_script(script, sdk_path)

    return HandshakeResult(
        human_nullifier=int(data["humanNullifier"]),
        agent_nullifier=int(data["agentNullifier"]),
        session_nonce=int(data["sessionNonce"]),
        scope_commitment=int(data["scopeCommitment"]),
        verified=data["verified"],
    )
