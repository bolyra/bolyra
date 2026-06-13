"""Shared subprocess bridge helpers for the Node.js SDK.

Extracted from handshake.py and delegation.py to avoid duplication.
All modules that need to shell out to the Node.js SDK import from here.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from bolyra.errors import (
    BolyraError,
    ConfigurationError,
    ProofGenerationError,
    ScopeEscalationError,
    VerificationError,
)


def resolve_node_sdk(config: Any | None) -> Path:
    """Resolve the path to the Bolyra Node.js SDK.

    Checks ``config.node_sdk_path`` first, then falls back to the sibling
    ``../sdk`` directory relative to the ``sdk-python/`` package root.
    """
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


def run_node_script(script: str, sdk_path: Path, op: str = "bridge") -> dict[str, Any]:
    """Run a Node.js script in the SDK directory and return parsed JSON output.

    Args:
        script: JavaScript source to execute via ``node -e``.
        sdk_path: Working directory (the Node.js SDK root).
        op: Operation label for error messages (e.g. "identity", "handshake").
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
