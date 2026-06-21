"""Shared fixtures for Bolyra CrewAI tool tests."""

from __future__ import annotations

import subprocess

import pytest


# Check if Node.js is available (needed for ZKP tools, not for SD-JWT)
try:
    subprocess.run(
        ["node", "--version"],
        capture_output=True,
        check=True,
        timeout=5,
    )
    NODE_AVAILABLE = True
except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
    NODE_AVAILABLE = False

# Check if bolyra Python SDK is importable
try:
    import bolyra  # noqa: F401

    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False

# Check if crewai is importable
try:
    import crewai  # noqa: F401

    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


requires_node_and_sdk = pytest.mark.skipif(
    not (NODE_AVAILABLE and SDK_AVAILABLE),
    reason="Requires Node.js >= 18 and bolyra Python SDK on PYTHONPATH",
)

requires_sdk = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="Requires bolyra Python SDK on PYTHONPATH",
)

requires_crewai = pytest.mark.skipif(
    not CREWAI_AVAILABLE,
    reason="Requires crewai>=0.50.0",
)
