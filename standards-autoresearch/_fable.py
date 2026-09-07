"""Sandboxed generator helper: Fable 5.1 as a TEXT generator, tools disabled.

Found live in iteration 1: `claude -p` inherits the workspace's tool
permissions, and the generator EXECUTED conformance runs it was asked to
merely describe. Generation and execution are separate powers here:
`--tools ""` disables the entire built-in tool set (and ignores
user/project/local settings allowlists), and the strict empty MCP config
excludes every inherited MCP server. The generator emits text, period.
"""
from __future__ import annotations

import subprocess

GENERATOR_MODEL = "claude-fable-5-1"  # Fable 5.1 — resolved + probed 2026-09-06


def call_fable(prompt: str, *, timeout: int = 600) -> str:
    """Invoke Fable 5.1 via the Claude MAX CLI with the tool set disabled."""
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", GENERATOR_MODEL,
             "--tools", "",
             "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}'],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Fable CLI timed out after {timeout}s") from e
    if result.returncode != 0:
        raise RuntimeError(
            f"Fable CLI failed (exit {result.returncode}): {result.stderr[-800:]}"
        )
    return result.stdout
