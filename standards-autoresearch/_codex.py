"""Codex judge helper for the standards-autoresearch loop.

Codex is THE judge at every gate in this loop (founder decision 2026-09-06):
Tier-1 ranking, Tier-2 acceptance, Tier-3 adversarial review, and the
ECOSYSTEM POSITION scoring dim. Fable 5.1 generates; Codex judges.

Invocation rules (from workspace memory):
- run from a trusted git directory (the repo root), never from scratch dirs
- stdin MUST be closed (< /dev/null equivalent) or codex can hang
- fail loudly if codex is unavailable (program.md rule 2b — no silent fallback)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from _shared import extract_json_object

REPO_ROOT = Path(__file__).resolve().parent.parent

GENERATOR_MODEL = "claude-fable-5-1"  # Fable 5.1 — resolved + probed 2026-09-06


class CodexUnavailableError(RuntimeError):
    """Raised when the codex CLI is missing — the loop must halt, not fall back."""


def call_codex(prompt: str, *, timeout: int = 600) -> str:
    """Run `codex exec` with the prompt, stdin closed, from the repo root.

    Returns raw stdout. Raises on timeout/non-zero exit/missing binary.
    """
    if shutil.which("codex") is None:
        raise CodexUnavailableError(
            "codex CLI not found on PATH; program.md rule 2b forbids fallback"
        )
    try:
        result = subprocess.run(
            # --sandbox read-only: judge calls consume untrusted content
            # (web signals, model artifacts); containment is enforced at the
            # process level, not just by prompt text.
            ["codex", "exec", "--sandbox", "read-only", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd=REPO_ROOT,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"codex exec timed out after {timeout}s") from e
    if result.returncode != 0:
        raise RuntimeError(
            f"codex exec failed (exit {result.returncode}): {result.stderr[:500]}"
        )
    return result.stdout


def call_codex_json(prompt: str, *, timeout: int = 600) -> dict[str, Any]:
    """Call codex and extract the first top-level JSON object from its output.

    The prompt MUST instruct codex to emit a single JSON object; this parses
    around any prose/preamble codex adds.
    """
    raw = call_codex(prompt, timeout=timeout)
    try:
        return extract_json_object(raw)
    except ValueError as e:
        raise RuntimeError(
            f"codex output contained no parseable JSON object: {raw[-800:]}"
        ) from e
