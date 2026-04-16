"""Shared helpers for patent-autoresearch modules.

Extracted from scoring.py and judge.py to avoid copy-paste duplication.
Imports are deliberately minimal (stdlib only); no pip dependencies.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any


def call_claude_cli(prompt: str, *, model: str = "opus", timeout: int = 300) -> str:
    """Invoke the Claude CLI with a prompt and return its stdout.

    Uses the user's Claude MAX login (no API keys, no SDK) per the user preference
    recorded in feedback_claude_max memory.

    Args:
        prompt: The prompt text to send (stdin-style, passed via -p).
        model: The Claude model alias (e.g. "opus", "sonnet", "haiku").
        timeout: Hard timeout in seconds. On expiry, raises RuntimeError with context.

    Returns:
        Raw stdout from the CLI. Downstream code must parse as needed.

    Raises:
        RuntimeError: if the CLI times out, exits non-zero, or returns stderr context.
    """
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", model],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Claude CLI timed out after {timeout}s") from e
    if result.returncode != 0:
        raise RuntimeError(
            f"Claude CLI failed (exit {result.returncode}): {result.stderr[:500]}"
        )
    return result.stdout


def extract_json_balanced(raw: str, open_char: str, close_char: str) -> Any:
    """Find the first top-level JSON structure starting at `open_char` in `raw`.

    Handles prose preamble/postamble and markdown fences by scanning for the
    opening delimiter and balancing delimiters with string-awareness (tracks
    double-quoted string boundaries and backslash escapes). Does not support
    single-quoted JSON (standard Claude output uses double quotes only).

    Args:
        raw: Raw text containing one top-level JSON object or array.
        open_char: "{" for objects, "[" for arrays.
        close_char: "}" for objects, "]" for arrays.

    Returns:
        Parsed JSON value (dict for objects, list for arrays).

    Raises:
        ValueError: if no structure is found or if the structure is unbalanced.
    """
    start = raw.find(open_char)
    if start == -1:
        structure = "object" if open_char == "{" else "array"
        raise ValueError(f"no JSON {structure} found in response")
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return json.loads(raw[start : i + 1])
    structure = "object" if open_char == "{" else "array"
    raise ValueError(f"unbalanced JSON {structure} in response")


def extract_json_object(raw: str) -> dict[str, Any]:
    """Convenience: extract the first top-level JSON object."""
    result = extract_json_balanced(raw, "{", "}")
    if not isinstance(result, dict):
        raise ValueError(f"expected JSON object, got {type(result).__name__}")
    return result


def extract_json_array(raw: str) -> list[Any]:
    """Convenience: extract the first top-level JSON array."""
    result = extract_json_balanced(raw, "[", "]")
    if not isinstance(result, list):
        raise ValueError(f"expected JSON array, got {type(result).__name__}")
    return result
