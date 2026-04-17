"""Score the current protocol state as-is. Serves as iteration 0 baseline.

Scores the actual circuits, contracts, tests, and specs on all 4 dimensions
(correctness, completeness, adoption, standards). Uses Claude CLI for the
LLM-judged dimensions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object
from scoring import DIMENSIONS, MAX_PER_DIMENSION, MAX_TOTAL


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent

BASELINE_PROMPT = """You are a protocol review panel scoring the current state of the
Bolyra identity protocol on 4 dimensions.

CIRCUITS:
{circuit_text}

CONTRACTS:
{contract_text}

TESTS (summary):
{test_summary}

SPECS / DOCS:
{spec_text}

Score the ENTIRE protocol on:
- correctness (0-25): circuit soundness, test coverage, no known bugs
- completeness (0-25): all CIP features present, artifacts exist
- adoption (0-25): SDK quality, framework integrations, DX, error messages
- standards (0-25): normative language, test vectors, interop, spec quality

Return ONLY a JSON object (no markdown fences):
{{
  "correctness":  {{"points": N, "critique": "..."}},
  "completeness": {{"points": N, "critique": "..."}},
  "adoption":     {{"points": N, "critique": "..."}},
  "standards":    {{"points": N, "critique": "..."}},
  "total": N
}}

All N must be integers. Dimension points in [0, 25]. Total in [0, 100] = sum of 4 points.
"""


def _gather_circuits() -> str:
    circuits_dir = PROJECT_ROOT / "circuits" / "src"
    if not circuits_dir.exists():
        return "(no circuits directory found)"
    parts = []
    for f in sorted(circuits_dir.rglob("*.circom")):
        try:
            parts.append(f"--- {f.name} ---\n{f.read_text()[:5000]}\n")
        except Exception:
            continue
    return "\n".join(parts) if parts else "(no .circom files found)"


def _gather_contracts() -> str:
    contracts_dir = PROJECT_ROOT / "contracts" / "contracts"
    if not contracts_dir.exists():
        return "(no contracts directory found)"
    parts = []
    for f in sorted(contracts_dir.rglob("*.sol")):
        try:
            parts.append(f"--- {f.name} ---\n{f.read_text()[:5000]}\n")
        except Exception:
            continue
    return "\n".join(parts) if parts else "(no .sol files found)"


def _gather_test_summary() -> str:
    parts = []
    for test_dir in [PROJECT_ROOT / "circuits" / "test", PROJECT_ROOT / "contracts" / "test"]:
        if not test_dir.exists():
            continue
        for f in sorted(test_dir.rglob("*")):
            if f.is_file() and f.suffix in (".js", ".ts", ".py"):
                try:
                    parts.append(f"--- {f.name} ({f.stat().st_size} bytes) ---\n{f.read_text()[:2000]}\n")
                except Exception:
                    continue
    return "\n".join(parts) if parts else "(no test files found)"


def _gather_specs() -> str:
    parts = []
    docs_dir = PROJECT_ROOT / "docs"
    if docs_dir.exists():
        for f in sorted(docs_dir.rglob("*.md")):
            try:
                parts.append(f"--- {f.name} ---\n{f.read_text()[:3000]}\n")
            except Exception:
                continue
    # Also check for drafts
    drafts_dir = PROJECT_ROOT / "drafts"
    if drafts_dir.exists():
        for f in sorted(drafts_dir.rglob("*.md")):
            try:
                parts.append(f"--- {f.name} ---\n{f.read_text()[:3000]}\n")
            except Exception:
                continue
    return "\n".join(parts) if parts else "(no spec/doc files found)"


REQUIRED_KEYS: tuple[str, ...] = (*DIMENSIONS, "total")


def _parse_baseline_response(raw: str) -> dict[str, Any]:
    data = extract_json_object(raw)
    for key in REQUIRED_KEYS:
        if key not in data:
            raise ValueError(f"baseline response missing key: {key}")
    for dim in DIMENSIONS:
        d = data[dim]
        if "points" not in d:
            raise ValueError(f"baseline dimension '{dim}' missing 'points' key")
        points = int(d["points"])
        if not (0 <= points <= MAX_PER_DIMENSION):
            raise ValueError(f"baseline dimension '{dim}' points={points} out of range [0, {MAX_PER_DIMENSION}]")
        d["points"] = points
    total = int(data["total"])
    if not (0 <= total <= MAX_TOTAL):
        raise ValueError(f"baseline total={total} out of range [0, {MAX_TOTAL}]")
    data["total"] = total
    return data


def score_baseline(
    *,
    model: str = "opus",
    timeout: int = 600,
) -> dict[str, Any]:
    """Score the current protocol state on 4 dimensions.

    Reads circuit files, contract files, test files, and specs as context.
    Uses Claude CLI for the LLM-judged assessment.

    Returns:
        dict with keys: correctness, completeness, adoption, standards, total
    """
    circuit_text = _gather_circuits()
    contract_text = _gather_contracts()
    test_summary = _gather_test_summary()
    spec_text = _gather_specs()

    prompt = BASELINE_PROMPT.format(
        circuit_text=circuit_text[:25000],
        contract_text=contract_text[:25000],
        test_summary=test_summary[:15000],
        spec_text=spec_text[:15000],
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    return _parse_baseline_response(raw)
