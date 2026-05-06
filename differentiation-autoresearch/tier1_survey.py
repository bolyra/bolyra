"""Tier 1 — Survey the strongest non-ZK baseline for a given candidate.

Input:  candidate (dict from candidates.json) + baseline markdown files
Output: baseline.md in the iter dir — distilled statement of "best non-ZK alternative
        for THIS specific candidate" so Tier 2 has a clear target to beat.

Uses Claude CLI as the researcher. No web search — baselines are already checked in.
"""
from __future__ import annotations

import json
from pathlib import Path

import _imports  # noqa: F401 — path setup
from _shared import call_claude_cli

HERE = Path(__file__).resolve().parent
BASELINES_DIR = HERE / "baselines"


def _load_baselines() -> str:
    """Concatenate all baseline files with headers."""
    parts: list[str] = []
    for name in sorted(BASELINES_DIR.glob("*.md")):
        parts.append(f"=== {name.name} ===\n{name.read_text()}\n")
    return "\n".join(parts)


def run(candidate: dict, out_dir: Path, *, model: str = "sonnet", timeout: int = 240) -> Path:
    """Write baseline.md for this candidate. Return path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    baselines = _load_baselines()
    prompt = (
        "You are a protocol standards survey analyst. Given a Bolyra differentiation "
        "candidate, distill the STRONGEST non-ZK baseline that could plausibly match it.\n\n"
        "Output a focused baseline.md (800-1500 words) that:\n"
        "  1. Names the best alternative (RFC 7662 variants, W3C VC+BBS+, SPIFFE/WIMSE, or combination)\n"
        "  2. Specifies exactly what that alternative CAN do against this candidate\n"
        "  3. Specifies what it fundamentally CANNOT do\n"
        "  4. Cites concrete RFCs/drafts/specs with links\n"
        "  5. Ends with a one-line 'Bar to beat:' statement\n\n"
        "Do not propose a ZK construction. That is Tier 2's job. Do not hedge — be specific about "
        "what the baseline can and cannot express. Absence of a capability must be named explicitly.\n\n"
        f"CANDIDATE:\n{json.dumps(candidate, indent=2)}\n\n"
        f"BASELINE SOURCE MATERIAL:\n{baselines}\n\n"
        "Return ONLY the markdown content. No preamble, no fences."
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    path = out_dir / "baseline.md"
    path.write_text(raw.strip() + "\n")
    return path
