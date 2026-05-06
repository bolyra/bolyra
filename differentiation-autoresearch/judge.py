"""Judge — score a construction 0-10 on the 5-dim × 2-pt rubric.

Input:  construction.md + attacks.md + rubric.md
Output: score.json
  {
    "candidate_id": "C2",
    "dims": {
      "baseline_dominance": {"points": 2, "justification": "..."},
      "formal_security_argument": {...},
      "implementability": {...},
      "adversarial_survival": {...},
      "scenario_fit": {...}
    },
    "strength": 10,
    "verdict": "promote" | "consider" | "drop",
    "gaps": ["...", "..."]
  }

Rule: strength = sum(dims.points); any dim at 0 or 1 caps total at 9.
"""
from __future__ import annotations

import json
from pathlib import Path

import _imports  # noqa: F401
from _shared import call_claude_cli, extract_json_object

HERE = Path(__file__).resolve().parent
RUBRIC_PATH = HERE / "rubric.md"

DIMS = [
    "baseline_dominance",
    "formal_security_argument",
    "implementability",
    "adversarial_survival",
    "scenario_fit",
]


def _verdict(strength: int) -> str:
    if strength == 10:
        return "promote"
    if strength >= 7:
        return "consider"
    return "drop"


def _cap_at_9_if_any_zero_or_one(dims: dict) -> int:
    total = sum(d["points"] for d in dims.values())
    any_weak = any(d["points"] < 2 for d in dims.values())
    if any_weak and total == 10:
        # Sanity: cannot happen if all dims < 2, but guard against judge returning inconsistent
        total = 9
    return total


def run(
    candidate: dict,
    out_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 300,
) -> dict:
    """Score the construction. Return the score dict and write score.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    construction_path = out_dir / "construction.md"
    attacks_path = out_dir / "attacks.md"
    if not construction_path.exists() or not attacks_path.exists():
        raise RuntimeError(f"construction.md or attacks.md missing in {out_dir}")
    construction = construction_path.read_text()
    attacks = attacks_path.read_text()
    rubric = RUBRIC_PATH.read_text()

    prompt = (
        "You are a rigorous rubric-based judge. Score the following Bolyra construction "
        "on the 5-dim × 2-pt rubric. You MUST award 0 on any dim you cannot positively "
        "justify from the construction.md or attacks.md contents. Absence of evidence is 0.\n\n"
        "You MUST NOT award 10 without every dimension at 2.\n\n"
        "Return ONLY a JSON object (no markdown fences) with this exact shape:\n"
        "{\n"
        '  "candidate_id": "...",\n'
        '  "dims": {\n'
        '    "baseline_dominance": {"points": 0|1|2, "justification": "..."},\n'
        '    "formal_security_argument": {"points": 0|1|2, "justification": "..."},\n'
        '    "implementability": {"points": 0|1|2, "justification": "..."},\n'
        '    "adversarial_survival": {"points": 0|1|2, "justification": "..."},\n'
        '    "scenario_fit": {"points": 0|1|2, "justification": "..."}\n'
        "  },\n"
        '  "gaps": ["specific gap the mutator should fix", "..."]\n'
        "}\n\n"
        f"RUBRIC:\n{rubric}\n\n"
        f"CANDIDATE:\n{json.dumps(candidate, indent=2)}\n\n"
        f"CONSTRUCTION:\n{construction}\n\n"
        f"ATTACKS (Tier 3):\n{attacks}\n"
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    data = extract_json_object(raw)

    # Validate shape
    if "dims" not in data:
        raise RuntimeError(f"judge missing 'dims' field: {raw[:500]}")
    for dim in DIMS:
        if dim not in data["dims"]:
            raise RuntimeError(f"judge missing dim {dim}: {raw[:500]}")
        pts = data["dims"][dim].get("points")
        if pts not in (0, 1, 2):
            raise RuntimeError(f"judge dim {dim} points={pts} out of {{0,1,2}}")

    strength = _cap_at_9_if_any_zero_or_one(data["dims"])
    data["candidate_id"] = candidate["id"]
    data["strength"] = strength
    data["verdict"] = _verdict(strength)

    (out_dir / "score.json").write_text(json.dumps(data, indent=2))
    return data
