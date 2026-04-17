"""Score the current patent draft as-is. Serves as iteration 0 baseline.

Runs one Claude CLI judge call that acts as a panel of 4 adversarial reviewers
(USPTO examiner, competitor attorney, 101 specialist, 112 specialist) and
returns a 5-dimension score plus per-claim breakdown for 101/103/112.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object
from scoring import DIMENSIONS, MAX_PER_DIMENSION, MAX_TOTAL


BASELINE_PROMPT = """You are a panel of 4 adversarial reviewers (USPTO examiner,
competitor attorney, 101 specialist, 112 specialist) jointly scoring a provisional
patent on 5 dimensions.

PATENT:
{patent_text}

Score the ENTIRE patent (independent claims 1/9/15/16, averaged where applicable) on:
- alice_101 (0-20): 35 USC 101 survival odds
- obviousness_103 (0-20): 35 USC 103 defense odds
- support_112 (0-20): written description + definiteness
- design_around (0-20): competitor escape resistance
- scope (0-20): commercial coverage breadth

For the claim-dependent dimensions (alice_101, obviousness_103, support_112) also
provide per-claim scores under a "per_claim" key mapping claim number → points.

Return ONLY a JSON object (no markdown fences) with this shape:
{{
  "alice_101":       {{"points": N, "per_claim": {{"1": N, "9": N, "15": N, "16": N}}, "critique": "..."}},
  "obviousness_103": {{"points": N, "per_claim": {{"1": N, "9": N, "15": N, "16": N}}, "critique": "..."}},
  "support_112":     {{"points": N, "per_claim": {{"1": N, "9": N, "15": N, "16": N}}, "critique": "..."}},
  "design_around":   {{"points": N, "critique": "..."}},
  "scope":           {{"points": N, "critique": "..."}},
  "total": N
}}

All N must be integers. Dimension points in [0, 20]. Total in [0, 100] = sum of 5 points.
"""

REQUIRED_KEYS: tuple[str, ...] = (*DIMENSIONS, "total")


def _parse_baseline_response(raw: str) -> dict[str, Any]:
    """Parse the judge's response. Validates all keys present and ranges."""
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
    patent_text: str,
    *,
    model: str = "opus",
    timeout: int = 600,
    max_chars: int = 120000,
) -> dict[str, Any]:
    """Score the whole patent on 5 dimensions + per-claim breakdown.

    Args:
        patent_text: full markdown of the patent draft. Truncated at max_chars
            to stay within CLI argv and model context limits. The default 120k
            covers the full IdentityOS patent (~69k chars) with headroom; the
            prior 30k limit silently truncated mid-paragraph and led the judge
            to report a non-existent spec truncation as a 112 red flag.
        model: Claude model alias (default opus for depth)
        timeout: seconds; default 600 since this is a big single-shot judgment
        max_chars: truncation threshold to stay within prompt limits

    Returns:
        dict with keys: alice_101, obviousness_103, support_112, design_around, scope, total
    """
    prompt = BASELINE_PROMPT.format(patent_text=patent_text[:max_chars])
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    return _parse_baseline_response(raw)
