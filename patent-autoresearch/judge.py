"""Tier 1 attack prioritizer.

Scores raw adversarial attacks on three axes (severity, specificity, remediability)
and buckets them into high/medium/low priority. The high-priority set is what
Tier 2 actually tries to fix each iteration.

Uses Claude CLI as judge, per feedback_claude_max preference. No API keys, no SDK.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array


SEVERITY_HIGH_THRESHOLD: int = 22  # total >= 22 → high
SEVERITY_MEDIUM_THRESHOLD: int = 15  # total 15..21 → medium; else low
MAX_PER_AXIS: int = 10
AXES = ("severity", "specificity", "remediability")


@dataclass
class AttackScore:
    attack_id: str
    severity: int = 0
    specificity: int = 0
    remediability: int = 0
    total: int = 0
    priority: str = "low"  # "high" | "medium" | "low"

    def finalize(self) -> None:
        self.total = self.severity + self.specificity + self.remediability
        if self.total >= SEVERITY_HIGH_THRESHOLD:
            self.priority = "high"
        elif self.total >= SEVERITY_MEDIUM_THRESHOLD:
            self.priority = "medium"
        else:
            self.priority = "low"


_RUBRIC_CACHE: str | None = None


def _load_rubric() -> str:
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        rubric_path = Path(__file__).parent / "rubrics" / "tier1_attack_rubric.md"
        _RUBRIC_CACHE = rubric_path.read_text()
    return _RUBRIC_CACHE


def _parse_judge_response(raw: str) -> list[AttackScore]:
    """Parse a Claude judge response into AttackScore entries.

    Validates:
      - each entry has id + all three axes
      - all axis values in [0, MAX_PER_AXIS]
    """
    data = extract_json_array(raw)
    scores: list[AttackScore] = []
    for entry in data:
        if "id" not in entry:
            raise ValueError(f"attack entry missing 'id' field: {entry}")
        attack_id = entry["id"]
        for axis in AXES:
            if axis not in entry:
                raise ValueError(f"attack {attack_id} missing '{axis}' field")
            value = int(entry[axis])
            if not (0 <= value <= MAX_PER_AXIS):
                raise ValueError(
                    f"attack {attack_id} {axis}={value} out of range [0, {MAX_PER_AXIS}]"
                )
        score = AttackScore(
            attack_id=attack_id,
            severity=int(entry["severity"]),
            specificity=int(entry["specificity"]),
            remediability=int(entry["remediability"]),
        )
        score.finalize()
        scores.append(score)
    return scores


def rank_attacks(
    attacks: list[dict[str, Any]],
    context_patent_text: str,
    *,
    model: str = "sonnet",
    timeout: int = 240,
) -> list[AttackScore]:
    """Rank a batch of adversarial attacks on severity/specificity/remediability.

    Args:
        attacks: list of attack dicts with at least {id, persona, finding}
        context_patent_text: patent text for reviewer context (truncated at 6000 chars)
        model: Claude model for the judge (default sonnet; opus if you want deeper reads)
        timeout: Claude CLI timeout in seconds

    Returns:
        list[AttackScore] matching the input length, in the same order the judge returned.
    """
    if not attacks:
        return []
    rubric = _load_rubric()
    prompt = (
        "You are a senior patent attorney triaging adversarial findings for a provisional "
        "patent application. Rate each attack on three 0-10 axes.\n\n"
        f"RUBRIC:\n{rubric}\n\n"
        f"PATENT CONTEXT:\n{context_patent_text[:6000]}\n\n"
        f"ATTACKS:\n{json.dumps(attacks, indent=2)[:10000]}\n\n"
        "Return ONLY a JSON array (no markdown fences), one object per attack:\n"
        '[{"id": "...", "severity": N, "specificity": N, "remediability": N}, ...]\n'
        "Each N must be an integer in [0, 10]. Include every attack from the input."
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    scores = _parse_judge_response(raw)
    if len(scores) != len(attacks):
        raise RuntimeError(
            f"judge returned {len(scores)} scores for {len(attacks)} attacks; "
            f"expected one score per attack. Input ids: {[a.get('id') for a in attacks]}; "
            f"returned ids: {[s.attack_id for s in scores]}"
        )
    return scores
