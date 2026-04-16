"""5-dimension claim scorer using Claude CLI as LLM-as-judge.

Uses user's Claude MAX login via the `claude` CLI, never API keys or the SDK
(user preference recorded in feedback_claude_max memory).

Typical flow:
    from scoring import score_candidate
    score = score_candidate(candidate_dict, patent_text, prior_art_list)
    # score.total in [0, 100], score.verdict in {apply, consider, reject}

Module is pure-Python stdlib + subprocess; no pip dependencies.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object

DIMENSIONS: list[str] = ["alice_101", "obviousness_103", "support_112", "design_around", "scope"]
MAX_PER_DIMENSION: int = 20
MAX_TOTAL: int = MAX_PER_DIMENSION * len(DIMENSIONS)  # 100

# Verdict thresholds (see rubrics/tier2_claim_rubric.md and program.md §4)
APPLY_TOTAL_MIN: int = 80
CONSIDER_TOTAL_MIN: int = 60
REJECT_IF_ANY_DIM_LE: int = 4
APPLY_REQUIRES_ALL_DIMS_ABOVE: int = 8  # apply requires no dim ≤ 8


@dataclass
class DimensionScore:
    name: str
    points: int
    max_points: int = MAX_PER_DIMENSION
    evidence: str = ""
    critique: str = ""


@dataclass
class CandidateScore:
    candidate_id: str
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    total: int = 0
    verdict: str = "reject"

    def finalize(self) -> None:
        """Compute total and verdict from dimensions.

        Verdict rules (per tier2_claim_rubric.md §Verdicts):
            reject:   any dim <= 4 OR total < 60
            apply:    total >= 80 AND no dim <= 8
            consider: total >= 60 otherwise (including total >= 80 with any dim in [5, 8])

        The "total >= 80 with dim <= 8" edge case is intentionally downgraded to
        consider rather than reject — conservative interpretation of the rubric
        per code-quality review feedback.
        """
        self.total = sum(d.points for d in self.dimensions.values())
        # Apply the verdict rules from the rubric.
        any_too_low = any(d.points <= REJECT_IF_ANY_DIM_LE for d in self.dimensions.values())
        any_below_apply_floor = any(d.points <= APPLY_REQUIRES_ALL_DIMS_ABOVE for d in self.dimensions.values())
        if any_too_low:
            self.verdict = "reject"
        elif self.total >= APPLY_TOTAL_MIN and not any_below_apply_floor:
            self.verdict = "apply"
        elif self.total >= CONSIDER_TOTAL_MIN:
            self.verdict = "consider"
        else:
            self.verdict = "reject"


_RUBRIC_CACHE: str | None = None

def _load_rubric() -> str:
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        rubric_path = Path(__file__).parent / "rubrics" / "tier2_claim_rubric.md"
        _RUBRIC_CACHE = rubric_path.read_text()
    return _RUBRIC_CACHE


def _parse_judge_response(raw: str) -> dict[str, DimensionScore]:
    """Parse a Claude judge response into DimensionScore entries.

    Validates:
      - all 5 dimensions present
      - points in [0, MAX_PER_DIMENSION]
    """
    data = extract_json_object(raw)
    dims: dict[str, DimensionScore] = {}
    for name in DIMENSIONS:
        if name not in data:
            raise KeyError(f"missing dimension in judge response: {name}")
        d = data[name]
        if "points" not in d:
            raise ValueError(f"dimension {name} missing 'points' key in judge response")
        points = int(d["points"])
        if not (0 <= points <= MAX_PER_DIMENSION):
            raise ValueError(f"dimension {name} points={points} out of range [0, {MAX_PER_DIMENSION}]")
        dims[name] = DimensionScore(
            name=name,
            points=points,
            evidence=str(d.get("evidence", "")),
            critique=str(d.get("critique", "")),
        )
    return dims


def score_candidate(
    candidate: dict[str, Any],
    context_patent_text: str,
    context_priorart: list[dict[str, Any]],
    *,
    model: str = "opus",
    timeout: int = 300,
) -> CandidateScore:
    """Score a candidate claim rewrite on 5 dimensions via Claude CLI judge.

    Args:
        candidate: dict with at least {id, claim_text, rationale, targets_weakness}
        context_patent_text: patent text for reviewer context (truncated at 8000 chars)
        context_priorart: list of prior-art entries (truncated JSON at 4000 chars)

    Returns:
        CandidateScore with dimensions populated and verdict finalized.
    """
    rubric = _load_rubric()
    prompt = (
        "You are a hostile USPTO patent examiner + competitor attorney.\n"
        "Score the following candidate claim revision on 5 dimensions (0-20 each, 100 total).\n\n"
        f"RUBRIC:\n{rubric}\n\n"
        f"PATENT CONTEXT (for reference, not to be scored):\n{context_patent_text[:8000]}\n\n"
        f"PRIOR ART DATABASE:\n{json.dumps(context_priorart, indent=2)[:4000]}\n\n"
        f"CANDIDATE:\n{json.dumps(candidate, indent=2)}\n\n"
        "Return ONLY a JSON object (no markdown fences) of the form:\n"
        '{\n'
        '  "alice_101":       {"points": N, "evidence": "...", "critique": "..."},\n'
        '  "obviousness_103": {"points": N, "evidence": "...", "critique": "..."},\n'
        '  "support_112":     {"points": N, "evidence": "...", "critique": "..."},\n'
        '  "design_around":   {"points": N, "evidence": "...", "critique": "..."},\n'
        '  "scope":           {"points": N, "evidence": "...", "critique": "..."}\n'
        "}\n"
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    dims = _parse_judge_response(raw)
    score = CandidateScore(candidate_id=candidate["id"], dimensions=dims)
    score.finalize()
    return score
