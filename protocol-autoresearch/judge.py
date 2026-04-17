"""Tier 1 candidate scorer for protocol improvements.

Scores candidates on 4 dimensions (adoption, standards, completeness, correctness)
using Claude CLI as judge. Batches candidates (6 per batch) to avoid output truncation.

Uses Claude MAX login via `claude` CLI, never API keys or SDK.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array


DIMENSIONS: list[str] = ["adoption", "standards", "completeness", "correctness"]
MAX_PER_DIMENSION: int = 25
MAX_TOTAL: int = MAX_PER_DIMENSION * len(DIMENSIONS)  # 100

# Verdict thresholds (per program.md §4)
PROMOTE_TOTAL_MIN: int = 75
PROMOTE_ALL_DIMS_MIN: int = 15
CONSIDER_TOTAL_MIN: int = 60
CONSIDER_TOTAL_MAX: int = 74
DROP_IF_ANY_DIM_LE: int = 8

DEFAULT_BATCH_SIZE: int = 6


@dataclass
class CandidateScore:
    candidate_id: str
    adoption: int = 0
    standards: int = 0
    completeness: int = 0
    correctness: int = 0
    total: int = 0
    verdict: str = "drop"

    def finalize(self) -> None:
        """Compute total and verdict from dimension scores."""
        self.total = self.adoption + self.standards + self.completeness + self.correctness
        dims = [self.adoption, self.standards, self.completeness, self.correctness]
        any_too_low = any(d <= DROP_IF_ANY_DIM_LE for d in dims)
        all_above_promote = all(d >= PROMOTE_ALL_DIMS_MIN for d in dims)

        if any_too_low or self.total < CONSIDER_TOTAL_MIN:
            self.verdict = "drop"
        elif self.total >= PROMOTE_TOTAL_MIN and all_above_promote:
            self.verdict = "promote"
        elif self.total >= CONSIDER_TOTAL_MIN:
            self.verdict = "consider"
        else:
            self.verdict = "drop"


_RUBRIC_CACHE: str | None = None


def _load_rubric() -> str:
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        rubric_path = Path(__file__).parent / "rubrics" / "tier1_rubric.md"
        _RUBRIC_CACHE = rubric_path.read_text()
    return _RUBRIC_CACHE


def _parse_judge_response(raw: str) -> list[CandidateScore]:
    """Parse a Claude judge response into CandidateScore entries.

    Validates:
      - each entry has id + all 4 dimension scores
      - all dimension scores in [0, MAX_PER_DIMENSION]
    """
    data = extract_json_array(raw)
    scores: list[CandidateScore] = []
    for entry in data:
        if "id" not in entry:
            raise ValueError(f"candidate entry missing 'id' field: {entry}")
        cid = entry["id"]
        for dim in DIMENSIONS:
            if dim not in entry:
                raise ValueError(f"candidate {cid} missing '{dim}' field")
            value = int(entry[dim])
            if not (0 <= value <= MAX_PER_DIMENSION):
                raise ValueError(
                    f"candidate {cid} {dim}={value} out of range [0, {MAX_PER_DIMENSION}]"
                )
        score = CandidateScore(
            candidate_id=cid,
            adoption=int(entry["adoption"]),
            standards=int(entry["standards"]),
            completeness=int(entry["completeness"]),
            correctness=int(entry["correctness"]),
        )
        score.finalize()
        scores.append(score)
    return scores


def _score_batch(
    candidates: list[dict[str, Any]],
    rubric: str,
    *,
    model: str,
    timeout: int,
) -> list[CandidateScore]:
    """Score a single batch of candidates. Raises RuntimeError on count mismatch."""
    prompt = (
        "You are a protocol review panel scoring improvement candidates for the Bolyra "
        "identity protocol. Rate each candidate on four 0-25 dimensions.\n\n"
        f"RUBRIC:\n{rubric}\n\n"
        f"CANDIDATES:\n{json.dumps(candidates, indent=2)[:15000]}\n\n"
        "Return ONLY a JSON array (no markdown fences), one object per candidate:\n"
        '[{"id": "...", "adoption": N, "standards": N, "completeness": N, "correctness": N}, ...]\n'
        "Each N must be an integer in [0, 25]. Include EVERY candidate from the input above "
        f"({len(candidates)} total). Do not truncate or skip any."
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    scores = _parse_judge_response(raw)
    if len(scores) != len(candidates):
        raise RuntimeError(
            f"judge returned {len(scores)} scores for {len(candidates)} candidates in this batch; "
            f"input ids: {[c.get('id') for c in candidates]}; "
            f"returned ids: {[s.candidate_id for s in scores]}"
        )
    return scores


def score_candidates(
    candidates: list[dict[str, Any]],
    *,
    model: str = "sonnet",
    timeout: int = 240,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> list[CandidateScore]:
    """Score protocol improvement candidates on 4 dimensions.

    Processes candidates in batches of `batch_size` (default 6) to stay within
    the judge model's output token budget.

    Args:
        candidates: list of candidate dicts with at least {id, title, description, dimension}
        model: Claude model for the judge (default sonnet)
        timeout: Claude CLI timeout per batch in seconds
        batch_size: max candidates per judge call

    Returns:
        list[CandidateScore] with one entry per input candidate.
    """
    if not candidates:
        return []
    rubric = _load_rubric()
    all_scores: list[CandidateScore] = []
    for start in range(0, len(candidates), batch_size):
        batch = candidates[start : start + batch_size]
        batch_scores = _score_batch(
            batch, rubric, model=model, timeout=timeout,
        )
        all_scores.extend(batch_scores)
    if len(all_scores) != len(candidates):
        raise RuntimeError(
            f"judge returned {len(all_scores)} scores across batches for {len(candidates)} "
            f"total candidates. Input ids: {[c.get('id') for c in candidates]}; "
            f"returned ids: {[s.candidate_id for s in all_scores]}"
        )
    return all_scores
