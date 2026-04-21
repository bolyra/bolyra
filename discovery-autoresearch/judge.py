"""Tier 1 discovery judge: LLM-as-judge scorer for opportunity candidates.

Batches candidates (6 per call), scores on 4 dimensions (demand, timing, fit,
feasibility) using the discovery rubric, and applies promotion logic.

Uses Claude MAX login via `claude` CLI, never API keys or SDK.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array
from scoring import OpportunityScore

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
RUBRIC_PATH = HERE / "rubrics" / "tier1_discovery_rubric.md"

DEFAULT_BATCH_SIZE: int = 6
DIMENSIONS: list[str] = ["demand", "timing", "fit", "feasibility"]
MAX_PER_DIMENSION: int = 25

# Promotion thresholds (aligned with rubric)
PROMOTE_TOTAL_MIN: int = 50


_RUBRIC_CACHE: str | None = None


def _load_rubric() -> str:
    """Load the tier1 discovery rubric markdown."""
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        _RUBRIC_CACHE = RUBRIC_PATH.read_text()
    return _RUBRIC_CACHE


def _parse_judge_response(raw: str) -> list[OpportunityScore]:
    """Parse a Claude judge response into OpportunityScore entries.

    Validates that each entry has an id and all 4 dimension scores in [0, 25].
    """
    data = extract_json_array(raw)
    scores: list[OpportunityScore] = []
    for entry in data:
        if "id" not in entry:
            raise ValueError(f"Judge entry missing 'id' field: {entry}")
        cid = entry["id"]

        for dim in DIMENSIONS:
            if dim not in entry:
                raise ValueError(f"Candidate {cid} missing '{dim}' field")
            value = int(entry[dim])
            if not (0 <= value <= MAX_PER_DIMENSION):
                raise ValueError(
                    f"Candidate {cid} {dim}={value} out of range [0, {MAX_PER_DIMENSION}]"
                )

        score = OpportunityScore(
            demand=int(entry["demand"]),
            timing=int(entry["timing"]),
            fit=int(entry["fit"]),
            feasibility=int(entry["feasibility"]),
            total=0,
            verdict="",
            ead_classification=entry.get("ead_classification", "BUILD_NOW"),
        )
        # Compute total and verdict via the scoring module
        total = score.demand + score.timing + score.fit + score.feasibility
        dims = [score.demand, score.timing, score.fit, score.feasibility]
        if total < 50 or any(d <= 5 for d in dims):
            verdict = "DROP"
        elif total >= 70 and all(d >= 12 for d in dims):
            verdict = "PROMOTE"
        else:
            verdict = "CONSIDER"
        score.total = total
        score.verdict = verdict

        # Attach candidate_id for merge lookup
        score.candidate_id = cid  # type: ignore[attr-defined]
        scores.append(score)
    return scores


def _score_batch(
    candidates: list[dict[str, Any]],
    rubric: str,
    *,
    model: str,
    timeout: int,
) -> list[OpportunityScore]:
    """Score a single batch of candidates. Raises RuntimeError on count mismatch."""
    prompt = (
        "You are a market discovery review panel scoring opportunity candidates for the "
        "Bolyra identity protocol. Rate each candidate on four 0-25 dimensions.\n\n"
        f"RUBRIC:\n{rubric}\n\n"
        f"CANDIDATES:\n{json.dumps(candidates, indent=2)[:15000]}\n\n"
        "Return ONLY a JSON array (no markdown fences), one object per candidate:\n"
        '[{"id": "...", "demand": N, "timing": N, "fit": N, "feasibility": N}, ...]\n'
        "Each N must be an integer in [0, 25]. Include EVERY candidate from the input above "
        f"({len(candidates)} total). Do not truncate or skip any."
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
    except RuntimeError as e:
        logger.error("Judge CLI call failed for batch: %s", e)
        raise

    scores = _parse_judge_response(raw)
    if len(scores) != len(candidates):
        raise RuntimeError(
            f"Judge returned {len(scores)} scores for {len(candidates)} candidates; "
            f"input ids: {[c.get('id') for c in candidates]}; "
            f"returned ids: {[s.candidate_id for s in scores]}"  # type: ignore[attr-defined]
        )
    return scores


def score_candidates(
    candidates: list[dict[str, Any]],
    *,
    model: str = "sonnet",
    timeout: int = 240,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> list[OpportunityScore]:
    """Score discovery opportunity candidates on 4 dimensions.

    Processes candidates in batches of `batch_size` (default 6).

    Args:
        candidates: list of candidate dicts with at least {id, title, description}
        model: Claude model for the judge (default sonnet)
        timeout: Claude CLI timeout per batch in seconds
        batch_size: max candidates per judge call

    Returns:
        list[OpportunityScore] with one entry per input candidate.
    """
    if not candidates:
        return []
    rubric = _load_rubric()
    all_scores: list[OpportunityScore] = []

    for start in range(0, len(candidates), batch_size):
        batch = candidates[start : start + batch_size]
        batch_num = (start // batch_size) + 1
        total_batches = (len(candidates) + batch_size - 1) // batch_size
        logger.info("Scoring batch %d/%d (%d candidates)...", batch_num, total_batches, len(batch))

        try:
            batch_scores = _score_batch(batch, rubric, model=model, timeout=timeout)
            all_scores.extend(batch_scores)
        except (RuntimeError, ValueError) as e:
            logger.error("Batch %d failed: %s — assigning zero scores", batch_num, e)
            for c in batch:
                zero = OpportunityScore(
                    demand=0, timing=0, fit=0, feasibility=0,
                    total=0, verdict="DROP", ead_classification="BUILD_NOW",
                )
                zero.candidate_id = c.get("id", "unknown")  # type: ignore[attr-defined]
                all_scores.append(zero)

    return all_scores


def judge_tier1(
    output_dir: Path,
    *,
    model: str = "sonnet",
    timeout: int = 240,
    batch_size: int = DEFAULT_BATCH_SIZE,
    promote_min: int = PROMOTE_TOTAL_MIN,
) -> dict[str, Any]:
    """Run the full judge pipeline on tier1_opportunities.json.

    Reads:
      - tier1_opportunities.json (from run_tier1_discover)

    Writes:
      - tier1_scored.json (all candidates with scores merged)
      - tier1_promoted.json (candidates with total >= promote_min)

    Returns:
        Dict with scored and promoted lists.
    """
    opportunities_path = output_dir / "tier1_opportunities.json"
    if not opportunities_path.exists():
        raise FileNotFoundError(f"No tier1_opportunities.json in {output_dir}")

    candidates = json.loads(opportunities_path.read_text())

    # Filter out meta/error stubs
    scorable = [c for c in candidates if c.get("category") != "meta"]
    logger.info(
        "Scoring %d candidates (%d meta stubs excluded)",
        len(scorable),
        len(candidates) - len(scorable),
    )

    # Score
    scores = score_candidates(scorable, model=model, timeout=timeout, batch_size=batch_size)
    score_by_id: dict[str, OpportunityScore] = {}
    for s in scores:
        cid = getattr(s, "candidate_id", None)
        if cid:
            score_by_id[cid] = s

    # Merge scores into candidate dicts
    scored: list[dict[str, Any]] = []
    for c in candidates:
        cid = c.get("id", "")
        s = score_by_id.get(cid)
        if s is not None:
            scored.append({
                **c,
                "demand": s.demand,
                "timing": s.timing,
                "fit": s.fit,
                "feasibility": s.feasibility,
                "total": s.total,
                "verdict": s.verdict,
                "ead_classification": s.ead_classification,
            })
        else:
            # Meta stub or unscored
            scored.append({
                **c,
                "demand": 0,
                "timing": 0,
                "fit": 0,
                "feasibility": 0,
                "total": 0,
                "verdict": "DROP",
                "ead_classification": "BUILD_NOW",
            })

    # Promotion: total >= promote_min and verdict is PROMOTE or CONSIDER
    promoted = [
        s for s in scored
        if s.get("total", 0) >= promote_min
        and s.get("verdict") in ("PROMOTE", "CONSIDER")
    ]
    promoted.sort(key=lambda x: x.get("total", 0), reverse=True)

    # Save
    (output_dir / "tier1_scored.json").write_text(json.dumps(scored, indent=2))
    (output_dir / "tier1_promoted.json").write_text(json.dumps(promoted, indent=2))

    logger.info(
        "Scored %d candidates: %d promoted, %d dropped",
        len(scored),
        len(promoted),
        len(scored) - len(promoted),
    )

    return {
        "scored": scored,
        "promoted": promoted,
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(
        description="Tier 1 discovery judge: score and promote opportunities"
    )
    ap.add_argument("--output-dir", required=True, help="Iteration output directory")
    ap.add_argument("--model", default="sonnet", help="Claude model for judge")
    ap.add_argument("--timeout", type=int, default=240, help="CLI timeout per batch (s)")
    ap.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Candidates per batch")
    ap.add_argument(
        "--promote-min", type=int, default=PROMOTE_TOTAL_MIN, help="Min total to promote"
    )
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    result = judge_tier1(
        output_dir,
        model=args.model,
        timeout=args.timeout,
        batch_size=args.batch_size,
        promote_min=args.promote_min,
    )
    print(f"Scored {len(result['scored'])} candidates, promoted {len(result['promoted'])}")
    print(f"Results in {output_dir / 'tier1_scored.json'} and {output_dir / 'tier1_promoted.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
