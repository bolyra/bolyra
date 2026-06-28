"""Tier 1 judge: LLM-as-judge scorer for theseus integration candidates.

Batches candidates (6 per call), scores on 4 theseus-specific dimensions
(agent_need, zkp_edge, primitive_readiness, partnership_leverage) using the
discovery rubric, and applies promotion logic.

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
from scoring import IntegrationScore, score_integration

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
RUBRIC_PATH = HERE / "rubrics" / "tier1_discovery_rubric.md"

DEFAULT_BATCH_SIZE: int = 6
DIMENSIONS: list[str] = ["agent_need", "zkp_edge", "primitive_readiness", "partnership_leverage"]
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


def _parse_judge_response(raw: str) -> list[IntegrationScore]:
    """Parse a Claude judge response into IntegrationScore entries.

    Validates that each entry has an id and all 4 dimension scores in [0, 25].
    """
    data = extract_json_array(raw)
    scores: list[IntegrationScore] = []
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

        score = score_integration(
            agent_need=int(entry["agent_need"]),
            zkp_edge=int(entry["zkp_edge"]),
            primitive_readiness=int(entry["primitive_readiness"]),
            partnership_leverage=int(entry["partnership_leverage"]),
        )

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
) -> list[IntegrationScore]:
    """Score a single batch of candidates. Raises RuntimeError on count mismatch."""
    prompt = (
        "You are a partnership review panel scoring integration opportunities between "
        "Bolyra (ZKP identity protocol) and Theseus (agent-native L1 chain). "
        "Rate each candidate on four 0-25 dimensions.\n\n"
        f"RUBRIC:\n{rubric}\n\n"
        f"CANDIDATES:\n{json.dumps(candidates, indent=2)[:15000]}\n\n"
        "Return ONLY a JSON array (no markdown fences), one object per candidate:\n"
        '[{"id": "...", "agent_need": N, "zkp_edge": N, "primitive_readiness": N, '
        '"partnership_leverage": N}, ...]\n'
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
) -> list[IntegrationScore]:
    """Score theseus integration candidates on 4 dimensions.

    Processes candidates in batches of `batch_size` (default 6).

    Args:
        candidates: list of candidate dicts with at least {id, title, description}
        model: Claude model for the judge (default sonnet)
        timeout: Claude CLI timeout per batch in seconds
        batch_size: max candidates per judge call

    Returns:
        list[IntegrationScore] with one entry per input candidate.
    """
    if not candidates:
        return []
    rubric = _load_rubric()
    all_scores: list[IntegrationScore] = []

    for start in range(0, len(candidates), batch_size):
        batch = candidates[start : start + batch_size]
        batch_num = (start // batch_size) + 1
        total_batches = (len(candidates) + batch_size - 1) // batch_size
        logger.info("Scoring batch %d/%d (%d candidates)...", batch_num, total_batches, len(batch))

        try:
            batch_scores = _score_batch(batch, rubric, model=model, timeout=timeout)
            all_scores.extend(batch_scores)
        except (RuntimeError, ValueError) as e:
            logger.error("Batch %d failed: %s -- assigning zero scores", batch_num, e)
            for c in batch:
                zero = IntegrationScore(
                    agent_need=0, zkp_edge=0, primitive_readiness=0,
                    partnership_leverage=0, total=0, verdict="DROP",
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
    score_by_id: dict[str, IntegrationScore] = {}
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
                "scores": {
                    "agent_need": s.agent_need,
                    "zkp_edge": s.zkp_edge,
                    "primitive_readiness": s.primitive_readiness,
                    "partnership_leverage": s.partnership_leverage,
                    "total": s.total,
                },
                "verdict": s.verdict,
            })
        else:
            # Meta stub or unscored
            scored.append({
                **c,
                "scores": {
                    "agent_need": 0,
                    "zkp_edge": 0,
                    "primitive_readiness": 0,
                    "partnership_leverage": 0,
                    "total": 0,
                },
                "verdict": "DROP",
            })

    # Promotion: total >= promote_min and verdict is PROMOTE or CONSIDER
    promoted = [
        s for s in scored
        if s.get("scores", {}).get("total", 0) >= promote_min
        and s.get("verdict") in ("PROMOTE", "CONSIDER")
    ]
    promoted.sort(key=lambda x: x.get("scores", {}).get("total", 0), reverse=True)

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
        description="Tier 1 judge: score and promote theseus integration opportunities"
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
