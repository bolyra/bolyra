"""Plateau detection for the Discovery AutoResearch Loop.

Adapted from protocol-autoresearch/history/plateau_detector.py for discovery context.

Stop conditions (any one triggers):
  - max_iters reached (default 10)
  - plateau: 3 consecutive iterations produce no new opportunities scoring > 60
  - no new opportunities at all for 3 consecutive iterations

Uses opportunity_trajectory.jsonl which tracks per-iteration opportunity counts
and max scores.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAJECTORY_PATH = HERE / "opportunity_trajectory.jsonl"


def load_trajectory(path: Path | None = None) -> list[dict]:
    """Load opportunity trajectory from JSONL file."""
    p = path or TRAJECTORY_PATH
    if not p.exists():
        return []
    return [
        json.loads(line)
        for line in p.read_text().splitlines()
        if line.strip()
    ]


def should_stop(
    trajectory: list[dict],
    *,
    max_iters: int = 10,
    plateau_window: int = 3,
    min_score_threshold: float = 60.0,
) -> tuple[bool, str]:
    """Determine whether the discovery loop should stop.

    Args:
        trajectory: List of iteration records, each containing at minimum:
            - iter: iteration number
            - new_opportunities: count of new opportunities this iteration
            - max_score: highest opportunity score this iteration
            - approved_count: number of APPROVED/CONDITIONAL cards
        max_iters: Maximum iterations before forced stop.
        plateau_window: Number of consecutive dry iterations to trigger plateau.
        min_score_threshold: Minimum score to count as a "good" opportunity.

    Returns:
        (should_stop, reason) tuple.
    """
    if not trajectory:
        return False, "no iterations run yet"

    # Count completed iterations (exclude iter 0 baseline if present)
    iter_count = max(0, len(trajectory) - 1) if trajectory[0].get("iter", 1) == 0 else len(trajectory)
    if iter_count >= max_iters:
        return True, f"max iterations {max_iters} reached (completed {iter_count})"

    if len(trajectory) < plateau_window:
        return False, f"need {plateau_window} iterations for plateau check (have {len(trajectory)})"

    # Check for plateau: no new high-scoring opportunities
    recent = trajectory[-plateau_window:]
    high_scoring_counts = [
        entry.get("high_scoring_count", 0) for entry in recent
    ]
    if all(c == 0 for c in high_scoring_counts):
        return True, (
            f"plateau: last {plateau_window} iterations produced no opportunities "
            f"scoring > {min_score_threshold} (counts={high_scoring_counts})"
        )

    # Check for total drought: no new opportunities at all
    new_opp_counts = [entry.get("new_opportunities", 0) for entry in recent]
    if all(c == 0 for c in new_opp_counts):
        return True, (
            f"drought: last {plateau_window} iterations produced no new opportunities "
            f"at all (counts={new_opp_counts})"
        )

    return False, (
        f"still discovering (recent high-scoring={high_scoring_counts}, "
        f"new_opps={new_opp_counts})"
    )


def record_iteration(
    *,
    iter_num: int,
    ts: str,
    new_opportunities: int,
    max_score: float,
    approved_count: int,
    conditional_count: int,
    rejected_count: int,
    high_scoring_count: int,
    board_size: int,
    path: Path | None = None,
) -> dict:
    """Append an iteration record to the trajectory file.

    Returns the recorded entry.
    """
    p = path or TRAJECTORY_PATH
    p.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "iter": iter_num,
        "ts": ts,
        "new_opportunities": new_opportunities,
        "max_score": max_score,
        "approved_count": approved_count,
        "conditional_count": conditional_count,
        "rejected_count": rejected_count,
        "high_scoring_count": high_scoring_count,
        "board_size": board_size,
    }

    with p.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    return entry


if __name__ == "__main__":
    import sys

    traj = load_trajectory()
    if not traj:
        print("No trajectory data found.")
        sys.exit(0)

    stop, reason = should_stop(traj)
    print(f"Iterations: {len(traj)}")
    print(f"Should stop: {stop}")
    print(f"Reason: {reason}")
    if traj:
        latest = traj[-1]
        print(f"Latest: iter={latest.get('iter')}, max_score={latest.get('max_score')}, "
              f"approved={latest.get('approved_count')}")
    sys.exit(0)
