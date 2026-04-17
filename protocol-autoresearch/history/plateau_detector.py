"""Detect when the protocol-autoresearch loop should stop.

Stop conditions (any one triggers):
  - target_score reached (default 84.0 = all dims >= 21)
  - max_iters reached (default 10)
  - plateau: last N deltas all < plateau_delta (default N=3, delta=3.0)

The plateau check requires at least plateau_window + 1 iterations to compute
N pairwise deltas, so the loop will always run at least plateau_window + 1
iterations before plateau can trigger.

Wider tolerance (3.0 vs 2.0 in patent loop) because protocol improvements
are chunkier than claim edits.
"""
from __future__ import annotations


def should_stop(
    trajectory: list[dict],
    *,
    max_iters: int = 10,
    plateau_window: int = 3,
    plateau_delta: float = 3.0,
    target_score: float = 84.0,
) -> tuple[bool, str]:
    """Return (should_stop, reason)."""
    if not trajectory:
        return False, "no iterations run yet"
    latest = trajectory[-1]["total"]
    if latest >= target_score:
        return True, f"target score {target_score} reached (latest={latest})"
    # trajectory contains the iter-0 baseline + one entry per completed iteration.
    iter_count = max(0, len(trajectory) - 1)
    if iter_count >= max_iters:
        return True, f"max iterations {max_iters} reached (completed {iter_count})"
    if len(trajectory) < plateau_window + 1:
        return False, f"need {plateau_window + 1} iterations for plateau check (have {len(trajectory)})"
    window = [t["total"] for t in trajectory[-(plateau_window + 1):]]
    deltas = [abs(window[i + 1] - window[i]) for i in range(plateau_window)]
    if max(deltas) < plateau_delta:
        return True, f"plateau: last {plateau_window} deltas all < {plateau_delta} (deltas={deltas})"
    return False, f"still improving (recent deltas={deltas})"
