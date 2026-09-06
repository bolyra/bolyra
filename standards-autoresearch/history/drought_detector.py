"""Drought exit: 3 consecutive iterations with zero new board cards AND zero
Tier-3 approvals. Scan-only iterations count toward drought — a loop that
only scans is a zombie-week generator (pr-outreach lesson).

No target score: the loop is open-ended (discovery-family convention).
"""
from __future__ import annotations

DROUGHT_WINDOW = 3


def should_stop(trajectory: list[dict], *, max_iters: int | None = None) -> tuple[bool, str]:
    if max_iters is not None and trajectory:
        last_iter = trajectory[-1].get("iter", 0)
        if last_iter >= max_iters:
            return True, f"max iterations reached ({max_iters})"

    recent = [t for t in trajectory if t.get("iter", 0) > 0][-DROUGHT_WINDOW:]
    if len(recent) >= DROUGHT_WINDOW:
        dry = all((t.get("new_cards", 0) == 0 and t.get("staged", 0) == 0)
                  for t in recent)
        if dry:
            return True, (f"drought: {DROUGHT_WINDOW} consecutive iterations with "
                          "no new cards and no staged artifacts")
    return False, ""
