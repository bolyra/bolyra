"""Plateau detector for the differentiation loop.

Wraps the sibling patent-autoresearch plateau detector with differentiation-specific
defaults (target_score=10.0, plateau_delta=0.5 since scores are small integers).
"""
from __future__ import annotations

import importlib.util as _ilu
from pathlib import Path as _Path

_SIBLING = _Path(__file__).resolve().parent.parent / "patent-autoresearch" / "history" / "plateau_detector.py"
_spec = _ilu.spec_from_file_location("_patent_plateau_detector", _SIBLING)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_base_should_stop = _mod.should_stop


def should_stop(
    trajectory: list[dict],
    *,
    max_iters: int = 10,
    plateau_window: int = 3,
) -> tuple[bool, str]:
    """Return (should_stop, reason) for a single-candidate trajectory.

    Trajectory entries: {"iter": N, "total": strength, "ts": "..."}.
    Stop if target (10) reached, max_iters reached, or last 3 iterations had no improvement.
    """
    return _base_should_stop(
        trajectory,
        max_iters=max_iters,
        plateau_window=plateau_window,
        plateau_delta=0.5,  # integer scores — no-improvement means delta = 0
        target_score=10.0,
    )
