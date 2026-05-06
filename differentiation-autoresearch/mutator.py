"""Mutator — apply targeted fixes to a construction given judge-identified gaps.

Mutation strategy: re-invoke Tier 2 with the prior construction + explicit gap list.
This is equivalent to "refine" rather than "regenerate" — Tier 2 already supports
a refinement mode via its `prior_construction` + `gaps` parameters.

Kept as a thin shim so the orchestrator's flow is clear:
  tier1 -> tier2 -> tier3 -> judge -> mutator (-> tier3 -> judge ...) until strength=10.
"""
from __future__ import annotations

from pathlib import Path

import tier2_construct


def run(
    candidate: dict,
    out_dir: Path,
    *,
    gaps: list[str],
    model: str = "opus",
    timeout: int = 1200,
) -> Path:
    """Refine construction.md in place using judge gaps."""
    prior = out_dir / "construction.md"
    if not prior.exists():
        raise RuntimeError(f"construction.md missing in {out_dir}")
    return tier2_construct.run(
        candidate,
        out_dir,
        prior_construction=prior,
        gaps=gaps,
        model=model,
        timeout=timeout,
    )
