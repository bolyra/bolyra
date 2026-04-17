"""Apply winning candidate claim mutations to the patent draft.

STRICT: uses exact-string replacement. If `original_language` is not found
verbatim in the patent, we raise ValueError rather than silently apply a
misaligned edit. A skipped mutation can always be retried next iteration;
a wrong mutation propagates silently into future adversarial rounds.

Mutations are sequential — each winner sees the state from applying prior
winners in the list. Callers should order winners sensibly (e.g. by claim
number) if they touch overlapping regions.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MutationResult:
    """Result of applying a batch of winners."""
    applied: list[str] = field(default_factory=list)       # winner IDs successfully applied
    skipped: list[dict[str, str]] = field(default_factory=list)  # [{"id": ..., "reason": ...}]


def apply_mutation(patent_text: str, winner: dict[str, Any]) -> str:
    """Apply a single winner mutation to `patent_text` and return the new text.

    Raises:
        ValueError: if `winner["original_language"]` is not present verbatim
            in `patent_text`, OR if `winner["claim_text"]` looks like LLM
            meta-instructions rather than literal replacement prose. The
            instruction-guard prevents M2-style self-inflicted wounds where
            the LLM writes "REPLACE step (d) with..." and the mutator blindly
            pastes that instruction text into the patent.
    """
    # Import here to avoid circular deps at module load time.
    from run_tier2_claim import looks_like_instruction

    original = winner["original_language"]
    replacement = winner["claim_text"]
    weakness = winner.get("targets_weakness", "?")

    if looks_like_instruction(replacement):
        preview = replacement[:120].replace("\n", "\\n")
        raise ValueError(
            f"claim_text looks like LLM meta-instructions rather than literal "
            f"replacement prose for winner targeting {weakness}: {preview!r}. "
            f"Regenerate this candidate — instruction markers detected."
        )
    if looks_like_instruction(original):
        preview = original[:120].replace("\n", "\\n")
        raise ValueError(
            f"original_language looks like LLM meta-instructions rather than "
            f"a literal patent substring for winner targeting {weakness}: {preview!r}."
        )
    if original not in patent_text:
        preview = original[:120].replace("\n", "\\n")
        raise ValueError(
            f"original_language not found in patent for winner targeting "
            f"{weakness}: {preview!r}"
        )
    # Only replace first occurrence — avoids cascading replaces if the literal
    # happens to appear in multiple places (e.g. repeated claim structure).
    return patent_text.replace(original, replacement, 1)


def apply_winners(
    patent_path: Path,
    winners: list[dict[str, Any]],
    output_path: Path,
) -> MutationResult:
    """Apply all winner mutations to the patent at `patent_path`, writing to `output_path`.

    The source patent file at `patent_path` is NOT modified — all output is
    written to `output_path`. A caller-level human review gate should diff
    the two before promoting `output_path` to the live patent.

    Mutations are applied sequentially. If a mutation fails (original_language
    not found), it is recorded in `result.skipped` and subsequent winners
    still attempt to apply. This avoids one bad mutation blocking N good ones.

    Returns:
        MutationResult with `applied` (IDs that succeeded) and `skipped`
        (dicts with `id` and `reason` for each failure).
    """
    patent_text = patent_path.read_text()
    applied: list[str] = []
    skipped: list[dict[str, str]] = []

    for w in winners:
        winner_id = w.get("id", "unknown")
        try:
            patent_text = apply_mutation(patent_text, w)
            applied.append(winner_id)
        except ValueError as e:
            skipped.append({"id": winner_id, "reason": str(e)})

    output_path.write_text(patent_text)
    return MutationResult(applied=applied, skipped=skipped)
