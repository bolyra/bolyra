"""Tier 2: For each selected attack, generate K candidate claim rewrites.

Runs one CLI call per attack (parallel across attacks). Each call returns K
candidate rewrites with different strategies (narrow, positive_structural,
dependent_claim, genus_with_species, delete_problem_language).

Task 6 covers candidate generation only. Task 7 will add scoring + winner
selection. Task 8 adds mutation application.
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array
from scoring import score_candidate


DEFAULT_K: int = 3

# Minimum total score to be eligible as a winner. Matches scoring.py's
# "consider" threshold — we promote even moderate wins, but never the "reject"
# range (<60 or any dim <= 4).
MIN_WINNER_TOTAL: int = 60

CANDIDATE_PROMPT = """You are a senior patent attorney drafting revised claim language.
A hostile reviewer has identified the following weakness in the patent:

ATTACK:
{attack_json}

PATENT CONTEXT:
{patent_text}

Your task: produce {k} DIFFERENT candidate revisions that address this weakness.
Each candidate must be a SPECIFIC replacement for the identified claim language,
not a philosophical direction. Be concrete. Different candidates should represent
DIFFERENT strategies (e.g., one narrows, one adds a dependent, one rewrites the
limitation as positive structure).

Return ONLY a JSON array (no markdown fences) with {k} objects:
[
  {{
    "id": "cand_{attack_id}_01",
    "strategy": "narrow" | "positive_structural" | "dependent_claim" | "genus_with_species" | "delete_problem_language",
    "claim_refs": [<claim numbers>],
    "original_language": "exact text being replaced",
    "claim_text": "exact replacement text",
    "rationale": "why this fixes the weakness, 2-4 sentences",
    "targets_weakness": "{attack_id}",
    "tradeoffs": "what it loses in scope or risk in exchange"
  }}
]
"""


def _build_prompt(attack: dict, patent_text: str, k: int) -> str:
    return CANDIDATE_PROMPT.format(
        attack_json=json.dumps(attack, indent=2),
        patent_text=patent_text[:20000],
        k=k,
        attack_id=attack["id"],
    )


def generate_candidates_for_attack(
    attack: dict,
    patent_text: str,
    k: int = DEFAULT_K,
    *,
    model: str = "opus",
    timeout: int = 360,
) -> list[dict]:
    """Dispatch one CLI call for `attack`, return K candidate dicts.

    On parse failure, returns a single error-stub candidate so callers can see
    which attack failed candidate generation without the whole batch dying.
    """
    prompt = _build_prompt(attack, patent_text, k)
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    try:
        candidates = extract_json_array(raw)
    except ValueError as e:
        return [
            {
                "id": f"cand_{attack['id']}_parse_error",
                "strategy": "error",
                "claim_refs": attack.get("claim_refs", []),
                "original_language": "",
                "claim_text": "",
                "rationale": f"Failed to parse LLM response: {e}",
                "targets_weakness": attack["id"],
                "tradeoffs": "",
            }
        ]
    # Backfill targets_weakness if the LLM omitted it
    for c in candidates:
        c.setdefault("targets_weakness", attack["id"])
    return candidates


def generate_candidates_for_run(
    selected_attacks: list[dict],
    patent_text: str,
    output_dir: Path,
    k: int = DEFAULT_K,
    *,
    model: str = "opus",
    timeout: int = 360,
    max_workers: int = 4,
) -> list[dict]:
    """Dispatch candidate generation across all selected attacks in parallel.

    Each attack produces K candidates (or a single error stub on failure).
    All candidates are collected and written to tier2_candidates.json.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if not selected_attacks:
        (output_dir / "tier2_candidates.json").write_text(json.dumps([], indent=2))
        return []

    all_candidates: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                generate_candidates_for_attack, a, patent_text, k,
                model=model, timeout=timeout,
            ): a
            for a in selected_attacks
        }
        for fut in as_completed(futures):
            attack = futures[fut]
            try:
                cands = fut.result()
                all_candidates.extend(cands)
            except Exception as e:
                all_candidates.append(
                    {
                        "id": f"cand_{attack['id']}_exception",
                        "strategy": "error",
                        "claim_refs": attack.get("claim_refs", []),
                        "original_language": "",
                        "claim_text": "",
                        "rationale": f"Candidate generation failed: {type(e).__name__}: {e}",
                        "targets_weakness": attack["id"],
                        "tradeoffs": "",
                    }
                )

    (output_dir / "tier2_candidates.json").write_text(json.dumps(all_candidates, indent=2))
    return all_candidates


def score_and_pick_winners(
    candidates: list[dict],
    patent_text: str,
    prior_art: list[dict],
    output_dir: Path,
) -> list[dict]:
    """Score all candidates on 5 dims, write tier2_scored.json, pick winner per weakness.

    Scoring:
      - Error-stub candidates (strategy == "error") are skipped but included
        in tier2_scored.json with zero score for visibility
      - Scoring exceptions caught → zero-score entry with 'error' field
    Winner selection:
      - Group by targets_weakness
      - Pick highest-scoring candidate per weakness
      - Only candidates with total >= MIN_WINNER_TOTAL (60) are eligible
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    scored: list[dict] = []
    for c in candidates:
        if c.get("strategy") == "error":
            # Don't score error stubs. Include them with zero for visibility.
            scored.append({
                **c,
                "score": {
                    "total": 0,
                    "verdict": "reject",
                    "dimensions": {},
                    "note": "skipped — error stub from candidate generation",
                },
            })
            continue
        try:
            cs = score_candidate(c, patent_text, prior_art)
            entry = {
                **c,
                "score": {
                    "total": cs.total,
                    "verdict": cs.verdict,
                    "dimensions": {
                        k: asdict(v) for k, v in cs.dimensions.items()
                    },
                },
            }
            scored.append(entry)
        except Exception as e:
            scored.append({
                **c,
                "score": {
                    "total": 0,
                    "verdict": "reject",
                    "dimensions": {},
                    "error": f"{type(e).__name__}: {e}",
                },
            })

    (output_dir / "tier2_scored.json").write_text(json.dumps(scored, indent=2, default=str))

    # Group by targets_weakness, pick highest-scoring per weakness >= threshold
    by_weakness: dict[str, list[dict]] = {}
    for s in scored:
        weakness = s.get("targets_weakness", "unknown")
        by_weakness.setdefault(weakness, []).append(s)

    winners: list[dict] = []
    for weakness, cands in by_weakness.items():
        cands_sorted = sorted(cands, key=lambda x: x["score"].get("total", 0), reverse=True)
        best = cands_sorted[0]
        if best["score"].get("total", 0) >= MIN_WINNER_TOTAL:
            winners.append(best)

    (output_dir / "tier2_winners.json").write_text(json.dumps(winners, indent=2, default=str))
    return winners


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 2: candidate claim generation")
    ap.add_argument("--selected", required=True, help="Path to tier1_selected.json")
    ap.add_argument("--patent", required=True, help="Path to current patent .md")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--k", type=int, default=DEFAULT_K, help="Candidates per attack")
    ap.add_argument("--model", default="opus")
    ap.add_argument("--timeout", type=int, default=360)
    ap.add_argument("--score", action="store_true", help="Also score candidates and pick winners")
    ap.add_argument("--prior-art", default=None, help="Path to prior_art.json (for scoring)")
    args = ap.parse_args()

    selected = json.loads(Path(args.selected).read_text())
    patent_text = Path(args.patent).read_text()
    output_dir = Path(args.output_dir)

    candidates = generate_candidates_for_run(
        selected, patent_text, output_dir, args.k,
        model=args.model, timeout=args.timeout,
    )
    print(f"Generated {len(candidates)} candidates → {output_dir / 'tier2_candidates.json'}")

    # If --score flag passed, also score candidates and pick winners
    if args.score:
        prior_art_path = Path(args.prior_art) if args.prior_art else None
        if prior_art_path and prior_art_path.exists():
            prior_art = json.loads(prior_art_path.read_text())
        else:
            prior_art = []
        winners = score_and_pick_winners(candidates, patent_text, prior_art, output_dir)
        print(f"Picked {len(winners)} winners → {output_dir / 'tier2_winners.json'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
