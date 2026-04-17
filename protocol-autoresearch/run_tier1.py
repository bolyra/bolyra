"""Tier 1: Dispatch 8 constructive explorer personas in parallel.

Each persona proposes protocol improvements (not attacks). The fanout runs in
a ThreadPoolExecutor so CLI calls happen concurrently.

Output: protocol-autoresearch/runs/<iter>/tier1_candidates.json (raw, unranked)
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
from judge import score_candidates, CandidateScore


MAX_SELECTED_WINNERS: int = 8

HERE = Path(__file__).resolve().parent
PERSONAS_PATH = HERE / "personas" / "exploration_personas.json"
SEED_CANDIDATES_PATH = HERE / "seed_candidates.json"

EXPLORE_PROMPT = """You are a protocol improvement explorer playing the role: {role}
Focus areas: {focus}

Your job: propose specific, actionable improvements to the Bolyra protocol.
Each proposal should be concrete enough for an engineer to implement in 1-3 days.

SEED CANDIDATES (for inspiration, not to limit your thinking):
{seed_candidates}

CURRENT CIRCUITS:
{circuit_context}

CURRENT CONTRACTS:
{contract_context}

Return ONLY a JSON array (no markdown fences), one object per proposal:
[
  {{
    "id": "{persona_id}_<short_slug>",
    "persona": "{persona_id}",
    "title": "short descriptive title",
    "dimension": "correctness" | "completeness" | "adoption" | "standards",
    "description": "2-4 sentences: what to build and why",
    "priority": "critical" | "high" | "medium",
    "estimated_effort": "hours" | "days" | "week"
  }}
]

Produce 3-5 proposals. Focus on your role's expertise. Be specific about artifacts.
"""


def _load_seed_data() -> tuple[list[dict], list[dict]]:
    """Load personas and seed candidates."""
    personas = json.loads(PERSONAS_PATH.read_text())
    seeds = json.loads(SEED_CANDIDATES_PATH.read_text())
    return personas, seeds


def _load_context() -> tuple[str, str]:
    """Load circuit and contract source files for context."""
    project_root = HERE.parent
    circuit_context = ""
    contract_context = ""

    circuits_dir = project_root / "circuits" / "src"
    if circuits_dir.exists():
        for f in sorted(circuits_dir.rglob("*.circom")):
            try:
                content = f.read_text()
                circuit_context += f"--- {f.name} ---\n{content[:4000]}\n\n"
            except Exception:
                continue
    if not circuit_context:
        circuit_context = "(no circuit files found)"

    contracts_dir = project_root / "contracts" / "contracts"
    if contracts_dir.exists():
        for f in sorted(contracts_dir.rglob("*.sol")):
            try:
                content = f.read_text()
                contract_context += f"--- {f.name} ---\n{content[:4000]}\n\n"
            except Exception:
                continue
    if not contract_context:
        contract_context = "(no contract files found)"

    return circuit_context[:20000], contract_context[:20000]


def _build_prompt(persona: dict, seed_candidates: list, circuit_ctx: str, contract_ctx: str) -> str:
    return EXPLORE_PROMPT.format(
        role=persona["role"],
        focus=", ".join(persona["focus"]),
        persona_id=persona["id"],
        seed_candidates=json.dumps(seed_candidates, indent=2)[:8000],
        circuit_context=circuit_ctx,
        contract_context=contract_ctx,
    )


def _run_persona(
    persona: dict,
    seed_candidates: list,
    circuit_ctx: str,
    contract_ctx: str,
    *,
    model: str = "opus",
    timeout: int = 360,
) -> list[dict]:
    """Dispatch one persona. Returns a list of candidate dicts.

    On parse failure, returns an error-stub entry rather than raising.
    """
    prompt = _build_prompt(persona, seed_candidates, circuit_ctx, contract_ctx)
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    try:
        candidates = extract_json_array(raw)
    except ValueError as e:
        return [
            {
                "id": f"{persona['id']}_parse_error",
                "persona": persona["id"],
                "title": "Parse error",
                "dimension": "meta",
                "description": f"Failed to parse LLM response: {e}",
                "priority": "low",
                "estimated_effort": "unknown",
            }
        ]
    for c in candidates:
        c.setdefault("persona", persona["id"])
    return candidates


def run_tier1(
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 360,
    max_workers: int = 8,
) -> dict[str, Any]:
    """Dispatch all personas in parallel, collect candidates, score, and select winners.

    Writes:
      - tier1_candidates.json (raw from all personas)
      - tier1_scored.json (with judge scores merged)
      - tier1_winners.json (top candidates with verdict promote/consider, capped at 8)
    """
    personas, seed_candidates = _load_seed_data()
    circuit_ctx, contract_ctx = _load_context()
    all_candidates: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                _run_persona, p, seed_candidates, circuit_ctx, contract_ctx,
                model=model, timeout=timeout,
            ): p["id"]
            for p in personas
        }
        for fut in as_completed(futures):
            persona_id = futures[fut]
            try:
                candidates = fut.result()
                all_candidates.extend(candidates)
            except Exception as e:
                all_candidates.append(
                    {
                        "id": f"{persona_id}_exception",
                        "persona": persona_id,
                        "title": "Exception",
                        "dimension": "meta",
                        "description": f"Persona execution failed: {type(e).__name__}: {e}",
                        "priority": "low",
                        "estimated_effort": "unknown",
                    }
                )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tier1_candidates.json").write_text(json.dumps(all_candidates, indent=2))

    # Tier 1b: Judge scoring.
    # Meta-stubs are excluded from scoring.
    scorable = [c for c in all_candidates if c.get("dimension") != "meta"]
    scored: list[dict] = []
    if scorable:
        try:
            candidate_scores = score_candidates(scorable)
            score_by_id = {s.candidate_id: s for s in candidate_scores}
            for c in all_candidates:
                if c.get("dimension") == "meta":
                    scored.append({
                        **c,
                        "adoption": 0, "standards": 0,
                        "completeness": 0, "correctness": 0,
                        "total": 0, "verdict": "drop",
                    })
                    continue
                s = score_by_id.get(c["id"])
                if s is None:
                    scored.append({
                        **c,
                        "adoption": 0, "standards": 0,
                        "completeness": 0, "correctness": 0,
                        "total": 0, "verdict": "drop",
                    })
                else:
                    scored.append({**c, **asdict(s)})
        except RuntimeError as e:
            scored = [
                {**c, "adoption": 0, "standards": 0, "completeness": 0,
                 "correctness": 0, "total": 0, "verdict": "drop"}
                for c in all_candidates
            ]
            (output_dir / "tier1_judge_error.txt").write_text(
                f"Judge failed: {type(e).__name__}: {e}"
            )
    else:
        scored = []

    (output_dir / "tier1_scored.json").write_text(json.dumps(scored, indent=2))

    # Tier 1c: Select winners (promote or consider, sorted by total, capped).
    eligible = [s for s in scored if s.get("verdict") in ("promote", "consider")]
    eligible.sort(key=lambda x: x.get("total", 0), reverse=True)
    winners = eligible[:MAX_SELECTED_WINNERS]
    (output_dir / "tier1_winners.json").write_text(json.dumps(winners, indent=2))

    return {
        "candidates": all_candidates,
        "scored": scored,
        "winners": winners,
        "output_dir": str(output_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 1: parallel protocol exploration")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--model", default="opus", help="Claude model for personas")
    ap.add_argument("--timeout", type=int, default=360, help="CLI timeout per persona (s)")
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    result = run_tier1(output_dir, model=args.model, timeout=args.timeout)
    print(f"Wrote {len(result['candidates'])} candidates to {output_dir / 'tier1_candidates.json'}")
    print(f"Selected {len(result['winners'])} winners")
    return 0


if __name__ == "__main__":
    sys.exit(main())
