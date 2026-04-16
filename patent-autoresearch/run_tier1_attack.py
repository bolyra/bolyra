"""Tier 1: Dispatch N hostile reviewer personas in parallel.

Each persona reads the patent + prior art + case law and produces a list of
specific, actionable attacks. The fanout runs in a ThreadPoolExecutor so the
6 CLI calls happen concurrently rather than sequentially.

Output: patent-autoresearch/runs/<iter>/tier1_attacks.json (raw, unranked)
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from dataclasses import asdict

from _shared import call_claude_cli, extract_json_array
from judge import rank_attacks


# Maximum number of high-priority attacks promoted to Tier 2 per iteration.
# More than this creates too many candidate-generation CLI calls (cost + time).
MAX_SELECTED_HIGH_PRIORITY: int = 8

HERE = Path(__file__).resolve().parent
PERSONAS_PATH = HERE / "personas.json"
PRIOR_ART_PATH = HERE / "prior_art.json"
CASE_LAW_PATH = HERE / "case_law.json"


ATTACK_PROMPT = """You are a hostile patent reviewer playing the role: {role}
Focus: {focus}

Your job: find specific, actionable weaknesses in the following provisional patent.
Each finding should identify claim numbers, specific language, and recommend a direction.
Be brutal. No compliments.

PATENT:
{patent_text}

PRIOR ART (use these references; cite any applicable):
{prior_art}

CASE LAW (ground your 101/103/112 arguments):
{case_law}

Return ONLY a JSON array (no markdown fences), one object per finding:
[
  {{
    "id": "{persona_id}_<short_slug>",
    "persona": "{persona_id}",
    "claim_refs": [<claim numbers>],
    "category": "101" | "103" | "112" | "design_around" | "accuracy",
    "finding": "specific weakness in 2-4 sentences",
    "recommended_direction": "concrete fix suggestion",
    "evidence": "quote claim language + prior-art or case-law citation"
  }}
]

Produce at most 5 findings. If you cannot find any specific weakness, return [].
"""


def _load_seed_data() -> tuple[list[dict], list[dict], list[dict]]:
    """Load personas, prior art, and case law from the seed JSON files.

    Returns a 3-tuple (personas, prior_art, case_law) for use by callers.
    """
    personas = json.loads(PERSONAS_PATH.read_text())
    prior_art = json.loads(PRIOR_ART_PATH.read_text())
    case_law = json.loads(CASE_LAW_PATH.read_text())
    return personas, prior_art, case_law


def _build_prompt(persona: dict, patent_text: str, prior_art: list, case_law: list) -> str:
    return ATTACK_PROMPT.format(
        role=persona["role"],
        focus=", ".join(persona["focus"]),
        persona_id=persona["id"],
        patent_text=patent_text[:30000],
        prior_art=json.dumps(prior_art, indent=2)[:8000],
        case_law=json.dumps(case_law, indent=2)[:6000],
    )


def _run_persona(
    persona: dict,
    patent_text: str,
    prior_art: list,
    case_law: list,
    *,
    model: str = "opus",
    timeout: int = 360,
) -> list[dict]:
    """Dispatch one persona. Returns a list of attack dicts.

    On LLM parse failure, returns a single error-stub entry rather than raising —
    the orchestrator needs the other 5 personas to still produce output.
    """
    prompt = _build_prompt(persona, patent_text, prior_art, case_law)
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    try:
        attacks = extract_json_array(raw)
    except ValueError as e:
        return [
            {
                "id": f"{persona['id']}_parse_error",
                "persona": persona["id"],
                "claim_refs": [],
                "category": "meta",
                "finding": f"Failed to parse LLM response: {e}",
                "recommended_direction": "",
                "evidence": raw[:500],
            }
        ]
    # Backfill persona id if the model omitted it
    for a in attacks:
        a.setdefault("persona", persona["id"])
    return attacks


def run_tier1(
    patent_text: str,
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 360,
    max_workers: int = 6,
) -> dict[str, Any]:
    """Dispatch all personas in parallel, collect attacks, write tier1_attacks.json.

    If a persona raises (e.g., CLI timeout), an exception stub is inserted in its
    place so the orchestrator always sees one attack-or-stub per persona.
    """
    personas, prior_art, case_law = _load_seed_data()
    all_attacks: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                _run_persona, p, patent_text, prior_art, case_law,
                model=model, timeout=timeout,
            ): p["id"]
            for p in personas
        }
        for fut in as_completed(futures):
            persona_id = futures[fut]
            try:
                attacks = fut.result()
                all_attacks.extend(attacks)
            except Exception as e:
                all_attacks.append(
                    {
                        "id": f"{persona_id}_exception",
                        "persona": persona_id,
                        "claim_refs": [],
                        "category": "meta",
                        "finding": f"Persona execution failed: {type(e).__name__}: {e}",
                        "recommended_direction": "",
                        "evidence": traceback.format_exc()[:500],
                    }
                )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tier1_attacks.json").write_text(json.dumps(all_attacks, indent=2))

    # Tier 1b: Judge prioritization.
    # Meta-stubs (parse errors, exceptions) are excluded from scoring — they have
    # no real claim refs or finding content for the judge to evaluate.
    scorable_attacks = [a for a in all_attacks if a.get("category") != "meta"]
    scored: list[dict] = []
    if scorable_attacks:
        try:
            attack_scores = rank_attacks(scorable_attacks, context_patent_text=patent_text)
            # Key by attack_id, not position. The LLM may reorder the array;
            # rank_attacks only guarantees count match, not order preservation.
            score_by_id = {s.attack_id: s for s in attack_scores}
            for a in all_attacks:
                if a.get("category") == "meta":
                    # Meta stub: not scored, include with zero scores
                    scored.append({
                        **a,
                        "severity": 0,
                        "specificity": 0,
                        "remediability": 0,
                        "total": 0,
                        "priority": "low",
                    })
                    continue
                s = score_by_id.get(a["id"])
                if s is None:
                    # Judge returned fewer scores than expected for this id.
                    # rank_attacks' count-match guard should have caught total-mismatch,
                    # but a per-id drop is still possible if duplicate ids exist
                    # upstream. Fall back to zero for this entry.
                    scored.append({
                        **a,
                        "severity": 0,
                        "specificity": 0,
                        "remediability": 0,
                        "total": 0,
                        "priority": "low",
                    })
                else:
                    scored.append({**a, **asdict(s)})
        except RuntimeError as e:
            # Judge failed (timeout, count mismatch). Fall back to no-scoring.
            scored = [
                {**a, "severity": 0, "specificity": 0, "remediability": 0, "total": 0, "priority": "low"}
                for a in all_attacks
            ]
            (output_dir / "tier1_judge_error.txt").write_text(f"Judge failed: {type(e).__name__}: {e}")
    else:
        scored = []

    (output_dir / "tier1_scored.json").write_text(json.dumps(scored, indent=2))

    # Tier 1c: Select top MAX_SELECTED_HIGH_PRIORITY high-priority attacks by total score.
    high_priority = [s for s in scored if s.get("priority") == "high"]
    high_priority.sort(key=lambda x: x.get("total", 0), reverse=True)
    selected = high_priority[:MAX_SELECTED_HIGH_PRIORITY]
    (output_dir / "tier1_selected.json").write_text(json.dumps(selected, indent=2))

    return {
        "attacks": all_attacks,
        "scored": scored,
        "selected": selected,
        "output_dir": str(output_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 1: parallel adversarial attack discovery")
    ap.add_argument("--patent", required=True, help="Path to patent .md")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--model", default="opus", help="Claude model for personas")
    ap.add_argument("--timeout", type=int, default=360, help="CLI timeout per persona (s)")
    args = ap.parse_args()

    patent_text = Path(args.patent).read_text()
    output_dir = Path(args.output_dir)
    result = run_tier1(patent_text, output_dir, model=args.model, timeout=args.timeout)
    print(f"Wrote {len(result['attacks'])} attacks to {output_dir / 'tier1_attacks.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
