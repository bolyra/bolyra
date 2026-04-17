"""Tier 2: Build orchestrator — outline + build for selected candidates.

Two stages:
- Stage A (outline): cheap Claude call produces structured outline JSON
- Stage B (build): generates artifacts into experiments/tier2_NNN_<id>/

For this initial implementation, Stage B creates the experiment directory
structure with placeholder files. The real generation will happen when the
loop runs with Claude CLI.
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

from _shared import call_claude_cli, extract_json_object
from scoring import score_experiment, ExperimentScore


HERE = Path(__file__).resolve().parent
EXPERIMENTS_DIR = HERE / "experiments"

OUTLINE_PROMPT = """You are a protocol engineer outlining an implementation plan.

CANDIDATE:
{candidate_json}

SEED CONTEXT (existing protocol files for reference):
{context}

Produce a structured implementation outline. Return ONLY a JSON object (no markdown fences):
{{
  "id": "{candidate_id}",
  "title": "{title}",
  "artifacts": [
    {{"type": "circuit" | "contract" | "sdk" | "spec" | "test" | "docs", "filename": "...", "description": "..."}}
  ],
  "steps": ["step 1", "step 2", ...],
  "estimated_constraints": <number or null>,
  "dependencies": ["dep1", "dep2"]
}}
"""

BUILD_PROMPT = """You are a protocol engineer implementing an experiment for the Bolyra identity protocol.

OUTLINE:
{outline_json}

CANDIDATE:
{candidate_json}

Generate all artifacts listed in the outline. For each artifact, produce the FULL file content.

Return ONLY a JSON object (no markdown fences):
{{
  "files": {{
    "filename.ext": "full file content here",
    "another.ext": "full file content"
  }}
}}

Include at minimum:
- The main artifact (circuit, contract, SDK module, or spec)
- A test file
- A README.md with usage instructions
"""


def generate_outline(
    candidate: dict,
    context: str = "",
    *,
    model: str = "sonnet",
    timeout: int = 120,
) -> dict:
    """Stage A: Generate structured implementation outline."""
    prompt = OUTLINE_PROMPT.format(
        candidate_json=json.dumps(candidate, indent=2)[:4000],
        context=context[:8000],
        candidate_id=candidate.get("id", "unknown"),
        title=candidate.get("title", "untitled"),
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "id": candidate.get("id", "unknown"),
            "title": candidate.get("title", "untitled"),
            "artifacts": [],
            "steps": [],
            "error": f"outline generation failed: {e}",
        }


def build_experiment(
    candidate: dict,
    outline: dict,
    experiment_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 360,
) -> Path:
    """Stage B: Generate experiment artifacts into experiment_dir.

    Uses Claude CLI to generate file contents based on the outline.
    Falls back to placeholder files on failure.
    """
    experiment_dir.mkdir(parents=True, exist_ok=True)

    # Save candidate and outline metadata
    (experiment_dir / "candidate.json").write_text(json.dumps(candidate, indent=2))
    (experiment_dir / "outline.json").write_text(json.dumps(outline, indent=2))

    # Try Claude CLI for real generation
    prompt = BUILD_PROMPT.format(
        outline_json=json.dumps(outline, indent=2)[:6000],
        candidate_json=json.dumps(candidate, indent=2)[:4000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        data = extract_json_object(raw)
        files = data.get("files", {})
        for filename, content in files.items():
            filepath = experiment_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(str(content))
        return experiment_dir
    except Exception as e:
        # Fall back to placeholder structure
        _create_placeholder_experiment(candidate, outline, experiment_dir, str(e))
        return experiment_dir


def _create_placeholder_experiment(
    candidate: dict, outline: dict, experiment_dir: Path, error: str = ""
) -> None:
    """Create placeholder experiment directory structure."""
    dim = candidate.get("dimension", "unknown")

    # Create dimension-appropriate placeholders
    if dim in ("correctness", "completeness"):
        (experiment_dir / "circuit.circom").write_text(
            f"// Placeholder circuit for: {candidate.get('title', 'untitled')}\n"
            f"// TODO: implement\n"
        )
        (experiment_dir / "contract.sol").write_text(
            f"// SPDX-License-Identifier: MIT\n"
            f"// Placeholder contract for: {candidate.get('title', 'untitled')}\n"
        )
    if dim == "adoption":
        (experiment_dir / "sdk.ts").write_text(
            f"// Placeholder SDK module for: {candidate.get('title', 'untitled')}\n"
            f"export function placeholder() {{}}\n"
        )
    if dim == "standards":
        (experiment_dir / "spec.md").write_text(
            f"# {candidate.get('title', 'Untitled Spec')}\n\n"
            f"## Abstract\n\n{candidate.get('description', '')}\n\n"
            f"## Normative Requirements\n\nImplementations MUST ...\n"
        )

    # Always create test file and README
    (experiment_dir / "test_experiment.py").write_text(
        f"# Placeholder tests for: {candidate.get('title', 'untitled')}\n"
        f"def test_placeholder():\n"
        f"    assert True  # TODO: implement real tests\n"
    )
    (experiment_dir / "README.md").write_text(
        f"# {candidate.get('title', 'Experiment')}\n\n"
        f"{candidate.get('description', '')}\n\n"
        f"## Status\n\nPlaceholder — awaiting implementation.\n"
    )
    if error:
        (experiment_dir / "build_error.txt").write_text(error)


def run_tier2(
    winners: list[dict],
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 360,
    max_workers: int = 4,
    skip_llm_score: bool = False,
) -> dict[str, Any]:
    """Run Tier 2 for all selected winners from Tier 1.

    For each winner:
    1. Generate outline (Stage A)
    2. Build experiment (Stage B)
    3. Score experiment (24-check harness)

    Returns dict with experiment results.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    all_outlines: list[dict] = []
    all_experiments: list[dict] = []
    all_scores: list[dict] = []

    # Stage A: outlines (parallel)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(generate_outline, w, model="sonnet", timeout=120): w
            for w in winners
        }
        for fut in as_completed(futures):
            winner = futures[fut]
            try:
                outline = fut.result()
            except Exception as e:
                outline = {
                    "id": winner.get("id", "unknown"),
                    "error": f"outline failed: {e}",
                    "artifacts": [],
                    "steps": [],
                }
            all_outlines.append({"winner": winner, "outline": outline})

    (output_dir / "tier2_outlines.json").write_text(json.dumps(all_outlines, indent=2))

    # Stage B: build experiments (sequential for now, to avoid disk contention)
    for i, entry in enumerate(all_outlines):
        winner = entry["winner"]
        outline = entry["outline"]
        cid = winner.get("id", f"unknown_{i}")
        exp_dir = EXPERIMENTS_DIR / f"tier2_{i:03d}_{cid}"

        try:
            build_experiment(winner, outline, exp_dir, model=model, timeout=timeout)
        except Exception as e:
            exp_dir.mkdir(parents=True, exist_ok=True)
            _create_placeholder_experiment(winner, outline, exp_dir, str(e))

        # Score experiment
        try:
            score = score_experiment(
                exp_dir, candidate=winner,
                skip_llm=skip_llm_score, skip_build=True,
            )
            score_dict = {
                "experiment_id": score.experiment_id,
                "total": score.total,
                "verdict": score.verdict,
                "dimensions": {
                    d: {"points": ds.points, "max_points": ds.max_points}
                    for d, ds in score.dimensions.items()
                },
            }
        except Exception as e:
            score_dict = {
                "experiment_id": cid,
                "total": 0,
                "verdict": "drop",
                "error": str(e),
            }

        all_experiments.append({
            "candidate": winner,
            "experiment_dir": str(exp_dir),
            "score": score_dict,
        })
        all_scores.append(score_dict)

    (output_dir / "tier2_experiments.json").write_text(json.dumps(all_experiments, indent=2))
    (output_dir / "tier2_scores.json").write_text(json.dumps(all_scores, indent=2))

    # Pick winners: promote or consider verdicts, sorted by total
    tier2_winners = [
        e for e in all_experiments
        if e["score"].get("verdict") in ("promote", "consider")
    ]
    tier2_winners.sort(key=lambda x: x["score"].get("total", 0), reverse=True)
    (output_dir / "tier2_winners.json").write_text(json.dumps(tier2_winners, indent=2))

    return {
        "outlines": all_outlines,
        "experiments": all_experiments,
        "scores": all_scores,
        "winners": tier2_winners,
        "output_dir": str(output_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 2: build experiments from winners")
    ap.add_argument("--winners", required=True, help="Path to tier1_winners.json")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--model", default="opus")
    ap.add_argument("--timeout", type=int, default=360)
    args = ap.parse_args()

    winners = json.loads(Path(args.winners).read_text())
    output_dir = Path(args.output_dir)
    result = run_tier2(winners, output_dir, model=args.model, timeout=args.timeout)
    print(f"Built {len(result['experiments'])} experiments")
    print(f"Promoted {len(result['winners'])} winners")
    return 0


if __name__ == "__main__":
    sys.exit(main())
