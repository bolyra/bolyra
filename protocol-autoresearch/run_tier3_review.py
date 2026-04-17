"""Tier 3: Adversarial review orchestrator.

Wraps adversarial.py to review all Tier 2 winners. Handles APPROVE/CONDITIONAL/REJECT:
- APPROVE: copy to winners/
- CONDITIONAL: attempt fixes, re-score, promote if still passing
- REJECT: log findings, inject into next iteration context
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from dataclasses import asdict
from typing import Any

from adversarial import review_experiment, AdversarialVerdict
from scoring import score_experiment


HERE = Path(__file__).resolve().parent
WINNERS_DIR = HERE / "winners"


def _attempt_fix(
    experiment_dir: Path,
    findings: list[str],
    candidate: dict | None = None,
) -> bool:
    """Attempt to fix CONDITIONAL findings.

    For now, this is a stub that returns False (no automatic fixes).
    Future: dispatch Claude CLI to fix specific findings.
    """
    # Record findings for manual review
    fixes_file = experiment_dir / "conditional_findings.json"
    fixes_file.write_text(json.dumps({
        "findings": findings,
        "status": "pending_manual_fix",
    }, indent=2))
    return False


def review_tier2_winner(
    experiment_entry: dict,
    *,
    timeout: int = 300,
) -> dict:
    """Review a single Tier 2 winner.

    Returns dict with verdict, findings, and action taken.
    """
    exp_dir = Path(experiment_entry.get("experiment_dir", ""))
    candidate = experiment_entry.get("candidate", {})

    if not exp_dir.exists():
        return {
            "experiment_id": candidate.get("id", "unknown"),
            "experiment_dir": str(exp_dir),
            "verdict": "REJECT",
            "findings": ["experiment directory does not exist"],
            "action": "rejected",
            "source": "system",
        }

    try:
        verdict = review_experiment(exp_dir, timeout=timeout)
    except Exception as e:
        return {
            "experiment_id": candidate.get("id", "unknown"),
            "experiment_dir": str(exp_dir),
            "verdict": "REJECT",
            "findings": [f"review failed: {type(e).__name__}: {e}"],
            "action": "rejected",
            "source": "error",
        }

    result = {
        "experiment_id": candidate.get("id", "unknown"),
        "experiment_dir": str(exp_dir),
        "verdict": verdict.verdict,
        "findings": verdict.findings,
        "summary": verdict.summary,
        "source": verdict.source,
    }

    if verdict.verdict == "APPROVE":
        # Copy to winners/
        dest = WINNERS_DIR / exp_dir.name
        dest.mkdir(parents=True, exist_ok=True)
        if exp_dir.exists():
            shutil.copytree(exp_dir, dest, dirs_exist_ok=True)
        result["action"] = "promoted"
        result["promoted_to"] = str(dest)

    elif verdict.verdict == "CONDITIONAL":
        # Attempt fixes
        fixed = _attempt_fix(exp_dir, verdict.findings, candidate)
        if fixed:
            # Re-score after fix
            try:
                new_score = score_experiment(exp_dir, candidate=candidate, skip_build=True)
                if new_score.verdict in ("promote", "consider"):
                    dest = WINNERS_DIR / exp_dir.name
                    dest.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(exp_dir, dest, dirs_exist_ok=True)
                    result["action"] = "fixed_and_promoted"
                    result["promoted_to"] = str(dest)
                else:
                    result["action"] = "fixed_but_still_failing"
            except Exception as e:
                result["action"] = f"fix_rescore_failed: {e}"
        else:
            result["action"] = "conditional_pending_manual_fix"

    else:  # REJECT
        result["action"] = "rejected"

    return result


def run_tier3(
    tier2_winners: list[dict],
    output_dir: Path,
    *,
    timeout: int = 300,
) -> dict[str, Any]:
    """Review all Tier 2 winners through adversarial review.

    Returns dict with reviews, promoted experiments, and rejected findings.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    WINNERS_DIR.mkdir(parents=True, exist_ok=True)

    reviews: list[dict] = []
    promoted: list[dict] = []
    rejected_findings: list[dict] = []

    for winner in tier2_winners:
        review = review_tier2_winner(winner, timeout=timeout)
        reviews.append(review)

        if review["action"] in ("promoted", "fixed_and_promoted"):
            promoted.append(review)
        elif review["action"] == "rejected":
            rejected_findings.append({
                "experiment_id": review["experiment_id"],
                "findings": review["findings"],
                "summary": review.get("summary", ""),
            })

    (output_dir / "tier3_reviews.json").write_text(json.dumps(reviews, indent=2))
    (output_dir / "tier3_promoted.json").write_text(json.dumps(promoted, indent=2))
    (output_dir / "tier3_rejected.json").write_text(json.dumps(rejected_findings, indent=2))

    return {
        "reviews": reviews,
        "promoted": promoted,
        "rejected_findings": rejected_findings,
        "output_dir": str(output_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 3: adversarial review of Tier 2 winners")
    ap.add_argument("--winners", required=True, help="Path to tier2_winners.json")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    winners = json.loads(Path(args.winners).read_text())
    output_dir = Path(args.output_dir)
    result = run_tier3(winners, output_dir, timeout=args.timeout)
    print(f"Reviewed {len(result['reviews'])} experiments")
    print(f"Promoted {len(result['promoted'])}, rejected {len(result['rejected_findings'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
