"""Main orchestrator for the protocol-autoresearch loop.

Flow per iteration:
  1. Tier 1: parallel explorer fanout -> candidates + judge scoring + winner selection
  2. Human gate: curate tier1_winners.json (unless --auto-approve)
  3. Tier 2: generate outlines + build experiments -> score -> pick winners
  4. Tier 3: adversarial review of Tier 2 winners -> APPROVE/CONDITIONAL/REJECT
  5. Score new protocol state
  6. Correctness regression detector (halts on drop > 1pt)
  7. REJECT feedback loop (inject findings into next Tier 1)
  8. Reports: reports/protocol-iteration-r{N}.md
  9. Update trajectory

Exit conditions (from history.plateau_detector):
  - Target score reached (84.0 = all dims >= 21)
  - Max iterations reached
  - 3 consecutive iterations with deltas < 3.0
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_tier1 import run_tier1
from run_tier2 import run_tier2
from run_tier3_review import run_tier3
from baseline import score_baseline

# Add history/ to import path for plateau_detector
sys.path.insert(0, str(Path(__file__).resolve().parent / "history"))
from plateau_detector import should_stop

HERE = Path(__file__).resolve().parent
RUNS_DIR = HERE / "runs"
HISTORY_DIR = HERE / "history"
HISTORY_PATH = HISTORY_DIR / "score_trajectory.jsonl"
REPORTS_DIR = HERE / "reports"

CORRECTNESS_REGRESSION_TOLERANCE = 1.0


def load_trajectory() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    return [
        json.loads(line)
        for line in HISTORY_PATH.read_text().splitlines()
        if line.strip()
    ]


def record_trajectory(entry: dict) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def detect_regression(
    trajectory: list[dict], *, tolerance: float = CORRECTNESS_REGRESSION_TOLERANCE
) -> tuple[bool, float]:
    """Compare latest total to previous. Return (regressed, delta)."""
    if len(trajectory) < 2:
        return False, 0.0
    prev = trajectory[-2]["total"]
    latest = trajectory[-1]["total"]
    delta = latest - prev
    return delta < -tolerance, delta


def detect_correctness_regression(
    prev_score: dict, new_score: dict
) -> tuple[bool, float]:
    """Check if correctness dimension specifically regressed."""
    prev_corr = prev_score.get("correctness", {}).get("points", 0) if isinstance(prev_score.get("correctness"), dict) else 0
    new_corr = new_score.get("correctness", {}).get("points", 0) if isinstance(new_score.get("correctness"), dict) else 0
    delta = new_corr - prev_corr
    return delta < -CORRECTNESS_REGRESSION_TOLERANCE, delta


def write_iteration_report(
    *,
    iter_dir: Path,
    iter_num: int,
    ts: str,
    tier1_result: dict,
    tier2_result: dict,
    tier3_result: dict,
    new_score: dict,
    prev_total: float,
) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    delta = new_score["total"] - prev_total

    md = [
        f"# Protocol Iteration {iter_num} Report",
        "",
        f"- Timestamp: {ts}",
        f"- Previous total: {prev_total}",
        f"- New total: {new_score['total']}",
        f"- Delta: {delta:+.1f}",
        "",
        "## Tier 1: Discovery",
        f"- Candidates generated: {len(tier1_result.get('candidates', []))}",
        f"- Winners selected: {len(tier1_result.get('winners', []))}",
        "",
        "## Tier 2: Build",
        f"- Experiments built: {len(tier2_result.get('experiments', []))}",
        f"- Tier 2 winners: {len(tier2_result.get('winners', []))}",
        "",
        "## Tier 3: Adversarial Review",
        f"- Reviews completed: {len(tier3_result.get('reviews', []))}",
        f"- Promoted: {len(tier3_result.get('promoted', []))}",
        f"- Rejected: {len(tier3_result.get('rejected_findings', []))}",
        "",
        "## Dimension Scores",
    ]
    for dim in ["correctness", "completeness", "adoption", "standards"]:
        d = new_score.get(dim, {})
        if isinstance(d, dict):
            pts = d.get("points", "?")
            md.append(f"- {dim}: {pts}/25")
    md.append("")

    # Rejected findings for next iteration feedback
    rejected = tier3_result.get("rejected_findings", [])
    if rejected:
        md.append("## Rejected Findings (feedback for next iteration)")
        md.append("")
        for r in rejected:
            md.append(f"- **{r.get('experiment_id', '?')}**: {'; '.join(r.get('findings', []))}")
        md.append("")

    report_path = REPORTS_DIR / f"protocol-iteration-r{iter_num}.md"
    report_path.write_text("\n".join(md))
    # Also save in iter dir
    (iter_dir / "iteration_report.md").write_text("\n".join(md))


def run_iteration(
    iter_num: int,
    *,
    auto_approve: bool = False,
    reject_findings: list[dict] | None = None,
) -> tuple[dict, list[dict]]:
    """Run one full iteration. Returns (new_score, rejected_findings)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    iter_dir = RUNS_DIR / f"iter_{iter_num:03d}_{ts}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    # Save reject findings from previous iteration for context
    if reject_findings:
        (iter_dir / "prev_rejected_findings.json").write_text(
            json.dumps(reject_findings, indent=2)
        )

    # Get previous score for regression detection
    trajectory = load_trajectory()
    prev_score = trajectory[-1] if trajectory else {"total": 0}

    # Tier 1: Discovery
    print(f"[iter {iter_num}] Tier 1: dispatching explorer personas...")
    tier1_result = run_tier1(iter_dir)

    # Human gate
    winners_path = iter_dir / "tier1_winners.json"
    if not auto_approve:
        print(f"[iter {iter_num}] Human gate: review {winners_path}, then press Enter.")
        input()

    winners = json.loads(winners_path.read_text())
    if not winners:
        print(f"[iter {iter_num}] No winners from Tier 1; scoring current state.")
        new_score = score_baseline()
        new_score.update({"iter": iter_num, "ts": ts, "skipped": True})
        record_trajectory(new_score)
        return new_score, []

    # Tier 2: Build
    print(f"[iter {iter_num}] Tier 2: building {len(winners)} experiments...")
    tier2_result = run_tier2(winners, iter_dir)

    tier2_winners = tier2_result.get("winners", [])
    if not tier2_winners:
        print(f"[iter {iter_num}] No Tier 2 winners; scoring current state.")
        new_score = score_baseline()
        new_score.update({"iter": iter_num, "ts": ts, "tier2_winners": 0})
        record_trajectory(new_score)
        return new_score, []

    # Tier 3: Adversarial review
    print(f"[iter {iter_num}] Tier 3: adversarial review of {len(tier2_winners)} experiments...")
    tier3_result = run_tier3(tier2_winners, iter_dir)

    # Score new protocol state
    print(f"[iter {iter_num}] Scoring protocol state...")
    new_score = score_baseline()

    # Correctness regression check
    corr_regressed, corr_delta = detect_correctness_regression(prev_score, new_score)
    if corr_regressed:
        print(f"[iter {iter_num}] WARNING: CORRECTNESS REGRESSION: delta={corr_delta:+.1f}")
        if auto_approve:
            print("    Auto-approve set, but correctness regression detected - HALTING.")
            sys.exit(1)
        print("    Press Enter to accept, or Ctrl-C to abort.")
        input()

    # Overall regression check
    hypothetical_traj = trajectory + [{"iter": iter_num, "total": new_score["total"]}]
    regressed, delta = detect_regression(hypothetical_traj)
    if regressed:
        print(f"[iter {iter_num}] WARNING: REGRESSION: delta={delta:+.1f}")
        if auto_approve:
            print("    Auto-approve set, regression detected - HALTING.")
            sys.exit(1)
        print("    Press Enter to accept, or Ctrl-C to abort.")
        input()

    # Record trajectory
    new_score.update({"iter": iter_num, "ts": ts})
    record_trajectory(new_score)

    # Write reports
    prev_total = prev_score.get("total", 0)
    write_iteration_report(
        iter_dir=iter_dir,
        iter_num=iter_num,
        ts=ts,
        tier1_result=tier1_result,
        tier2_result=tier2_result,
        tier3_result=tier3_result,
        new_score=new_score,
        prev_total=prev_total,
    )

    # Collect rejected findings for next iteration
    new_rejected = tier3_result.get("rejected_findings", [])
    return new_score, new_rejected


def main() -> int:
    ap = argparse.ArgumentParser(description="Protocol autoresearch loop orchestrator")
    ap.add_argument("--max-iters", type=int, default=10)
    ap.add_argument("--target-score", type=float, default=84.0)
    ap.add_argument("--auto-approve", action="store_true",
                    help="Skip human gates (dangerous outside dev)")
    ap.add_argument("--baseline-only", action="store_true",
                    help="Score the current protocol and exit")
    args = ap.parse_args()

    # Initial baseline if trajectory is empty
    if not load_trajectory():
        print("No trajectory found; running baseline (iteration 0)...")
        baseline = score_baseline()
        baseline.update({
            "iter": 0,
            "ts": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"),
        })
        record_trajectory(baseline)
        print(f"Baseline: total={baseline['total']}")

    if args.baseline_only:
        return 0

    # Main loop
    reject_findings: list[dict] = []
    for i in range(1, args.max_iters + 1):
        trajectory = load_trajectory()
        stop, reason = should_stop(
            trajectory,
            max_iters=args.max_iters,
            target_score=args.target_score,
        )
        if stop:
            print(f"Stopping: {reason}")
            break

        new_score, reject_findings = run_iteration(
            i,
            auto_approve=args.auto_approve,
            reject_findings=reject_findings,
        )

    print("Loop complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
