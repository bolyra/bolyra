"""Main orchestrator for the patent-autoresearch loop.

Flow per iteration:
  1. Snapshot current patent to runs/iter_N_TS/current_patent.md
  2. Tier 1: parallel adversarial fanout → attacks + judge ranking + high-priority selection
  3. Human gate: curate tier1_selected.json (unless --auto-approve)
  4. Tier 2: generate K candidates per selected attack → score → pick winners
  5. Apply winning mutations → patent_after.md
  6. Human gate: review diff (unless --auto-approve)
  7. Score patent_after.md to update trajectory
  8. Regression detector: if score dropped > 1.0, pause or halt
  9. Emit iteration_report.md + reports/adversarial-review-r{N}.md
 10. Overwrite live patent if no regression

Exit conditions (from history.plateau_detector):
  - Target score reached
  - Max iterations reached
  - 3 consecutive iterations with deltas < 2.0
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_tier1_attack import run_tier1
from run_tier2_claim import generate_candidates_for_run, score_and_pick_winners
from mutator import apply_winners, MutationResult
from baseline import score_baseline

# Add history/ to import path for plateau_detector
sys.path.insert(0, str(Path(__file__).resolve().parent / "history"))
from plateau_detector import should_stop

HERE = Path(__file__).resolve().parent
PATENT_PATH = HERE.parent / "drafts" / "provisional-patent-identityos.md"
PRIOR_ART_PATH = HERE / "prior_art.json"
RUNS_DIR = HERE / "runs"
HISTORY_DIR = HERE / "history"
HISTORY_PATH = HISTORY_DIR / "score_trajectory.jsonl"
REPORTS_DIR = HERE / "reports"

# Rounds 1-3 were manual adversarial reviews (drafts/adversarial-review{,-r2,-r3}.md).
# Automated iterations produce round 4+ reports.
MANUAL_ROUNDS_OFFSET = 3

REGRESSION_TOLERANCE = 1.0  # score drop > this pt amount triggers regression halt


def load_trajectory() -> list[dict]:
    """Read score_trajectory.jsonl."""
    if not HISTORY_PATH.exists():
        return []
    return [
        json.loads(line)
        for line in HISTORY_PATH.read_text().splitlines()
        if line.strip()
    ]


def record_trajectory(entry: dict) -> None:
    """Append one entry to score_trajectory.jsonl."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def detect_regression(trajectory: list[dict], *, tolerance: float = REGRESSION_TOLERANCE) -> tuple[bool, float]:
    """Compare latest total to previous. Return (regressed, delta).

    Regression means latest < previous - tolerance. A small drop within tolerance
    is noise-safe.
    """
    if len(trajectory) < 2:
        return False, 0.0
    prev = trajectory[-2]["total"]
    latest = trajectory[-1]["total"]
    delta = latest - prev
    return delta < -tolerance, delta


def write_iteration_report(
    *,
    iter_dir: Path,
    iter_num: int,
    ts: str,
    selected_count: int,
    candidates_count: int,
    applied_ids: list[str],
    skipped_entries: list[dict],
    new_total: float,
) -> None:
    """Emit iteration_report.md (human-readable summary for the iter dir)."""
    attacks_path = iter_dir / "tier1_attacks.json"
    attack_count = len(json.loads(attacks_path.read_text())) if attacks_path.exists() else 0

    lines = [
        f"# Iteration {iter_num} Report",
        "",
        f"- Timestamp: {ts}",
        f"- Attacks generated: {attack_count}",
        f"- Attacks selected (high priority): {selected_count}",
        f"- Candidates generated: {candidates_count}",
        f"- Winners applied: {len(applied_ids)}",
        f"- Winners skipped: {len(skipped_entries)}",
        f"- New total score: {new_total}",
    ]
    if applied_ids:
        lines.append("")
        lines.append("## Applied Mutations")
        for aid in applied_ids:
            lines.append(f"- {aid}")
    if skipped_entries:
        lines.append("")
        lines.append("## Skipped Mutations")
        for s in skipped_entries:
            lines.append(f"- **{s['id']}**: {s['reason']}")
    lines.append("")
    lines.append("See individual JSON files in this directory for detail.")
    (iter_dir / "iteration_report.md").write_text("\n".join(lines))


def write_adversarial_report(
    *,
    iter_num: int,
    ts: str,
    iter_dir: Path,
    applied_winners: list[dict],
    applied_ids: list[str],
    skipped_entries: list[dict],
    prev_total: float,
    new_total: float,
) -> None:
    """Emit reports/adversarial-review-r{N}.md — drop-in successor to the manual
    reviews at drafts/adversarial-review{,-r2,-r3}.md.

    Round numbering: r{iter_num + MANUAL_ROUNDS_OFFSET} (r1-r3 were manual).
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    round_num = iter_num + MANUAL_ROUNDS_OFFSET
    scored_path = iter_dir / "tier1_scored.json"
    attacks = json.loads(scored_path.read_text()) if scored_path.exists() else []

    by_category: dict[str, list] = {}
    for a in attacks:
        cat = a.get("category", "other")
        by_category.setdefault(cat, []).append(a)

    delta = new_total - prev_total
    md = [
        f"# Adversarial Review — Round {round_num} (automated)",
        "",
        f"Generated by patent-autoresearch loop iteration {iter_num} on {ts}",
        f"",
        f"- Baseline/previous score: {prev_total}",
        f"- Post-iteration score: {new_total}",
        f"- Delta: {delta:+.1f}",
        "",
        "## Attacks by Category",
        "",
    ]
    for cat in sorted(by_category.keys()):
        items = by_category[cat]
        md.append(f"### {cat} ({len(items)} findings)")
        md.append("")
        for a in items:
            prio = a.get("priority", "?")
            persona = a.get("persona", "?")
            finding = a.get("finding", "")[:300]
            md.append(f"- **[{prio}]** ({persona}) {finding}")
            if a.get("evidence"):
                md.append(f"  - Evidence: {a['evidence'][:200]}")
        md.append("")

    md.append("## Applied Mutations")
    md.append("")
    if applied_winners:
        for w in applied_winners:
            if w["id"] in applied_ids:
                rat = w.get("rationale", "")[:300]
                target = w.get("targets_weakness", "?")
                md.append(f"- **{w['id']}** targeting `{target}`: {rat}")
    else:
        md.append("_No mutations applied this iteration._")
    md.append("")

    if skipped_entries:
        md.append("## Skipped Mutations")
        md.append("")
        for s in skipped_entries:
            md.append(f"- **{s['id']}**: {s['reason']}")
        md.append("")

    (REPORTS_DIR / f"adversarial-review-r{round_num}.md").write_text("\n".join(md))


def run_iteration(
    iter_num: int,
    *,
    patent_path: Path = PATENT_PATH,
    auto_approve: bool = False,
    k: int = 3,
) -> dict:
    """Run one full iteration. Returns the new score dict (with iter/ts keys)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    iter_dir = RUNS_DIR / f"iter_{iter_num:03d}_{ts}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    # Snapshot
    shutil.copy(patent_path, iter_dir / "current_patent.md")
    patent_text = patent_path.read_text()

    # Tier 1
    print(f"[iter {iter_num}] Tier 1: dispatching adversarial reviewers...")
    run_tier1(patent_text, iter_dir)

    # Human gate
    selected_path = iter_dir / "tier1_selected.json"
    if not auto_approve:
        print(f"[iter {iter_num}] Human gate: review {selected_path}, then press Enter to proceed.")
        input()

    selected = json.loads(selected_path.read_text())
    if not selected:
        print(f"[iter {iter_num}] No high-priority attacks selected; skipping Tier 2.")
        # Still score the unchanged patent to keep trajectory monotonic in iteration count
        new_score = score_baseline(patent_text)
        new_score.update({"iter": iter_num, "ts": ts, "skipped": True})
        record_trajectory(new_score)
        return new_score

    # Tier 2
    print(f"[iter {iter_num}] Tier 2: generating candidates for {len(selected)} attacks...")
    candidates = generate_candidates_for_run(selected, patent_text, iter_dir, k=k)

    prior_art = json.loads(PRIOR_ART_PATH.read_text()) if PRIOR_ART_PATH.exists() else []
    winners = score_and_pick_winners(candidates, patent_text, prior_art, iter_dir)

    if not winners:
        print(f"[iter {iter_num}] No winners scored high enough; skipping mutation.")
        new_score = score_baseline(patent_text)
        new_score.update({"iter": iter_num, "ts": ts, "winners": 0})
        record_trajectory(new_score)
        return new_score

    # Apply mutations
    patent_after = iter_dir / "patent_after.md"
    result = apply_winners(patent_path, winners, patent_after)
    print(f"[iter {iter_num}] Applied {len(result.applied)} / skipped {len(result.skipped)}")

    # Score BEFORE overwriting live patent (keeps rollback option)
    print(f"[iter {iter_num}] Scoring new patent...")
    new_score = score_baseline(patent_after.read_text())

    # Regression check: peek at trajectory with hypothetical new entry
    hypothetical_traj = load_trajectory() + [{"iter": iter_num, "total": new_score["total"]}]
    regressed, delta = detect_regression(hypothetical_traj, tolerance=REGRESSION_TOLERANCE)
    if regressed:
        print(f"[iter {iter_num}] WARNING: REGRESSION detected: delta={delta:+.1f}")
        print(f"    Applied: {result.applied}")
        print(f"    Skipped: {result.skipped}")
        print(f"    Review: diff {iter_dir / 'current_patent.md'} {patent_after}")
        if auto_approve:
            print("    Auto-approve set, but regression detected — HALTING loop for safety.")
            sys.exit(1)
        print("    Press Enter to accept regression (rare), or Ctrl-C to abort.")
        input()

    # Human gate before overwriting live patent
    if not auto_approve:
        print(f"[iter {iter_num}] Review {patent_after} vs {patent_path}.")
        print("Press Enter to overwrite the live patent, or Ctrl-C to abort.")
        input()

    shutil.copy(patent_after, patent_path)

    # Record to trajectory
    new_score.update({"iter": iter_num, "ts": ts})
    record_trajectory(new_score)

    # Emit reports
    prev_total = hypothetical_traj[-2]["total"] if len(hypothetical_traj) >= 2 else new_score["total"]
    write_iteration_report(
        iter_dir=iter_dir,
        iter_num=iter_num,
        ts=ts,
        selected_count=len(selected),
        candidates_count=len(candidates),
        applied_ids=result.applied,
        skipped_entries=result.skipped,
        new_total=new_score["total"],
    )
    write_adversarial_report(
        iter_num=iter_num,
        ts=ts,
        iter_dir=iter_dir,
        applied_winners=winners,
        applied_ids=result.applied,
        skipped_entries=result.skipped,
        prev_total=prev_total,
        new_total=new_score["total"],
    )

    return new_score


def main() -> int:
    ap = argparse.ArgumentParser(description="Patent autoresearch loop orchestrator")
    ap.add_argument("--max-iters", type=int, default=10)
    ap.add_argument("--target-score", type=float, default=90.0)
    ap.add_argument("--auto-approve", action="store_true",
                    help="Skip human gates (dangerous outside dev)")
    ap.add_argument("--baseline-only", action="store_true",
                    help="Score the current patent and exit; useful for anchoring trajectory at iter 0")
    ap.add_argument("--k", type=int, default=3, help="Candidates per attack (Tier 2)")
    args = ap.parse_args()

    # Initial baseline if trajectory is empty
    if not load_trajectory():
        print("No trajectory found; running baseline (iteration 0)...")
        baseline = score_baseline(PATENT_PATH.read_text())
        baseline.update({
            "iter": 0,
            "ts": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"),
        })
        record_trajectory(baseline)
        print(f"Baseline: total={baseline['total']}")

    if args.baseline_only:
        return 0

    # Main loop
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
        run_iteration(i, auto_approve=args.auto_approve, k=args.k)

    print("Loop complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
