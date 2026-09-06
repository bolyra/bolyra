"""Standards AutoResearch Loop — orchestrator.

Per iteration:
  0a. reconcile.py       ground truth first, unconditionally (no LLM)
  0b. fetch_signals      WebSearch per registry query (Fable 5.1)
  1.  Tier 1             persona fan-out (Fable 5.1) -> Codex judge -> human gate
  2.  Tier 2             build artifacts -> objective checks -> Codex acceptance
      + board updates    promoted scout candidates applied to boards
  3.  Tier 3             Codex adversarial review -> staged/ + APPLY.md
  4.  scoring            objective dims + Codex ecosystem-position; regression halt
  5.  report + trajectory

Exit: drought (3 dry iterations), --max-iters, regression (> 2.0 drop) halt.

Usage: python3 run_loop.py [--max-iters N] [--auto-approve] [--baseline-only]
                           [--skip-signals]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "sources"))
sys.path.insert(0, str(HERE / "history"))

from run_tier1_attack import run_tier1, held_entities  # noqa: E402
from run_tier2_build import run_tier2  # noqa: E402
from run_tier3_review import run_tier3  # noqa: E402
from reconcile import run_reconcile  # noqa: E402
from scoring import score_all  # noqa: E402
from boards import apply_board_updates, new_cards_since  # noqa: E402
from drought_detector import should_stop  # noqa: E402

RUNS_DIR = HERE / "runs"
HISTORY_PATH = HERE / "history" / "score_trajectory.jsonl"
REPORTS_DIR = HERE / "reports"

REGRESSION_TOLERANCE = 2.0


def load_trajectory() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    return [json.loads(l) for l in HISTORY_PATH.read_text().splitlines() if l.strip()]


def record_trajectory(entry: dict) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def write_report(iter_num: int, iter_dir: Path, *, reconcile_summary: dict,
                 tier1: dict, tier2: dict, tier3: dict, score: dict,
                 prev_total: float, board_counts: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    delta = score["total"] - prev_total
    md = [
        f"# Standards Iteration {iter_num} Report",
        "",
        f"- Timestamp: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Standard-ness: {prev_total} -> {score['total']} ({delta:+.1f})",
        "",
        "## Stage 0a: Reconcile",
        f"- Entities checked: {reconcile_summary.get('entities_checked')} "
        f"(stale: {reconcile_summary.get('entities_stale')})",
        f"- Boards: {json.dumps(reconcile_summary.get('boards', {}))}",
        "",
        "## Tier 1",
        f"- Candidates: {len(tier1.get('candidates', []))} · "
        f"Winners: {len(tier1.get('winners', []))}",
        "",
        "## Tier 2",
        f"- Built: {len(tier2.get('experiments', []))} · "
        f"Advanced: {len(tier2.get('winners', []))} · "
        f"Board updates: {json.dumps(board_counts)}",
        "",
        "## Tier 3",
        f"- Staged: {len(tier3.get('promoted', []))} · "
        f"Rejected: {len(tier3.get('rejected_findings', []))}",
        "",
        "## Score dimensions",
    ]
    for dim in ("implementations", "spec_hardness", "interop_evidence",
                "ecosystem_position", "registry_closure"):
        d = score.get(dim, {})
        md.append(f"- {dim}: {d.get('points', '?')}")
    rejected = tier3.get("rejected_findings", [])
    if rejected:
        md += ["", "## Rejected findings (fed to next Tier 1)"]
        md += [f"- **{r['experiment_id']}**: {'; '.join(r['findings'])[:300]}" for r in rejected]
    staged = tier3.get("promoted", [])
    if staged:
        md += ["", "## Staged for founder apply"]
        md += [f"- {r['id']} -> {r.get('staged_to')}" for r in staged]
    text = "\n".join(md) + "\n"
    (REPORTS_DIR / f"standards-iteration-r{iter_num}.md").write_text(text)
    (iter_dir / "iteration_report.md").write_text(text)


def run_iteration(iter_num: int, *, auto_approve: bool, skip_signals: bool,
                  reject_findings: list[dict]) -> tuple[dict, list[dict]]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    iter_dir = RUNS_DIR / f"iter_{iter_num:03d}_{ts}"
    iter_dir.mkdir(parents=True, exist_ok=True)
    if reject_findings:
        (iter_dir / "prev_rejected_findings.json").write_text(
            json.dumps(reject_findings, indent=2))

    trajectory = load_trajectory()
    prev_total = trajectory[-1]["total"] if trajectory else 0.0

    print(f"[iter {iter_num}] Stage 0a: reconciling ground truth...")
    reconcile_summary = run_reconcile(iter_dir)
    print(f"  {reconcile_summary['entities_checked']} entities, "
          f"{reconcile_summary['entities_stale']} stale")

    signals_text = ""
    if not skip_signals:
        print(f"[iter {iter_num}] Stage 0b: fetching signals...")
        try:
            from fetch_signals import fetch_signals
            signals = fetch_signals(iter_dir)
            signals_text = json.dumps(signals[:20], indent=2)
            print(f"  {len(signals)} new signals")
        except Exception as e:  # error stub, keep iterating
            signals_text = ""
            (iter_dir / "signals_error.json").write_text(json.dumps({"error": str(e)[:300]}))
            print(f"  signal fetch failed (continuing): {e}")

    print(f"[iter {iter_num}] Tier 1: persona fan-out + Codex judge...")
    tier1 = run_tier1(iter_dir, signals=signals_text,
                      reject_findings=json.dumps(reject_findings, indent=2) if reject_findings else "")

    winners_path = iter_dir / "tier1_winners.json"
    if not auto_approve:
        print(f"[iter {iter_num}] HUMAN GATE: review {winners_path}, then press Enter.")
        input()
    winners = json.loads(winners_path.read_text())

    tier2 = {"experiments": [], "winners": [], "board_updates": []}
    tier3 = {"reviews": [], "promoted": [], "rejected_findings": []}
    board_counts: dict = {}
    if winners:
        print(f"[iter {iter_num}] Tier 2: building {len(winners)} artifacts...")
        tier2 = run_tier2(winners, iter_dir)
        board_counts = apply_board_updates(
            tier2.get("board_updates", []), iter_num=iter_num,
            held_names=held_entities())
        if tier2["winners"]:
            print(f"[iter {iter_num}] Tier 3: Codex adversarial review...")
            tier3 = run_tier3(tier2["winners"], iter_dir)
    else:
        print(f"[iter {iter_num}] No Tier-1 winners; scan-only iteration (counts toward drought).")

    print(f"[iter {iter_num}] Scoring...")
    score = score_all(reconcile_summary)
    score.update({
        "iter": iter_num, "ts": ts,
        "new_cards": new_cards_since(iter_num),
        "staged": len(tier3.get("promoted", [])),
    })

    delta = score["total"] - prev_total
    if trajectory and delta < -REGRESSION_TOLERANCE:
        print(f"[iter {iter_num}] REGRESSION HALT: {prev_total} -> {score['total']} "
              f"({delta:+.1f}). Ground truth moved against us; founder should read "
              f"the report.")
        record_trajectory({**score, "regression_halt": True})
        write_report(iter_num, iter_dir, reconcile_summary=reconcile_summary,
                     tier1=tier1, tier2=tier2, tier3=tier3, score=score,
                     prev_total=prev_total, board_counts=board_counts)
        sys.exit(2)

    record_trajectory(score)
    write_report(iter_num, iter_dir, reconcile_summary=reconcile_summary,
                 tier1=tier1, tier2=tier2, tier3=tier3, score=score,
                 prev_total=prev_total, board_counts=board_counts)
    return score, tier3.get("rejected_findings", [])


def main() -> int:
    ap = argparse.ArgumentParser(description="Standards autoresearch loop")
    ap.add_argument("--max-iters", type=int, default=5)
    ap.add_argument("--auto-approve", action="store_true",
                    help="skip the human gate (safe: outputs are boards + staged artifacts only)")
    ap.add_argument("--baseline-only", action="store_true")
    ap.add_argument("--skip-signals", action="store_true",
                    help="skip Stage 0b web-search signal fetch")
    args = ap.parse_args()

    trajectory = load_trajectory()
    if not trajectory:
        print("No trajectory; scoring baseline (iteration 0, no judge call)...")
        baseline = score_all(judge=not args.baseline_only)
        baseline.update({"iter": 0,
                         "ts": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"),
                         "new_cards": 0, "staged": 0})
        record_trajectory(baseline)
        print(f"Baseline total: {baseline['total']}")
    if args.baseline_only:
        return 0

    reject_findings: list[dict] = []
    start = (load_trajectory()[-1].get("iter", 0)) + 1
    for i in range(start, start + args.max_iters):
        stop, reason = should_stop(load_trajectory(), max_iters=start + args.max_iters - 1)
        if stop:
            print(f"Stopping: {reason}")
            break
        _, reject_findings = run_iteration(
            i, auto_approve=args.auto_approve,
            skip_signals=args.skip_signals, reject_findings=reject_findings)
    print("Loop complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
