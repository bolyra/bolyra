#!/usr/bin/env python3
"""Generate a final summary from the patent-autoresearch loop state.

Reads history/score_trajectory.jsonl and per-iteration reports under runs/.
Prints a human-readable summary with ASCII score trajectory chart to stdout
and optionally writes FINAL_REPORT.md.

Usage:
    python3 patent-autoresearch/scripts/summarize_run.py
    python3 patent-autoresearch/scripts/summarize_run.py --write-file
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # patent-autoresearch/
HIST = HERE / "history" / "score_trajectory.jsonl"
RUNS = HERE / "runs"
REPORTS = HERE / "reports"
FINAL_REPORT = HERE / "FINAL_REPORT.md"

BAR_WIDTH = 40  # chars


def load_trajectory() -> list[dict]:
    if not HIST.exists():
        return []
    return [json.loads(line) for line in HIST.read_text().splitlines() if line.strip()]


def render_trajectory_chart(traj: list[dict]) -> str:
    if not traj:
        return "(no data — run `python3 run_loop.py --baseline-only` first)"
    lines = []
    for t in traj:
        total = t.get("total", 0)
        bar = "█" * int((total / 100.0) * BAR_WIDTH)
        pad = " " * (BAR_WIDTH - len(bar))
        iter_label = f"iter {t.get('iter', '?'):>3}"
        note = ""
        if t.get("skipped"):
            note = " (skipped — no high-priority attacks)"
        elif t.get("winners") == 0:
            note = " (no winners applied)"
        lines.append(f"{iter_label}  {bar}{pad}  {total:>5.1f}{note}")
    return "\n".join(lines)


def summarize_iterations(traj: list[dict]) -> str:
    if not traj:
        return "No iterations run."
    baseline = traj[0]
    latest = traj[-1]
    delta = latest["total"] - baseline["total"]
    lines = [
        f"- Baseline (iter 0): {baseline['total']:.1f}",
        f"- Latest (iter {latest.get('iter', '?')}): {latest['total']:.1f}",
        f"- Delta: {delta:+.1f}",
        f"- Iterations run: {len(traj) - 1}",  # baseline doesn't count
    ]
    return "\n".join(lines)


def list_reports() -> list[str]:
    if not REPORTS.exists():
        return []
    return sorted(str(p.name) for p in REPORTS.glob("adversarial-review-r*.md"))


def list_runs() -> list[str]:
    if not RUNS.exists():
        return []
    return sorted(str(p.name) for p in RUNS.iterdir() if p.is_dir())


def build_report() -> str:
    traj = load_trajectory()
    chart = render_trajectory_chart(traj)
    summary = summarize_iterations(traj)
    reports = list_reports()
    runs = list_runs()

    md = [
        "# Patent Autoresearch — Final Report",
        "",
        "## Score Trajectory",
        "",
        "```",
        chart,
        "```",
        "",
        "## Summary",
        "",
        summary,
        "",
    ]
    if reports:
        md.append("## Adversarial-Review Reports (automated rounds)")
        md.append("")
        md.append("Drop-in successors to the manual rounds at drafts/adversarial-review{,-r2,-r3}.md:")
        md.append("")
        for r in reports:
            md.append(f"- patent-autoresearch/reports/{r}")
        md.append("")
    if runs:
        md.append("## Iteration Run Directories")
        md.append("")
        md.append(f"{len(runs)} per-iteration snapshot directories under `runs/`:")
        md.append("")
        for r in runs:
            md.append(f"- patent-autoresearch/runs/{r}/")
        md.append("")
    md.append("## Current Patent")
    md.append("")
    md.append("Latest reviewed/approved patent at: `drafts/provisional-patent-identityos.md`")
    md.append("")
    return "\n".join(md)


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize patent-autoresearch loop state")
    ap.add_argument("--write-file", action="store_true",
                    help=f"Also write {FINAL_REPORT.name} to patent-autoresearch/")
    args = ap.parse_args()

    report = build_report()
    print(report)

    if args.write_file:
        FINAL_REPORT.write_text(report)
        print(f"\n(wrote {FINAL_REPORT.relative_to(HERE.parent)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
