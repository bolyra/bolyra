#!/usr/bin/env python3
"""Summarize a protocol-autoresearch run.

Usage:
    python3 scripts/summarize_run.py              # print to stdout
    python3 scripts/summarize_run.py --write-file # also write FINAL_REPORT.md
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
HISTORY_PATH = HERE / "history" / "score_trajectory.jsonl"
REPORTS_DIR = HERE / "reports"
RUNS_DIR = HERE / "runs"


def load_trajectory() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    return [
        json.loads(line)
        for line in HISTORY_PATH.read_text().splitlines()
        if line.strip()
    ]


def ascii_chart(trajectory: list[dict], width: int = 50) -> str:
    """Simple ASCII bar chart of total scores."""
    if not trajectory:
        return "(no data)"
    lines = []
    max_total = 100
    for entry in trajectory:
        iter_num = entry.get("iter", "?")
        total = entry.get("total", 0)
        bar_len = int(total / max_total * width)
        bar = "#" * bar_len + "." * (width - bar_len)
        lines.append(f"  iter {iter_num:>3}: [{bar}] {total}")
    return "\n".join(lines)


def summarize() -> str:
    trajectory = load_trajectory()
    if not trajectory:
        return "No trajectory data found. Run `python3 run_loop.py --baseline-only` first."

    baseline = trajectory[0]
    latest = trajectory[-1]
    delta = latest["total"] - baseline["total"]

    lines = [
        "# Protocol AutoResearch Run Summary",
        "",
        f"Iterations: {len(trajectory) - 1} (plus baseline)",
        f"Baseline total: {baseline['total']}",
        f"Latest total: {latest['total']}",
        f"Delta: {delta:+.1f}",
        "",
        "## Score Trajectory",
        "",
        ascii_chart(trajectory),
        "",
        "## Dimension Breakdown (latest)",
        "",
    ]

    for dim in ["correctness", "completeness", "adoption", "standards"]:
        d = latest.get(dim, {})
        if isinstance(d, dict):
            pts = d.get("points", "?")
            critique = d.get("critique", "")[:100]
            lines.append(f"- **{dim}**: {pts}/25 — {critique}")
        else:
            lines.append(f"- **{dim}**: {d}")

    lines.append("")

    # List reports
    if REPORTS_DIR.exists():
        reports = sorted(REPORTS_DIR.glob("protocol-iteration-r*.md"))
        if reports:
            lines.append("## Iteration Reports")
            lines.append("")
            for r in reports:
                lines.append(f"- {r.name}")
            lines.append("")

    # List runs
    if RUNS_DIR.exists():
        runs = sorted(RUNS_DIR.iterdir())
        if runs:
            lines.append("## Run Directories")
            lines.append("")
            for r in runs:
                if r.is_dir():
                    lines.append(f"- {r.name}")
            lines.append("")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize protocol-autoresearch run")
    ap.add_argument("--write-file", action="store_true", help="Write FINAL_REPORT.md")
    args = ap.parse_args()

    summary = summarize()
    print(summary)

    if args.write_file:
        out = HERE / "FINAL_REPORT.md"
        out.write_text(summary)
        print(f"\nWritten to {out}")

    return 0


if __name__ == "__main__":
    exit(main())
