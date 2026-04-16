"""Tests for summarize_run.py."""
import json
import sys
import pytest
from pathlib import Path

# Make the script importable
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from summarize_run import (
    render_trajectory_chart,
    summarize_iterations,
    build_report,
    load_trajectory,
)


def test_render_trajectory_chart_empty():
    assert "no data" in render_trajectory_chart([])


def test_render_trajectory_chart_single():
    traj = [{"iter": 0, "total": 50.0}]
    out = render_trajectory_chart(traj)
    assert "iter" in out
    assert "50.0" in out
    assert "█" in out


def test_render_trajectory_chart_multiple():
    traj = [
        {"iter": 0, "total": 45.0},
        {"iter": 1, "total": 55.0},
        {"iter": 2, "total": 72.0},
    ]
    out = render_trajectory_chart(traj)
    lines = out.splitlines()
    assert len(lines) == 3
    # Later iteration has longer bar
    assert out.find("72.0") > out.find("45.0")


def test_render_trajectory_chart_flags_skipped():
    traj = [{"iter": 0, "total": 65.0}, {"iter": 1, "total": 65.0, "skipped": True}]
    out = render_trajectory_chart(traj)
    assert "skipped" in out


def test_render_trajectory_chart_flags_no_winners():
    traj = [{"iter": 0, "total": 65.0}, {"iter": 1, "total": 65.0, "winners": 0}]
    out = render_trajectory_chart(traj)
    assert "no winners applied" in out


def test_summarize_iterations_empty():
    assert "No iterations" in summarize_iterations([])


def test_summarize_iterations_computes_delta():
    traj = [{"iter": 0, "total": 60.0}, {"iter": 1, "total": 72.5}, {"iter": 2, "total": 80.0}]
    out = summarize_iterations(traj)
    assert "60.0" in out
    assert "80.0" in out
    assert "+20.0" in out
    assert "2" in out  # iterations run (excluding baseline)


def test_build_report_no_crash():
    """Even with empty trajectory, build_report should produce valid markdown."""
    md = build_report()
    assert "Patent Autoresearch" in md
    assert "Score Trajectory" in md
