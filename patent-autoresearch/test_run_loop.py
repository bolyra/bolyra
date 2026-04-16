"""Tests for run_loop.py — orchestrator.

Most integration happens via mocks. The real end-to-end run is exercised in Task 12.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from run_loop import (
    load_trajectory,
    record_trajectory,
    write_iteration_report,
    write_adversarial_report,
    detect_regression,
    HISTORY_PATH,
    RUNS_DIR,
    REPORTS_DIR,
)


def test_load_trajectory_empty(tmp_path, monkeypatch):
    empty_history = tmp_path / "score_trajectory.jsonl"
    monkeypatch.setattr("run_loop.HISTORY_PATH", empty_history)
    assert load_trajectory() == []


def test_load_trajectory_reads_jsonl(tmp_path, monkeypatch):
    history_file = tmp_path / "score_trajectory.jsonl"
    history_file.write_text(
        '{"iter": 0, "total": 65}\n'
        '{"iter": 1, "total": 70}\n'
    )
    monkeypatch.setattr("run_loop.HISTORY_PATH", history_file)
    traj = load_trajectory()
    assert len(traj) == 2
    assert traj[0]["iter"] == 0
    assert traj[1]["total"] == 70


def test_record_trajectory_appends(tmp_path, monkeypatch):
    history_file = tmp_path / "score_trajectory.jsonl"
    monkeypatch.setattr("run_loop.HISTORY_PATH", history_file)
    record_trajectory({"iter": 0, "total": 60})
    record_trajectory({"iter": 1, "total": 65})
    lines = history_file.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["iter"] == 0
    assert json.loads(lines[1])["total"] == 65


def test_detect_regression_flags_drop():
    traj = [{"iter": 0, "total": 70}, {"iter": 1, "total": 65}]
    regressed, delta = detect_regression(traj, tolerance=1.0)
    assert regressed is True
    assert delta == pytest.approx(-5.0)


def test_detect_regression_within_tolerance():
    traj = [{"iter": 0, "total": 70}, {"iter": 1, "total": 69.5}]
    regressed, delta = detect_regression(traj, tolerance=1.0)
    assert regressed is False  # within tolerance
    assert delta == pytest.approx(-0.5)


def test_detect_regression_empty_or_single():
    assert detect_regression([], tolerance=1.0) == (False, 0.0)
    assert detect_regression([{"iter": 0, "total": 65}], tolerance=1.0) == (False, 0.0)


def test_detect_regression_improvement_not_flagged():
    traj = [{"iter": 0, "total": 65}, {"iter": 1, "total": 70}]
    regressed, delta = detect_regression(traj, tolerance=1.0)
    assert regressed is False
    assert delta == pytest.approx(5.0)


def test_write_iteration_report_creates_md(tmp_path):
    iter_dir = tmp_path / "iter_001"
    iter_dir.mkdir()
    (iter_dir / "tier1_attacks.json").write_text(json.dumps([{"id": "a1"}, {"id": "a2"}]))

    write_iteration_report(
        iter_dir=iter_dir,
        iter_num=1,
        ts="20260416T120000",
        selected_count=3,
        candidates_count=9,
        applied_ids=["w1", "w2"],
        skipped_entries=[{"id": "w3", "reason": "not found"}],
        new_total=72.5,
    )
    report = iter_dir / "iteration_report.md"
    assert report.exists()
    content = report.read_text()
    assert "Iteration 1" in content
    assert "72.5" in content
    assert "w1" in content and "w2" in content


def test_write_adversarial_report_numbers_rounds_correctly(tmp_path, monkeypatch):
    """Round N = iteration_num + 3 (rounds 1-3 were manual)."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    monkeypatch.setattr("run_loop.REPORTS_DIR", reports_dir)

    iter_dir = tmp_path / "iter_001"
    iter_dir.mkdir()
    (iter_dir / "tier1_scored.json").write_text(json.dumps([
        {"id": "a1", "persona": "examiner_strict", "category": "101",
         "finding": "Claim 1 abstract", "priority": "high", "severity": 9,
         "specificity": 8, "remediability": 6, "total": 23, "evidence": "quote"},
        {"id": "a2", "persona": "obviousness_hunter", "category": "103",
         "finding": "Semaphore anticipates", "priority": "high",
         "severity": 9, "specificity": 7, "remediability": 6, "total": 22,
         "evidence": "ref"},
    ]))
    applied_winners = [
        {"id": "w1", "targets_weakness": "a1", "rationale": "Add circuit constraint anchor"},
    ]
    skipped = [{"id": "w2", "reason": "original not found"}]

    write_adversarial_report(
        iter_num=1,
        ts="20260416T120000",
        iter_dir=iter_dir,
        applied_winners=applied_winners,
        applied_ids=["w1"],
        skipped_entries=skipped,
        prev_total=60.0,
        new_total=72.5,
    )
    # Round 4 = iter 1 (since r1-r3 were manual)
    report = reports_dir / "adversarial-review-r4.md"
    assert report.exists()
    content = report.read_text()
    assert "Round 4" in content
    assert "72.5" in content
    assert "+12.5" in content  # delta
    assert "examiner_strict" in content
    assert "w1" in content
