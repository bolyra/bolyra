"""Tests for run_loop.py and history/plateau_detector.py."""
import json
import pytest
from pathlib import Path

# Import plateau detector directly
import sys
sys.path.insert(0, str(Path(__file__).parent / "history"))
from plateau_detector import should_stop

from run_loop import (
    load_trajectory,
    record_trajectory,
    detect_regression,
    detect_correctness_regression,
    HISTORY_PATH,
)


# --- Plateau detector tests ---

def test_plateau_no_trajectory():
    stop, reason = should_stop([])
    assert not stop
    assert "no iterations" in reason


def test_plateau_target_reached():
    traj = [{"total": 84, "iter": 0}]
    stop, reason = should_stop(traj, target_score=84.0)
    assert stop
    assert "target score" in reason


def test_plateau_max_iters():
    traj = [{"total": 50, "iter": i} for i in range(11)]  # 0 + 10 iterations
    stop, reason = should_stop(traj, max_iters=10)
    assert stop
    assert "max iterations" in reason


def test_plateau_detected():
    # 5 entries with no improvement
    traj = [
        {"total": 50, "iter": 0},
        {"total": 51, "iter": 1},
        {"total": 51.5, "iter": 2},
        {"total": 52, "iter": 3},
    ]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=3.0)
    assert stop
    assert "plateau" in reason


def test_plateau_not_detected_still_improving():
    traj = [
        {"total": 50, "iter": 0},
        {"total": 55, "iter": 1},
        {"total": 60, "iter": 2},
        {"total": 65, "iter": 3},
    ]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=3.0)
    assert not stop
    assert "still improving" in reason


def test_plateau_needs_window():
    traj = [
        {"total": 50, "iter": 0},
        {"total": 50, "iter": 1},
    ]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=3.0)
    assert not stop
    assert "need" in reason


# --- Regression detector tests ---

def test_detect_regression_no_data():
    regressed, delta = detect_regression([])
    assert not regressed
    assert delta == 0.0


def test_detect_regression_improvement():
    traj = [{"total": 50}, {"total": 55}]
    regressed, delta = detect_regression(traj)
    assert not regressed
    assert delta == 5.0


def test_detect_regression_detected():
    traj = [{"total": 55}, {"total": 50}]
    regressed, delta = detect_regression(traj)
    assert regressed
    assert delta == -5.0


def test_detect_regression_within_tolerance():
    traj = [{"total": 55}, {"total": 54.5}]
    regressed, delta = detect_regression(traj)
    assert not regressed  # -0.5 is within 1.0 tolerance


def test_detect_correctness_regression():
    prev = {"correctness": {"points": 20}}
    new = {"correctness": {"points": 15}}
    regressed, delta = detect_correctness_regression(prev, new)
    assert regressed
    assert delta == -5.0


def test_detect_correctness_no_regression():
    prev = {"correctness": {"points": 15}}
    new = {"correctness": {"points": 18}}
    regressed, delta = detect_correctness_regression(prev, new)
    assert not regressed
    assert delta == 3.0


# --- Trajectory I/O tests ---

def test_record_and_load_trajectory(tmp_path, monkeypatch):
    test_history = tmp_path / "history" / "score_trajectory.jsonl"
    monkeypatch.setattr("run_loop.HISTORY_PATH", test_history)

    record_trajectory({"iter": 0, "total": 50})
    record_trajectory({"iter": 1, "total": 55})

    traj = load_trajectory()
    assert len(traj) == 2
    assert traj[0]["total"] == 50
    assert traj[1]["total"] == 55
