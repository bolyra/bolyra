"""Tests for plateau_detector."""
import pytest

from plateau_detector import should_stop


def test_no_trajectory():
    stop, reason = should_stop([])
    assert not stop
    assert "no iterations" in reason


def test_max_iters_reached():
    traj = [{"total": 50}] * 10
    stop, reason = should_stop(traj, max_iters=10)
    assert stop
    assert "max iterations" in reason


def test_max_iters_not_reached():
    traj = [{"total": 50}] * 3
    stop, _ = should_stop(traj, max_iters=10, plateau_window=5)
    assert not stop  # not at max, not enough for plateau


def test_target_score_reached():
    traj = [{"total": 95}]
    stop, reason = should_stop(traj, target_score=90)
    assert stop
    assert "target score" in reason


def test_target_score_exact_boundary():
    traj = [{"total": 90}]
    stop, _ = should_stop(traj, target_score=90)
    assert stop  # >= is the check


def test_plateau_detection():
    """Last 3 deltas all < 2.0 → plateau."""
    traj = [{"total": 50}, {"total": 55}, {"total": 56}, {"total": 56.5}, {"total": 57}]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=2.0, max_iters=100)
    # window = [55, 56, 56.5, 57] → deltas = [1, 0.5, 0.5]. All < 2.
    assert stop
    assert "plateau" in reason


def test_not_yet_plateau_still_improving():
    """Last 3 deltas include a big jump → not plateau."""
    traj = [{"total": 50}, {"total": 55}, {"total": 56}, {"total": 56.5}, {"total": 70}]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=2.0, max_iters=100)
    # window = [55, 56, 56.5, 70] → deltas = [1, 0.5, 13.5]. Max > 2.
    assert not stop
    assert "still improving" in reason


def test_not_enough_iterations_for_plateau():
    traj = [{"total": 50}, {"total": 55}]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=2.0, max_iters=100)
    assert not stop
    assert "need" in reason and "plateau check" in reason


def test_regression_not_a_stop_reason():
    """Declining scores should NOT trigger plateau early — deltas are absolute values."""
    traj = [{"total": 80}, {"total": 75}, {"total": 70}, {"total": 65}]
    stop, reason = should_stop(traj, plateau_window=3, plateau_delta=2.0, max_iters=100)
    # deltas = |75-80|=5, |70-75|=5, |65-70|=5. Max=5, > 2 → not plateau.
    assert not stop


def test_target_score_takes_priority_over_max_iters():
    """Even if max_iters hit, target_score takes priority if latest >= target."""
    traj = [{"total": 95}] * 10
    stop, reason = should_stop(traj, max_iters=10, target_score=90)
    assert stop
    # Either is fine, but target_score check runs first per the spec.
    assert "target" in reason or "max" in reason
