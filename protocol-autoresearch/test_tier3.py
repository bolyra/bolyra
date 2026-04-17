"""Tests for run_tier3_review.py — adversarial review orchestrator."""
import json
import pytest
from pathlib import Path

from run_tier3_review import (
    review_tier2_winner,
    run_tier3,
    _attempt_fix,
)
from adversarial import AdversarialVerdict


def test_review_nonexistent_experiment():
    entry = {
        "experiment_dir": "/nonexistent/path",
        "candidate": {"id": "c1"},
    }
    result = review_tier2_winner(entry)
    assert result["verdict"] == "REJECT"
    assert result["action"] == "rejected"
    assert "does not exist" in result["findings"][0]


def test_review_approved_experiment(monkeypatch, tmp_path):
    exp_dir = tmp_path / "experiments" / "test_exp"
    exp_dir.mkdir(parents=True)
    (exp_dir / "README.md").write_text("# Test")

    winners_dir = tmp_path / "winners"
    monkeypatch.setattr("run_tier3_review.WINNERS_DIR", winners_dir)

    def fake_review(exp_dir, *, timeout=300):
        return AdversarialVerdict(
            verdict="APPROVE", findings=[], summary="Clean",
            source="claude_subagent"
        )

    monkeypatch.setattr("run_tier3_review.review_experiment", fake_review)

    entry = {
        "experiment_dir": str(exp_dir),
        "candidate": {"id": "c1"},
    }
    result = review_tier2_winner(entry)
    assert result["verdict"] == "APPROVE"
    assert result["action"] == "promoted"
    assert (winners_dir / "test_exp").exists()


def test_review_rejected_experiment(monkeypatch, tmp_path):
    exp_dir = tmp_path / "experiments" / "test_exp"
    exp_dir.mkdir(parents=True)

    def fake_review(exp_dir, *, timeout=300):
        return AdversarialVerdict(
            verdict="REJECT",
            findings=["critical circuit flaw"],
            summary="Unsalvageable",
            source="claude_subagent",
        )

    monkeypatch.setattr("run_tier3_review.review_experiment", fake_review)

    entry = {
        "experiment_dir": str(exp_dir),
        "candidate": {"id": "c1"},
    }
    result = review_tier2_winner(entry)
    assert result["verdict"] == "REJECT"
    assert result["action"] == "rejected"


def test_review_conditional_experiment(monkeypatch, tmp_path):
    exp_dir = tmp_path / "experiments" / "test_exp"
    exp_dir.mkdir(parents=True)

    def fake_review(exp_dir, *, timeout=300):
        return AdversarialVerdict(
            verdict="CONDITIONAL",
            findings=["add more tests"],
            summary="Close",
            source="claude_subagent",
        )

    monkeypatch.setattr("run_tier3_review.review_experiment", fake_review)

    entry = {
        "experiment_dir": str(exp_dir),
        "candidate": {"id": "c1"},
    }
    result = review_tier2_winner(entry)
    assert result["verdict"] == "CONDITIONAL"
    assert result["action"] == "conditional_pending_manual_fix"
    assert (exp_dir / "conditional_findings.json").exists()


def test_run_tier3_full(monkeypatch, tmp_path):
    """Full Tier 3 run with mixed verdicts."""
    exp1 = tmp_path / "experiments" / "exp_approve"
    exp1.mkdir(parents=True)
    exp2 = tmp_path / "experiments" / "exp_reject"
    exp2.mkdir(parents=True)

    winners_dir = tmp_path / "winners"
    monkeypatch.setattr("run_tier3_review.WINNERS_DIR", winners_dir)

    call_count = {"n": 0}

    def fake_review(exp_dir, *, timeout=300):
        call_count["n"] += 1
        if "approve" in str(exp_dir):
            return AdversarialVerdict(verdict="APPROVE", findings=[], summary="OK")
        return AdversarialVerdict(verdict="REJECT", findings=["bad"], summary="No")

    monkeypatch.setattr("run_tier3_review.review_experiment", fake_review)

    winners = [
        {"experiment_dir": str(exp1), "candidate": {"id": "c1"}, "score": {"total": 80}},
        {"experiment_dir": str(exp2), "candidate": {"id": "c2"}, "score": {"total": 70}},
    ]
    output_dir = tmp_path / "tier3_output"
    result = run_tier3(winners, output_dir)

    assert len(result["reviews"]) == 2
    assert len(result["promoted"]) == 1
    assert len(result["rejected_findings"]) == 1
    assert (output_dir / "tier3_reviews.json").exists()
    assert (output_dir / "tier3_promoted.json").exists()
    assert (output_dir / "tier3_rejected.json").exists()


def test_attempt_fix_stub(tmp_path):
    """_attempt_fix is stubbed and returns False."""
    exp_dir = tmp_path / "test"
    exp_dir.mkdir()
    result = _attempt_fix(exp_dir, ["finding1"])
    assert result is False
    assert (exp_dir / "conditional_findings.json").exists()
