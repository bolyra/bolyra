"""Tests for adversarial.py — Codex adversarial reviewer."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch

from adversarial import (
    review_experiment,
    AdversarialVerdict,
    _parse_verdict,
    _claude_fallback,
    VALID_VERDICTS,
)


def test_parse_verdict_approve():
    raw = '{"verdict": "APPROVE", "findings": [], "summary": "All good"}'
    v = _parse_verdict(raw)
    assert v.verdict == "APPROVE"
    assert v.findings == []
    assert v.summary == "All good"


def test_parse_verdict_conditional():
    raw = '{"verdict": "CONDITIONAL", "findings": ["fix X", "fix Y"], "summary": "Needs work"}'
    v = _parse_verdict(raw)
    assert v.verdict == "CONDITIONAL"
    assert len(v.findings) == 2
    assert "fix X" in v.findings


def test_parse_verdict_reject_with_blocking():
    raw = '{"verdict": "REJECT", "blocking_issues": ["fatal flaw"], "summary": "Cannot merge"}'
    v = _parse_verdict(raw)
    assert v.verdict == "REJECT"
    assert v.findings == ["fatal flaw"]


def test_parse_verdict_invalid_defaults_to_reject():
    raw = '{"verdict": "MAYBE", "findings": [], "summary": "uncertain"}'
    v = _parse_verdict(raw)
    assert v.verdict == "REJECT"


def test_review_experiment_falls_back_to_claude(monkeypatch, tmp_path):
    """When codex is unavailable, falls back to Claude CLI."""
    # Make codex unavailable
    monkeypatch.setattr("adversarial.shutil.which", lambda x: None)

    def fake_cli(prompt, *, model="opus", timeout=300):
        return json.dumps({
            "verdict": "CONDITIONAL",
            "findings": ["needs more tests"],
            "summary": "Close but needs tests"
        })

    monkeypatch.setattr("adversarial.call_claude_cli", fake_cli)

    exp_dir = tmp_path / "experiments" / "test_exp"
    exp_dir.mkdir(parents=True)
    (exp_dir / "readme.md").write_text("# Test experiment")

    result = review_experiment(exp_dir)
    assert isinstance(result, AdversarialVerdict)
    assert result.verdict == "CONDITIONAL"
    assert result.source == "claude_subagent"
    assert "needs more tests" in result.findings


def test_review_experiment_uses_codex_when_available(monkeypatch, tmp_path):
    """When codex is available and succeeds, use it."""
    monkeypatch.setattr("adversarial.shutil.which", lambda x: "/usr/local/bin/codex")

    import subprocess
    mock_result = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout=json.dumps({
            "verdict": "APPROVE",
            "findings": [],
            "summary": "Clean"
        }),
        stderr="",
    )

    def fake_run(*args, **kwargs):
        return mock_result

    monkeypatch.setattr("adversarial.subprocess.run", fake_run)

    exp_dir = tmp_path / "experiments" / "test_exp"
    exp_dir.mkdir(parents=True)

    result = review_experiment(exp_dir)
    assert result.verdict == "APPROVE"
    assert result.source == "codex"


def test_valid_verdicts():
    assert VALID_VERDICTS == {"APPROVE", "CONDITIONAL", "REJECT"}
