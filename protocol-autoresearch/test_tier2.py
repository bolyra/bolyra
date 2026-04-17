"""Tests for run_tier2.py — build orchestrator."""
import json
import pytest
from pathlib import Path

from run_tier2 import (
    generate_outline,
    build_experiment,
    _create_placeholder_experiment,
    run_tier2,
    EXPERIMENTS_DIR,
)


def test_generate_outline_returns_dict(monkeypatch):
    def fake_cli(prompt, *, model="sonnet", timeout=120):
        return json.dumps({
            "id": "test_cand",
            "title": "Test",
            "artifacts": [{"type": "circuit", "filename": "test.circom", "description": "test circuit"}],
            "steps": ["step 1"],
            "estimated_constraints": 1000,
            "dependencies": [],
        })

    monkeypatch.setattr("run_tier2.call_claude_cli", fake_cli)

    candidate = {"id": "test_cand", "title": "Test", "dimension": "correctness", "description": "test"}
    outline = generate_outline(candidate)
    assert outline["id"] == "test_cand"
    assert len(outline["artifacts"]) == 1


def test_generate_outline_handles_error(monkeypatch):
    def fake_cli(prompt, *, model="sonnet", timeout=120):
        raise RuntimeError("CLI failed")

    monkeypatch.setattr("run_tier2.call_claude_cli", fake_cli)

    candidate = {"id": "fail", "title": "Fail"}
    outline = generate_outline(candidate)
    assert "error" in outline


def test_create_placeholder_experiment_correctness(tmp_path):
    exp_dir = tmp_path / "test_exp"
    exp_dir.mkdir()
    candidate = {"id": "c1", "title": "Fix bug", "dimension": "correctness", "description": "desc"}
    _create_placeholder_experiment(candidate, {}, exp_dir)

    assert (exp_dir / "circuit.circom").exists()
    assert (exp_dir / "contract.sol").exists()
    assert (exp_dir / "test_experiment.py").exists()
    assert (exp_dir / "README.md").exists()


def test_create_placeholder_experiment_adoption(tmp_path):
    exp_dir = tmp_path / "test_exp"
    exp_dir.mkdir()
    candidate = {"id": "c2", "title": "SDK", "dimension": "adoption", "description": "desc"}
    _create_placeholder_experiment(candidate, {}, exp_dir)

    assert (exp_dir / "sdk.ts").exists()
    assert (exp_dir / "README.md").exists()


def test_create_placeholder_experiment_standards(tmp_path):
    exp_dir = tmp_path / "test_exp"
    exp_dir.mkdir()
    candidate = {"id": "c3", "title": "Spec", "dimension": "standards", "description": "desc"}
    _create_placeholder_experiment(candidate, {}, exp_dir)

    assert (exp_dir / "spec.md").exists()
    content = (exp_dir / "spec.md").read_text()
    assert "MUST" in content


def test_build_experiment_creates_dir(monkeypatch, tmp_path):
    def fake_cli(prompt, *, model="opus", timeout=360):
        return json.dumps({
            "files": {
                "main.py": "print('hello')",
                "test_main.py": "def test_main(): assert True",
            }
        })

    monkeypatch.setattr("run_tier2.call_claude_cli", fake_cli)

    candidate = {"id": "c1", "title": "Test", "dimension": "adoption"}
    outline = {"id": "c1", "artifacts": []}
    exp_dir = tmp_path / "experiments" / "test_exp"

    result = build_experiment(candidate, outline, exp_dir)
    assert result == exp_dir
    assert (exp_dir / "main.py").exists()
    assert (exp_dir / "candidate.json").exists()


def test_build_experiment_falls_back_on_cli_failure(monkeypatch, tmp_path):
    def fake_cli(prompt, *, model="opus", timeout=360):
        raise RuntimeError("timeout")

    monkeypatch.setattr("run_tier2.call_claude_cli", fake_cli)

    candidate = {"id": "c1", "title": "Test", "dimension": "correctness"}
    outline = {"id": "c1", "artifacts": []}
    exp_dir = tmp_path / "experiments" / "test_exp"

    build_experiment(candidate, outline, exp_dir)
    assert exp_dir.exists()
    assert (exp_dir / "build_error.txt").exists()
    assert (exp_dir / "circuit.circom").exists()  # placeholder


def test_run_tier2_end_to_end(monkeypatch, tmp_path):
    """Full run_tier2 with mocked CLI calls."""
    outline_call = {"n": 0}
    build_call = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        if "outline" in prompt.lower() or "implementation plan" in prompt.lower():
            outline_call["n"] += 1
            return json.dumps({
                "id": "test",
                "title": "Test",
                "artifacts": [],
                "steps": [],
            })
        build_call["n"] += 1
        return json.dumps({
            "files": {
                "main.circom": "template T() {}",
                "README.md": "# Test",
            }
        })

    monkeypatch.setattr("run_tier2.call_claude_cli", fake_cli)
    # Override EXPERIMENTS_DIR to tmp
    monkeypatch.setattr("run_tier2.EXPERIMENTS_DIR", tmp_path / "experiments")

    winners = [
        {"id": "w1", "title": "Winner 1", "dimension": "correctness", "description": "test"},
        {"id": "w2", "title": "Winner 2", "dimension": "adoption", "description": "test"},
    ]
    output_dir = tmp_path / "tier2_output"
    result = run_tier2(winners, output_dir, skip_llm_score=True)

    assert (output_dir / "tier2_outlines.json").exists()
    assert (output_dir / "tier2_experiments.json").exists()
    assert (output_dir / "tier2_scores.json").exists()
    assert (output_dir / "tier2_winners.json").exists()
    assert len(result["experiments"]) == 2
