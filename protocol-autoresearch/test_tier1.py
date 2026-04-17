"""Tests for run_tier1.py — parallel protocol exploration fanout."""
import json
import pytest
from pathlib import Path

from run_tier1 import (
    run_tier1,
    PERSONAS_PATH,
    SEED_CANDIDATES_PATH,
    _run_persona,
    _load_seed_data,
    MAX_SELECTED_WINNERS,
)


def test_seed_paths_exist():
    assert PERSONAS_PATH.exists(), f"personas file missing: {PERSONAS_PATH}"
    assert SEED_CANDIDATES_PATH.exists(), f"seed candidates missing: {SEED_CANDIDATES_PATH}"


def test_load_seed_data_returns_personas_and_seeds():
    personas, seeds = _load_seed_data()
    assert len(personas) == 8
    assert len(seeds) == 20
    assert "id" in personas[0] and "role" in personas[0] and "focus" in personas[0]
    assert "id" in seeds[0] and "title" in seeds[0]


def test_run_persona_parses_candidates(monkeypatch):
    """Mock call_claude_cli and confirm _run_persona returns structured candidates."""
    mock_response = '''Here are my proposals.
[
  {
    "id": "sdk_designer_typed_sdk",
    "title": "Typed SDK core module",
    "dimension": "adoption",
    "description": "Build TypeScript SDK with full type exports",
    "priority": "critical",
    "estimated_effort": "days"
  }
]'''

    def fake_cli(prompt, *, model="opus", timeout=360):
        return mock_response

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)

    persona = {"id": "sdk_designer", "role": "SDK specialist", "focus": ["adoption"]}
    candidates = _run_persona(persona, seed_candidates=[], circuit_ctx="", contract_ctx="")
    assert len(candidates) == 1
    assert candidates[0]["persona"] == "sdk_designer"
    assert candidates[0]["dimension"] == "adoption"


def test_run_persona_gracefully_handles_parse_error(monkeypatch):
    def fake_cli(prompt, *, model="opus", timeout=360):
        return "I think the protocol looks great, no changes needed."

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)

    persona = {"id": "sdk_designer", "role": "...", "focus": ["adoption"]}
    candidates = _run_persona(persona, seed_candidates=[], circuit_ctx="", contract_ctx="")
    assert len(candidates) == 1
    assert candidates[0]["dimension"] == "meta"
    assert "parse_error" in candidates[0]["id"]


def test_run_persona_backfills_persona_id(monkeypatch):
    def fake_cli(prompt, *, model="opus", timeout=360):
        return '''[{"id": "x", "title": "X", "dimension": "adoption",
                    "description": "Y", "priority": "high", "estimated_effort": "days"}]'''

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)

    persona = {"id": "sdk_designer", "role": "...", "focus": ["adoption"]}
    candidates = _run_persona(persona, seed_candidates=[], circuit_ctx="", contract_ctx="")
    assert candidates[0]["persona"] == "sdk_designer"


def test_run_tier1_dispatches_all_personas(monkeypatch, tmp_path):
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        return json.dumps([{
            "id": f"p{call_count['n']}_proposal",
            "title": "Test proposal",
            "dimension": "adoption",
            "description": "test",
            "priority": "medium",
            "estimated_effort": "days",
        }])

    def fake_score(candidates, *, model="sonnet", timeout=240, batch_size=6):
        from judge import CandidateScore
        scores = []
        for c in candidates:
            s = CandidateScore(
                candidate_id=c["id"],
                adoption=18, standards=18, completeness=18, correctness=18,
            )
            s.finalize()
            scores.append(s)
        return scores

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1.score_candidates", fake_score)

    output_dir = tmp_path / "iter_001"
    result = run_tier1(output_dir)

    assert call_count["n"] == 8  # 8 personas
    assert (output_dir / "tier1_candidates.json").exists()
    candidates = json.loads((output_dir / "tier1_candidates.json").read_text())
    assert len(candidates) == 8
    persona_ids = {c["persona"] for c in candidates}
    assert len(persona_ids) == 8


def test_run_tier1_handles_persona_exception(monkeypatch, tmp_path):
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("CLI timeout")
        return json.dumps([{
            "id": f"p{call_count['n']}_ok",
            "title": "OK",
            "dimension": "adoption",
            "description": "test",
            "priority": "medium",
            "estimated_effort": "days",
        }])

    def fake_score(candidates, *, model="sonnet", timeout=240, batch_size=6):
        return []

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1.score_candidates", fake_score)

    output_dir = tmp_path / "iter_002"
    result = run_tier1(output_dir)
    candidates = json.loads((output_dir / "tier1_candidates.json").read_text())
    assert len(candidates) == 8
    errors = [c for c in candidates if c.get("dimension") == "meta"]
    assert len(errors) == 1
    assert "exception" in errors[0]["id"]


def test_run_tier1_selects_winners(monkeypatch, tmp_path):
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        return json.dumps([{
            "id": f"p{call_count['n']}_cand",
            "title": "Proposal",
            "dimension": "adoption",
            "description": "test",
            "priority": "high",
            "estimated_effort": "days",
        }])

    def fake_score(candidates, *, model="sonnet", timeout=240, batch_size=6):
        from judge import CandidateScore
        scores = []
        for i, c in enumerate(candidates):
            if i < 5:
                s = CandidateScore(candidate_id=c["id"],
                                   adoption=20, standards=20, completeness=20, correctness=20)
            else:
                s = CandidateScore(candidate_id=c["id"],
                                   adoption=5, standards=5, completeness=5, correctness=5)
            s.finalize()
            scores.append(s)
        return scores

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1.score_candidates", fake_score)

    output_dir = tmp_path / "iter_win"
    result = run_tier1(output_dir)
    winners = json.loads((output_dir / "tier1_winners.json").read_text())
    assert len(winners) == 5  # 5 scored high enough
    for w in winners:
        assert w["verdict"] in ("promote", "consider")


def test_run_tier1_dict_merge_correct(monkeypatch, tmp_path):
    """Verify dict-keyed merge not positional merge."""
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        return json.dumps([{
            "id": f"p{call_count['n']}_x",
            "title": "X",
            "dimension": "adoption",
            "description": f"from persona {call_count['n']}",
            "priority": "medium",
            "estimated_effort": "days",
        }])

    def fake_score(candidates, *, model="sonnet", timeout=240, batch_size=6):
        from judge import CandidateScore
        scores = []
        for c in candidates:
            num = int(c["id"].split("_")[0][1:])
            s = CandidateScore(candidate_id=c["id"],
                               adoption=num, standards=num, completeness=num, correctness=num)
            s.finalize()
            scores.append(s)
        # Return reversed to test dict-key merge
        return list(reversed(scores))

    monkeypatch.setattr("run_tier1.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1.score_candidates", fake_score)

    output_dir = tmp_path / "iter_merge"
    run_tier1(output_dir)
    scored = json.loads((output_dir / "tier1_scored.json").read_text())
    for s in scored:
        if s.get("dimension") == "meta":
            continue
        num = int(s["id"].split("_")[0][1:])
        assert s["adoption"] == num, f"Merge mismatch for {s['id']}"
