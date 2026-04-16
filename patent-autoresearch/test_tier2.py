"""Tests for run_tier2_claim.py — candidate claim generation + (Task 7) scoring."""
import json
import pytest
from pathlib import Path

from run_tier2_claim import (
    generate_candidates_for_attack,
    generate_candidates_for_run,
    DEFAULT_K,
)


def test_default_k_is_three():
    """Spec: K defaults to 3 candidates per attack."""
    assert DEFAULT_K == 3


def test_generate_candidates_for_attack_returns_k_variants(monkeypatch):
    """The generator dispatches one CLI call and parses K candidates from the response."""
    mock_response = '''[
      {
        "id": "cand_alice_specialist_1_01",
        "strategy": "narrow",
        "claim_refs": [1],
        "original_language": "abstract state write",
        "claim_text": "anchored cryptographic state write",
        "rationale": "Ties to specific circuit constraint output.",
        "targets_weakness": "alice_specialist_1",
        "tradeoffs": "Loses some genus coverage."
      },
      {
        "id": "cand_alice_specialist_1_02",
        "strategy": "positive_structural",
        "claim_refs": [1],
        "original_language": "abstract state write",
        "claim_text": "state write implemented via Poseidon hash output",
        "rationale": "Converts abstract language to concrete mechanism.",
        "targets_weakness": "alice_specialist_1",
        "tradeoffs": "More specific; slightly narrower."
      },
      {
        "id": "cand_alice_specialist_1_03",
        "strategy": "dependent_claim",
        "claim_refs": [1],
        "original_language": "abstract state write",
        "claim_text": "the method of claim 1 wherein the state write is...",
        "rationale": "Preserves independent claim, adds dependent narrowing.",
        "targets_weakness": "alice_specialist_1",
        "tradeoffs": "Keeps broad claim scope at independent level."
      }
    ]'''

    def fake_cli(prompt, *, model="opus", timeout=360):
        return mock_response

    monkeypatch.setattr("run_tier2_claim.call_claude_cli", fake_cli)

    attack = {
        "id": "alice_specialist_1",
        "claim_refs": [1],
        "category": "101",
        "finding": "Claim 1(d)(iii) is abstract state write",
        "recommended_direction": "Anchor with concrete circuit constraint",
    }
    candidates = generate_candidates_for_attack(
        attack=attack,
        patent_text="(patent excerpt)",
        k=3,
    )
    assert len(candidates) == 3
    for c in candidates:
        assert "id" in c
        assert "claim_text" in c
        assert "rationale" in c
        assert c["targets_weakness"] == attack["id"]


def test_generate_candidates_backfills_targets_weakness(monkeypatch):
    """If the LLM omits targets_weakness on a candidate, backfill from the attack id."""
    mock_response = '''[
      {"id": "cand_1", "strategy": "narrow", "claim_text": "...", "rationale": "..."},
      {"id": "cand_2", "strategy": "narrow", "claim_text": "...", "rationale": "..."}
    ]'''

    def fake_cli(prompt, *, model="opus", timeout=360):
        return mock_response

    monkeypatch.setattr("run_tier2_claim.call_claude_cli", fake_cli)

    attack = {"id": "test_weakness_42", "claim_refs": [9], "finding": "X", "recommended_direction": "Y"}
    candidates = generate_candidates_for_attack(attack, patent_text="...", k=2)
    for c in candidates:
        assert c["targets_weakness"] == "test_weakness_42"


def test_generate_candidates_for_attack_handles_parse_error(monkeypatch):
    """If the LLM returns unparseable output, return a single error-stub candidate."""
    def fake_cli(prompt, *, model="opus", timeout=360):
        return "I cannot generate candidates for this attack."

    monkeypatch.setattr("run_tier2_claim.call_claude_cli", fake_cli)

    attack = {"id": "w1", "claim_refs": [1], "finding": "x", "recommended_direction": "y"}
    candidates = generate_candidates_for_attack(attack, patent_text="...", k=3)
    # Returns one stub entry so the caller knows this attack failed candidate generation
    assert len(candidates) == 1
    assert candidates[0]["strategy"] == "error"
    assert candidates[0]["targets_weakness"] == "w1"
    assert "parse" in candidates[0]["rationale"].lower() or "fail" in candidates[0]["rationale"].lower()


def test_generate_candidates_for_run_dispatches_all_attacks(monkeypatch, tmp_path):
    """generate_candidates_for_run dispatches one CLI call per selected attack in parallel."""
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        n = call_count["n"]
        # Each call returns 3 candidates with unique ids
        return json.dumps([
            {
                "id": f"cand_call{n}_{i}",
                "strategy": "narrow",
                "claim_refs": [1],
                "original_language": "old",
                "claim_text": f"new {i}",
                "rationale": f"reason {i}",
                "tradeoffs": "some",
            }
            for i in range(3)
        ])

    monkeypatch.setattr("run_tier2_claim.call_claude_cli", fake_cli)

    selected_attacks = [
        {"id": f"attack_{i}", "claim_refs": [i], "finding": f"finding {i}", "recommended_direction": "y"}
        for i in range(1, 5)  # 4 attacks
    ]
    output_dir = tmp_path / "iter_tier2"
    output_dir.mkdir()

    candidates = generate_candidates_for_run(
        selected_attacks=selected_attacks,
        patent_text="test",
        output_dir=output_dir,
        k=3,
    )
    # 4 attacks × 3 candidates = 12
    assert len(candidates) == 12
    assert call_count["n"] == 4
    # tier2_candidates.json written
    assert (output_dir / "tier2_candidates.json").exists()
    written = json.loads((output_dir / "tier2_candidates.json").read_text())
    assert len(written) == 12

    # Each candidate has its targets_weakness set correctly
    attack_ids = {c["targets_weakness"] for c in candidates}
    assert attack_ids == {"attack_1", "attack_2", "attack_3", "attack_4"}


def test_generate_candidates_for_run_handles_attack_exception(monkeypatch, tmp_path):
    """If one attack's generator raises, the others still complete."""
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("Claude CLI timed out")
        return json.dumps([
            {
                "id": f"cand_ok_{call_count['n']}",
                "strategy": "narrow",
                "claim_refs": [1],
                "claim_text": "x",
                "rationale": "y",
            }
        ])

    monkeypatch.setattr("run_tier2_claim.call_claude_cli", fake_cli)

    selected_attacks = [
        {"id": f"attack_{i}", "claim_refs": [1], "finding": "x", "recommended_direction": "y"}
        for i in range(1, 4)
    ]
    output_dir = tmp_path / "iter_tier2_err"
    output_dir.mkdir()

    candidates = generate_candidates_for_run(
        selected_attacks=selected_attacks,
        patent_text="x",
        output_dir=output_dir,
        k=1,
    )
    # 3 attacks: 2 successful (1 candidate each) + 1 exception (1 error stub) = 3
    assert len(candidates) == 3
    errors = [c for c in candidates if c.get("strategy") == "error"]
    assert len(errors) == 1
    # The attack that errored should still appear in targets_weakness
    error_target = errors[0]["targets_weakness"]
    assert error_target in {"attack_1", "attack_2", "attack_3"}


def test_generate_candidates_for_run_empty_selected(tmp_path):
    """Empty selected list should write empty tier2_candidates.json and return []."""
    output_dir = tmp_path / "iter_empty"
    output_dir.mkdir()

    candidates = generate_candidates_for_run(
        selected_attacks=[],
        patent_text="x",
        output_dir=output_dir,
        k=3,
    )
    assert candidates == []
    path = output_dir / "tier2_candidates.json"
    assert path.exists()
    assert json.loads(path.read_text()) == []


@pytest.mark.integration
def test_generate_candidates_against_real_attack():
    """End-to-end: real Claude CLI call produces at least 1 candidate for a realistic attack."""
    attack = {
        "id": "alice_claim_15",
        "claim_refs": [15],
        "category": "101",
        "finding": "Claim 15 contains negative limitations without strong spec anchor; likely 101 rejection risk",
        "recommended_direction": "Rewrite negative limitations as positive structural recitations",
    }
    # Small patent excerpt to keep the integration test fast
    patent_text = "Claim 15. A method comprising ... [stub for integration test]"
    candidates = generate_candidates_for_attack(attack, patent_text=patent_text, k=2)
    assert len(candidates) >= 1
    assert all(c.get("targets_weakness") == "alice_claim_15" for c in candidates)
