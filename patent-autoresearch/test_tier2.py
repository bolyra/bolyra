"""Tests for run_tier2_claim.py — candidate claim generation + (Task 7) scoring."""
import json
import pytest
from pathlib import Path

from run_tier2_claim import (
    generate_candidates_for_attack,
    generate_candidates_for_run,
    DEFAULT_K,
)

from dataclasses import asdict

from scoring import CandidateScore, DimensionScore, DIMENSIONS
from run_tier2_claim import score_and_pick_winners, MIN_WINNER_TOTAL


def _make_candidate_score(candidate_id: str, total: int, verdict: str = None) -> CandidateScore:
    """Helper: build a fake CandidateScore with uniform per-dim points summing to total."""
    per_dim = total // len(DIMENSIONS)
    remainder = total - per_dim * len(DIMENSIONS)
    dims = {}
    for i, d in enumerate(DIMENSIONS):
        pts = per_dim + (1 if i < remainder else 0)
        dims[d] = DimensionScore(name=d, points=pts, evidence="x", critique="y")
    cs = CandidateScore(candidate_id=candidate_id, dimensions=dims)
    cs.finalize()
    if verdict is not None:
        cs.verdict = verdict  # override for tests that explicitly test the reject-by-low-dim path
    return cs


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


def test_score_and_pick_winners_writes_scored_and_winners(monkeypatch, tmp_path):
    """Happy path: 2 candidates per weakness, one wins per weakness."""
    candidates = [
        {"id": "c1", "strategy": "narrow", "claim_text": "a", "rationale": "r1", "targets_weakness": "w1"},
        {"id": "c2", "strategy": "positive_structural", "claim_text": "b", "rationale": "r2", "targets_weakness": "w1"},
        {"id": "c3", "strategy": "narrow", "claim_text": "c", "rationale": "r3", "targets_weakness": "w2"},
        {"id": "c4", "strategy": "dependent_claim", "claim_text": "d", "rationale": "r4", "targets_weakness": "w2"},
    ]

    scores_by_id = {
        "c1": _make_candidate_score("c1", 85),   # apply
        "c2": _make_candidate_score("c2", 70),   # consider
        "c3": _make_candidate_score("c3", 90),   # apply
        "c4": _make_candidate_score("c4", 65),   # consider
    }

    def fake_score(c, context_patent_text, context_priorart):
        return scores_by_id[c["id"]]

    monkeypatch.setattr("run_tier2_claim.score_candidate", fake_score)

    output_dir = tmp_path / "iter_winners"
    output_dir.mkdir()

    winners = score_and_pick_winners(
        candidates=candidates,
        patent_text="patent",
        prior_art=[],
        output_dir=output_dir,
    )

    # 2 weaknesses, one winner each
    assert len(winners) == 2
    winner_ids = {w["id"] for w in winners}
    # c1 (85) beats c2 (70) for w1
    # c3 (90) beats c4 (65) for w2
    assert winner_ids == {"c1", "c3"}

    # tier2_scored.json has all 4 candidates
    scored_path = output_dir / "tier2_scored.json"
    assert scored_path.exists()
    scored = json.loads(scored_path.read_text())
    assert len(scored) == 4
    for s in scored:
        assert "score" in s
        assert "total" in s["score"]
        assert "verdict" in s["score"]

    # tier2_winners.json matches
    winners_path = output_dir / "tier2_winners.json"
    assert winners_path.exists()
    assert json.loads(winners_path.read_text()) == winners


def test_score_and_pick_winners_rejects_below_threshold(monkeypatch, tmp_path):
    """Candidates with total < 60 are not eligible as winners."""
    candidates = [
        {"id": "c1", "strategy": "narrow", "claim_text": "a", "rationale": "r1", "targets_weakness": "w1"},
        {"id": "c2", "strategy": "narrow", "claim_text": "b", "rationale": "r2", "targets_weakness": "w1"},
    ]

    def fake_score(c, context_patent_text, context_priorart):
        # Both below threshold
        return _make_candidate_score(c["id"], 45)

    monkeypatch.setattr("run_tier2_claim.score_candidate", fake_score)

    output_dir = tmp_path / "iter_noreject"
    output_dir.mkdir()

    winners = score_and_pick_winners(candidates, patent_text="p", prior_art=[], output_dir=output_dir)
    assert winners == []

    # tier2_scored.json still has both candidates
    scored = json.loads((output_dir / "tier2_scored.json").read_text())
    assert len(scored) == 2


def test_score_and_pick_winners_picks_highest_per_weakness(monkeypatch, tmp_path):
    """Three candidates for one weakness: highest total wins."""
    candidates = [
        {"id": f"c{i}", "strategy": "narrow", "claim_text": str(i), "rationale": str(i), "targets_weakness": "w1"}
        for i in range(3)
    ]

    totals = {"c0": 70, "c1": 85, "c2": 78}

    def fake_score(c, context_patent_text, context_priorart):
        return _make_candidate_score(c["id"], totals[c["id"]])

    monkeypatch.setattr("run_tier2_claim.score_candidate", fake_score)

    output_dir = tmp_path / "iter_highest"
    output_dir.mkdir()

    winners = score_and_pick_winners(candidates, patent_text="p", prior_art=[], output_dir=output_dir)
    assert len(winners) == 1
    assert winners[0]["id"] == "c1"  # highest total (85)
    assert winners[0]["score"]["total"] == 85


def test_score_and_pick_winners_handles_score_exception(monkeypatch, tmp_path):
    """If scoring one candidate raises, that candidate gets a zero-score entry and doesn't win."""
    candidates = [
        {"id": "c1", "strategy": "narrow", "claim_text": "a", "rationale": "r", "targets_weakness": "w1"},
        {"id": "c2", "strategy": "narrow", "claim_text": "b", "rationale": "r", "targets_weakness": "w1"},
    ]

    def fake_score(c, context_patent_text, context_priorart):
        if c["id"] == "c1":
            raise RuntimeError("Claude CLI failed")
        return _make_candidate_score("c2", 80)

    monkeypatch.setattr("run_tier2_claim.score_candidate", fake_score)

    output_dir = tmp_path / "iter_score_err"
    output_dir.mkdir()

    winners = score_and_pick_winners(candidates, patent_text="p", prior_art=[], output_dir=output_dir)
    # c2 wins (80), c1 errored
    assert len(winners) == 1
    assert winners[0]["id"] == "c2"

    scored = json.loads((output_dir / "tier2_scored.json").read_text())
    assert len(scored) == 2
    c1_entry = next(s for s in scored if s["id"] == "c1")
    assert c1_entry["score"]["total"] == 0
    assert c1_entry["score"]["verdict"] == "reject"
    assert "error" in c1_entry["score"]


def test_score_and_pick_winners_skips_error_stubs(monkeypatch, tmp_path):
    """Error-stub candidates (strategy=='error') are not scored; they're skipped entirely."""
    score_calls = []

    def fake_score(c, context_patent_text, context_priorart):
        score_calls.append(c["id"])
        return _make_candidate_score(c["id"], 85)

    monkeypatch.setattr("run_tier2_claim.score_candidate", fake_score)

    candidates = [
        {"id": "cand_good", "strategy": "narrow", "claim_text": "x", "rationale": "y",
         "targets_weakness": "w1"},
        {"id": "cand_err", "strategy": "error", "claim_text": "", "rationale": "parse failed",
         "targets_weakness": "w2"},
    ]
    output_dir = tmp_path / "iter_skip_err"
    output_dir.mkdir()

    winners = score_and_pick_winners(candidates, patent_text="p", prior_art=[], output_dir=output_dir)
    # Only cand_good was scored
    assert score_calls == ["cand_good"]
    # Only one winner (cand_good)
    assert len(winners) == 1
    assert winners[0]["id"] == "cand_good"

    # But tier2_scored.json contains BOTH (error stub included with zero score for visibility)
    scored = json.loads((output_dir / "tier2_scored.json").read_text())
    assert len(scored) == 2
    err_entry = next(s for s in scored if s["id"] == "cand_err")
    assert err_entry["score"]["total"] == 0
    assert err_entry["score"]["verdict"] == "reject"


def test_score_and_pick_winners_empty(tmp_path):
    """No candidates → empty files, no winners."""
    output_dir = tmp_path / "iter_empty_tier2"
    output_dir.mkdir()
    winners = score_and_pick_winners([], patent_text="p", prior_art=[], output_dir=output_dir)
    assert winners == []
    assert json.loads((output_dir / "tier2_scored.json").read_text()) == []
    assert json.loads((output_dir / "tier2_winners.json").read_text()) == []


def test_min_winner_total_constant():
    """MIN_WINNER_TOTAL must match the scoring rubric's 'consider' threshold."""
    assert MIN_WINNER_TOTAL == 60
