"""Tests for run_tier1_attack.py — parallel adversarial reviewer fanout."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from run_tier1_attack import (
    run_tier1,
    PERSONAS_PATH,
    PRIOR_ART_PATH,
    CASE_LAW_PATH,
    _run_persona,
    _load_seed_data,
)


def test_seed_paths_exist():
    # These files must exist from Task 1
    assert PERSONAS_PATH.exists()
    assert PRIOR_ART_PATH.exists()
    assert CASE_LAW_PATH.exists()


def test_load_seed_data_returns_all_three():
    personas, prior_art, case_law = _load_seed_data()
    assert len(personas) == 6
    assert len(prior_art) >= 15
    assert len(case_law) >= 12
    # Shape checks
    assert "id" in personas[0] and "role" in personas[0] and "focus" in personas[0]
    assert "id" in prior_art[0] and "what_it_teaches" in prior_art[0]
    assert "id" in case_law[0] and "holding" in case_law[0]


def test_run_persona_parses_attacks(monkeypatch):
    """Mock call_claude_cli and confirm _run_persona returns structured attacks."""
    mock_response = '''Here are my findings.
[
  {
    "id": "examiner_strict_claim1_abstract",
    "claim_refs": [1],
    "category": "101",
    "finding": "Claim 1(d) reads as abstract state write without technical anchor",
    "recommended_direction": "Tie step (d) to specific circuit constraint output",
    "evidence": "See claim language at lines 467-468"
  }
]'''

    def fake_cli(prompt, *, model="opus", timeout=360):
        return mock_response

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)

    persona = {"id": "examiner_strict", "role": "USPTO examiner", "focus": ["101"]}
    attacks = _run_persona(persona, patent_text="...", prior_art=[], case_law=[])
    assert len(attacks) == 1
    assert attacks[0]["persona"] == "examiner_strict"
    assert attacks[0]["claim_refs"] == [1]
    assert attacks[0]["category"] == "101"


def test_run_persona_gracefully_handles_parse_error(monkeypatch):
    """If the CLI returns unparseable output, _run_persona should return a single error entry, not crash."""
    def fake_cli(prompt, *, model="opus", timeout=360):
        return "The patent looks fine, no issues to report."  # No JSON array

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)

    persona = {"id": "examiner_strict", "role": "...", "focus": ["101"]}
    attacks = _run_persona(persona, patent_text="...", prior_art=[], case_law=[])
    assert len(attacks) == 1
    assert attacks[0]["persona"] == "examiner_strict"
    assert attacks[0]["category"] == "meta"
    assert "parse_error" in attacks[0]["id"]
    assert "failed to parse" in attacks[0]["finding"].lower()


def test_run_persona_preserves_persona_id_when_llm_omits(monkeypatch):
    """LLM might omit the 'persona' field; _run_persona should backfill it."""
    def fake_cli(prompt, *, model="opus", timeout=360):
        return '''[
          {"id": "xyz", "claim_refs": [1], "category": "101",
           "finding": "X", "recommended_direction": "Y", "evidence": "Z"}
        ]'''

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)

    persona = {"id": "examiner_strict", "role": "...", "focus": ["101"]}
    attacks = _run_persona(persona, patent_text="...", prior_art=[], case_law=[])
    assert attacks[0]["persona"] == "examiner_strict"


def test_run_tier1_dispatches_all_personas(monkeypatch, tmp_path):
    """Verify run_tier1 dispatches every persona and writes tier1_attacks.json."""
    call_count = {"n": 0}
    personas_seen: list[str] = []

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        # Extract persona role from prompt to know which persona we're handling
        # The prompt contains "playing the role: <role>"
        for line in prompt.splitlines():
            if "playing the role:" in line:
                personas_seen.append(line.split("playing the role:")[1].strip())
                break
        return '''[{"id": "test_attack", "claim_refs": [1], "category": "101",
          "finding": "test", "recommended_direction": "test", "evidence": "test"}]'''

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)

    def fake_rank(attacks, context_patent_text, *, model="sonnet", timeout=240):
        return []  # No scoring in this test — just verify persona dispatch
    monkeypatch.setattr("run_tier1_attack.rank_attacks", fake_rank)

    output_dir = tmp_path / "iter_001"
    output_dir.mkdir()

    result = run_tier1(patent_text="test patent text", output_dir=output_dir)

    # All 6 personas dispatched
    assert call_count["n"] == 6
    # tier1_attacks.json written
    attacks_path = output_dir / "tier1_attacks.json"
    assert attacks_path.exists()
    attacks = json.loads(attacks_path.read_text())
    # 6 personas × 1 attack each = 6 attacks
    assert len(attacks) == 6
    # All personas represented
    persona_ids = {a["persona"] for a in attacks}
    assert len(persona_ids) == 6


def test_run_tier1_handles_persona_exception_without_crashing(monkeypatch, tmp_path):
    """If one persona's CLI call raises, run_tier1 should still complete with the others."""
    call_count = {"n": 0}

    def fake_cli(prompt, *, model="opus", timeout=360):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("Claude CLI failed: network issue")
        return '''[{"id": "ok", "claim_refs": [1], "category": "101",
          "finding": "ok", "recommended_direction": "ok", "evidence": "ok"}]'''

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)

    def fake_rank(attacks, context_patent_text, *, model="sonnet", timeout=240):
        return []  # No scoring in this test — just verify exception handling
    monkeypatch.setattr("run_tier1_attack.rank_attacks", fake_rank)

    output_dir = tmp_path / "iter_002"
    output_dir.mkdir()

    result = run_tier1(patent_text="x", output_dir=output_dir)
    attacks = json.loads((output_dir / "tier1_attacks.json").read_text())
    # 5 succeeded + 1 exception stub = 6 entries
    assert len(attacks) == 6
    # One should be an error stub
    errors = [a for a in attacks if a.get("category") == "meta"]
    assert len(errors) == 1
    assert "exception" in errors[0]["id"]


from dataclasses import asdict

from judge import AttackScore


def test_run_tier1_produces_scored_attacks(monkeypatch, tmp_path):
    """After Task 5 wiring: tier1_scored.json is written with severity/priority fields merged in."""
    # 2 attacks returned by personas (simplified: 2 personas × 1 attack each)
    persona_responses = iter([
        '[{"id": "p1_a1", "claim_refs": [1], "category": "101",'
        ' "finding": "x", "recommended_direction": "y", "evidence": "z"}]',
        '[{"id": "p2_a1", "claim_refs": [9], "category": "103",'
        ' "finding": "a", "recommended_direction": "b", "evidence": "c"}]',
    ] * 3)  # 6 personas

    def fake_cli(prompt, *, model="opus", timeout=360):
        return next(persona_responses)

    # Judge returns severity/specificity/remediability for each attack
    def fake_rank(attacks, context_patent_text, *, model="sonnet", timeout=240):
        scores = []
        for i, a in enumerate(attacks):
            # Alternate high and low priority to ensure filtering works
            if i % 2 == 0:
                s = AttackScore(attack_id=a["id"], severity=9, specificity=8, remediability=6)
            else:
                s = AttackScore(attack_id=a["id"], severity=3, specificity=3, remediability=3)
            s.finalize()
            scores.append(s)
        return scores

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1_attack.rank_attacks", fake_rank)

    output_dir = tmp_path / "iter_scored"
    output_dir.mkdir()
    run_tier1(patent_text="test", output_dir=output_dir)

    # tier1_attacks.json still exists (from Task 4)
    assert (output_dir / "tier1_attacks.json").exists()

    # tier1_scored.json has attacks merged with scores
    scored_path = output_dir / "tier1_scored.json"
    assert scored_path.exists()
    scored = json.loads(scored_path.read_text())
    assert len(scored) == 6
    for s in scored:
        # Original attack fields still present
        assert "id" in s and "persona" in s and "finding" in s
        # Judge fields merged
        assert "severity" in s
        assert "specificity" in s
        assert "remediability" in s
        assert "total" in s
        assert "priority" in s
        assert s["priority"] in {"high", "medium", "low"}


def test_run_tier1_writes_selected_high_priority(monkeypatch, tmp_path):
    """tier1_selected.json contains only 'high' priority attacks (up to 8)."""
    persona_responses = iter([
        '[{"id": "p1_a1", "claim_refs": [1], "category": "101",'
        ' "finding": "x", "recommended_direction": "y", "evidence": "z"}]',
    ] * 6)

    def fake_cli(prompt, *, model="opus", timeout=360):
        return next(persona_responses)

    def fake_rank(attacks, context_patent_text, *, model="sonnet", timeout=240):
        # Make half high-priority, half low
        scores = []
        for i, a in enumerate(attacks):
            if i < 3:
                s = AttackScore(attack_id=a["id"], severity=9, specificity=8, remediability=6)
            else:
                s = AttackScore(attack_id=a["id"], severity=3, specificity=3, remediability=3)
            s.finalize()
            scores.append(s)
        return scores

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1_attack.rank_attacks", fake_rank)

    output_dir = tmp_path / "iter_selected"
    output_dir.mkdir()
    run_tier1(patent_text="x", output_dir=output_dir)

    selected_path = output_dir / "tier1_selected.json"
    assert selected_path.exists()
    selected = json.loads(selected_path.read_text())
    # Exactly 3 are high priority in our mock
    assert len(selected) == 3
    for a in selected:
        assert a["priority"] == "high"


def test_run_tier1_selected_capped_at_max_n(monkeypatch, tmp_path):
    """If more than 8 high-priority attacks exist, only top 8 by total score are selected."""
    # Need more than 8 attacks total; configure 3 attacks per persona × 6 personas = 18
    many_attacks = json.dumps([
        {"id": f"p_a{i}", "claim_refs": [1], "category": "101",
         "finding": f"finding {i}", "recommended_direction": "y", "evidence": "z"}
        for i in range(3)
    ])

    def fake_cli(prompt, *, model="opus", timeout=360):
        return many_attacks

    def fake_rank(attacks, context_patent_text, *, model="sonnet", timeout=240):
        # All high priority, but with varying total scores
        scores = []
        for i, a in enumerate(attacks):
            # total varies from 22 to 30 (all >= 22 so all 'high')
            sev = min(10, 9 + (i % 2))
            spec = min(10, 8 + ((i // 2) % 3))
            rem = min(10, 6 + (i % 3))
            s = AttackScore(attack_id=a["id"], severity=sev, specificity=spec, remediability=rem)
            s.finalize()
            scores.append(s)
        return scores

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1_attack.rank_attacks", fake_rank)

    output_dir = tmp_path / "iter_capped"
    output_dir.mkdir()
    run_tier1(patent_text="x", output_dir=output_dir)

    selected = json.loads((output_dir / "tier1_selected.json").read_text())
    # Should be capped at 8 even though all 18 are high
    assert len(selected) == 8
    # Should be sorted by total score (descending) — highest scores first
    totals = [s["total"] for s in selected]
    assert totals == sorted(totals, reverse=True)


def test_run_tier1_selected_empty_when_no_high_priority(monkeypatch, tmp_path):
    persona_responses = iter([
        '[{"id": "p_a1", "claim_refs": [1], "category": "101",'
        ' "finding": "x", "recommended_direction": "y", "evidence": "z"}]',
    ] * 6)

    def fake_cli(prompt, *, model="opus", timeout=360):
        return next(persona_responses)

    def fake_rank(attacks, context_patent_text, *, model="sonnet", timeout=240):
        # All low priority
        return [
            (lambda s: (s.finalize(), s)[1])(
                AttackScore(attack_id=a["id"], severity=3, specificity=3, remediability=3)
            )
            for a in attacks
        ]

    monkeypatch.setattr("run_tier1_attack.call_claude_cli", fake_cli)
    monkeypatch.setattr("run_tier1_attack.rank_attacks", fake_rank)

    output_dir = tmp_path / "iter_no_high"
    output_dir.mkdir()
    run_tier1(patent_text="x", output_dir=output_dir)

    selected = json.loads((output_dir / "tier1_selected.json").read_text())
    assert selected == []


@pytest.mark.integration
def test_run_tier1_against_real_patent(tmp_path):
    """End-to-end: all 6 personas attack the real patent via Claude CLI."""
    patent_path = Path(__file__).parent.parent / "drafts" / "provisional-patent-identityos.md"
    patent_text = patent_path.read_text()

    output_dir = tmp_path / "iter_real"
    output_dir.mkdir()

    run_tier1(patent_text=patent_text, output_dir=output_dir)
    attacks = json.loads((output_dir / "tier1_attacks.json").read_text())
    # At least 4 of 6 personas should produce findings on the real patent
    persona_ids = {a["persona"] for a in attacks if a.get("category") != "meta"}
    assert len(persona_ids) >= 4
