"""Tests for judge.py — Tier 1 attack prioritizer."""
import pytest
from pathlib import Path

from judge import (
    AttackScore,
    rank_attacks,
    _parse_judge_response,
    SEVERITY_HIGH_THRESHOLD,
    SEVERITY_MEDIUM_THRESHOLD,
)


def test_attack_score_priority_high():
    s = AttackScore(attack_id="a", severity=9, specificity=8, remediability=6)
    s.finalize()
    assert s.total == 23
    assert s.priority == "high"


def test_attack_score_priority_medium():
    s = AttackScore(attack_id="a", severity=6, specificity=5, remediability=5)
    s.finalize()
    assert s.total == 16
    assert s.priority == "medium"


def test_attack_score_priority_low():
    s = AttackScore(attack_id="a", severity=3, specificity=3, remediability=3)
    s.finalize()
    assert s.total == 9
    assert s.priority == "low"


def test_attack_score_boundary_high():
    # total = SEVERITY_HIGH_THRESHOLD should be high
    s = AttackScore(attack_id="a", severity=8, specificity=8, remediability=SEVERITY_HIGH_THRESHOLD - 16)
    s.finalize()
    assert s.total == SEVERITY_HIGH_THRESHOLD
    assert s.priority == "high"


def test_attack_score_boundary_medium():
    # total = SEVERITY_MEDIUM_THRESHOLD should be medium
    s = AttackScore(attack_id="a", severity=5, specificity=5, remediability=SEVERITY_MEDIUM_THRESHOLD - 10)
    s.finalize()
    assert s.total == SEVERITY_MEDIUM_THRESHOLD
    assert s.priority == "medium"


def test_attack_score_boundary_low():
    # total = SEVERITY_MEDIUM_THRESHOLD - 1 should be low
    s = AttackScore(attack_id="a", severity=5, specificity=5, remediability=SEVERITY_MEDIUM_THRESHOLD - 11)
    s.finalize()
    assert s.total == SEVERITY_MEDIUM_THRESHOLD - 1  # 14
    assert s.priority == "low"


def test_rubric_file_exists():
    rubric_path = Path(__file__).parent / "rubrics" / "tier1_attack_rubric.md"
    assert rubric_path.exists(), f"tier1 rubric missing: {rubric_path}"
    content = rubric_path.read_text()
    for dim in ("severity", "specificity", "remediability"):
        assert dim in content.lower(), f"rubric missing dimension: {dim}"


def test_parse_judge_response_happy_path():
    raw = '''Some prose before.
[
  {"id": "a1", "severity": 9, "specificity": 8, "remediability": 6},
  {"id": "a2", "severity": 4, "specificity": 5, "remediability": 7}
]
Some trailing notes.'''
    scores = _parse_judge_response(raw)
    assert len(scores) == 2
    assert scores[0].attack_id == "a1"
    assert scores[0].severity == 9
    assert scores[0].priority == "high"
    assert scores[1].attack_id == "a2"
    assert scores[1].priority in {"medium", "low"}


def test_parse_judge_response_rejects_out_of_range():
    raw = '[{"id": "a", "severity": 15, "specificity": 8, "remediability": 6}]'
    with pytest.raises(ValueError, match="out of range"):
        _parse_judge_response(raw)


def test_parse_judge_response_rejects_missing_field():
    raw = '[{"id": "a", "severity": 9, "specificity": 8}]'
    with pytest.raises(ValueError, match="missing 'remediability'"):
        _parse_judge_response(raw)


def test_parse_judge_response_handles_markdown_fence():
    raw = '''```json
[{"id": "a1", "severity": 5, "specificity": 5, "remediability": 5}]
```'''
    scores = _parse_judge_response(raw)
    assert len(scores) == 1
    assert scores[0].attack_id == "a1"


def test_parse_judge_response_raises_on_empty_array():
    raw = "[]"
    scores = _parse_judge_response(raw)
    assert scores == []


@pytest.mark.integration
def test_rank_attacks_returns_scored_entries():
    attacks = [
        {"id": "a1", "persona": "alice_specialist",
         "finding": "Claim 1 step (d) is pure abstract state write without technical anchor"},
        {"id": "a2", "persona": "obviousness_hunter",
         "finding": "Tornado Cash root history fully anticipates claim 6"},
    ]
    ranked = rank_attacks(attacks, context_patent_text="(patent excerpt...)")
    assert len(ranked) == 2
    for r in ranked:
        assert isinstance(r, AttackScore)
        assert 0 <= r.severity <= 10
        assert 0 <= r.specificity <= 10
        assert 0 <= r.remediability <= 10
        assert r.priority in {"high", "medium", "low"}
