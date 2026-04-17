"""Tests for judge.py — Tier 1 candidate scorer."""
import json
import pytest
from pathlib import Path

from judge import (
    CandidateScore,
    DIMENSIONS,
    MAX_PER_DIMENSION,
    MAX_TOTAL,
    PROMOTE_TOTAL_MIN,
    CONSIDER_TOTAL_MIN,
    DROP_IF_ANY_DIM_LE,
    _parse_judge_response,
    score_candidates,
    DEFAULT_BATCH_SIZE,
)


def test_dimensions_constant():
    assert set(DIMENSIONS) == {"adoption", "standards", "completeness", "correctness"}
    assert MAX_PER_DIMENSION == 25
    assert MAX_TOTAL == 100


def test_candidate_score_dataclass():
    cs = CandidateScore(candidate_id="c1")
    assert cs.candidate_id == "c1"
    assert cs.total == 0
    assert cs.verdict == "drop"


def test_candidate_score_finalize_promote():
    cs = CandidateScore(
        candidate_id="a",
        adoption=20, standards=20, completeness=20, correctness=20,
    )
    cs.finalize()
    assert cs.total == 80
    assert cs.verdict == "promote"


def test_candidate_score_finalize_consider():
    cs = CandidateScore(
        candidate_id="b",
        adoption=16, standards=16, completeness=16, correctness=16,
    )
    cs.finalize()
    assert cs.total == 64
    assert cs.verdict == "consider"


def test_candidate_score_finalize_drop_low_total():
    cs = CandidateScore(
        candidate_id="c",
        adoption=10, standards=10, completeness=10, correctness=10,
    )
    cs.finalize()
    assert cs.total == 40
    assert cs.verdict == "drop"


def test_candidate_score_finalize_drop_any_dim_low():
    """Any dimension <= 8 forces drop even if total >= 75."""
    cs = CandidateScore(
        candidate_id="d",
        adoption=8, standards=25, completeness=25, correctness=25,
    )
    cs.finalize()
    assert cs.total == 83
    assert cs.verdict == "drop"  # adoption <= 8


def test_parse_judge_response_valid():
    raw = '''[
        {"id": "c1", "adoption": 20, "standards": 18, "completeness": 22, "correctness": 15},
        {"id": "c2", "adoption": 10, "standards": 10, "completeness": 10, "correctness": 10}
    ]'''
    scores = _parse_judge_response(raw)
    assert len(scores) == 2
    assert scores[0].candidate_id == "c1"
    assert scores[0].adoption == 20
    assert scores[0].total == 75
    assert scores[0].verdict == "promote"
    assert scores[1].verdict == "drop"


def test_parse_judge_response_rejects_missing_dimension():
    raw = '[{"id": "c1", "adoption": 10, "standards": 10}]'
    with pytest.raises(ValueError, match="missing"):
        _parse_judge_response(raw)


def test_parse_judge_response_rejects_out_of_range():
    raw = '[{"id": "c1", "adoption": 30, "standards": 10, "completeness": 10, "correctness": 10}]'
    with pytest.raises(ValueError, match="out of range"):
        _parse_judge_response(raw)


def test_parse_judge_response_missing_id():
    raw = '[{"adoption": 10, "standards": 10, "completeness": 10, "correctness": 10}]'
    with pytest.raises(ValueError, match="missing 'id'"):
        _parse_judge_response(raw)


def test_score_candidates_batching(monkeypatch):
    """Verify candidates are processed in batches of DEFAULT_BATCH_SIZE."""
    call_count = {"n": 0}
    batch_sizes_seen = []

    def fake_cli(prompt, *, model="sonnet", timeout=240):
        call_count["n"] += 1
        # Count how many candidates are in this batch by parsing the prompt
        # The prompt says "(N total)"
        import re
        m = re.search(r"\((\d+) total\)", prompt)
        n = int(m.group(1)) if m else 1
        batch_sizes_seen.append(n)
        scores = [
            {"id": f"c{i}", "adoption": 15, "standards": 15, "completeness": 15, "correctness": 15}
            for i in range(n)
        ]
        return json.dumps(scores)

    monkeypatch.setattr("judge.call_claude_cli", fake_cli)

    # 8 candidates → should batch into ceil(8/6) = 2 batches (6 + 2)
    candidates = [
        {"id": f"c{i}", "title": f"Cand {i}", "description": "test", "dimension": "adoption"}
        for i in range(8)
    ]
    scores = score_candidates(candidates, batch_size=6)
    assert len(scores) == 8
    assert call_count["n"] == 2
    assert batch_sizes_seen == [6, 2]


def test_score_candidates_empty():
    """Empty input returns empty output."""
    assert score_candidates([]) == []


def test_rubric_file_exists():
    rubric_path = Path(__file__).parent / "rubrics" / "tier1_rubric.md"
    assert rubric_path.exists(), f"rubric file missing: {rubric_path}"
    content = rubric_path.read_text()
    for dim in DIMENSIONS:
        assert dim.upper() in content, f"rubric missing dimension: {dim}"
