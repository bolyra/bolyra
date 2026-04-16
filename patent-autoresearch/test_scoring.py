"""Tests for scoring.py.

The integration tests call Claude CLI (costs time + $). They are gated behind
@pytest.mark.integration so normal test runs are fast.
"""
import json
import pytest
from pathlib import Path

from scoring import (
    score_candidate,
    DimensionScore,
    CandidateScore,
    DIMENSIONS,
    MAX_PER_DIMENSION,
    MAX_TOTAL,
    _parse_judge_response,
)


def test_dimensions_constant():
    assert set(DIMENSIONS) == {"alice_101", "obviousness_103", "support_112", "design_around", "scope"}
    assert MAX_PER_DIMENSION == 20
    assert MAX_TOTAL == 100


def test_dimension_score_dataclass():
    ds = DimensionScore(name="alice_101", points=15, evidence="strong concrete crypto", critique="could be tighter")
    assert ds.name == "alice_101"
    assert ds.points == 15
    assert ds.max_points == 20
    assert ds.evidence == "strong concrete crypto"


def test_candidate_score_dataclass():
    cs = CandidateScore(candidate_id="c1")
    assert cs.candidate_id == "c1"
    assert cs.dimensions == {}
    assert cs.total == 0
    assert cs.verdict == "reject"


def test_parse_judge_response_all_dimensions():
    raw = '''Some preamble.
{
  "alice_101": {"points": 15, "evidence": "A", "critique": "B"},
  "obviousness_103": {"points": 12, "evidence": "C", "critique": "D"},
  "support_112": {"points": 18, "evidence": "E", "critique": "F"},
  "design_around": {"points": 10, "evidence": "G", "critique": "H"},
  "scope": {"points": 14, "evidence": "I", "critique": "J"}
}
Some postamble.'''
    dims = _parse_judge_response(raw)
    assert set(dims.keys()) == set(DIMENSIONS)
    assert dims["alice_101"].points == 15
    assert dims["scope"].points == 14
    assert dims["obviousness_103"].evidence == "C"


def test_parse_judge_response_rejects_out_of_range_points():
    raw = '''{"alice_101": {"points": 25, "evidence": "x", "critique": "x"},
             "obviousness_103": {"points": 10, "evidence": "x", "critique": "x"},
             "support_112": {"points": 10, "evidence": "x", "critique": "x"},
             "design_around": {"points": 10, "evidence": "x", "critique": "x"},
             "scope": {"points": 10, "evidence": "x", "critique": "x"}}'''
    with pytest.raises(ValueError, match="out of range"):
        _parse_judge_response(raw)


def test_parse_judge_response_rejects_missing_dimension():
    raw = '''{"alice_101": {"points": 10, "evidence": "x", "critique": "x"}}'''
    with pytest.raises((KeyError, ValueError)):
        _parse_judge_response(raw)


def test_rubric_file_exists():
    rubric_path = Path(__file__).parent / "rubrics" / "tier2_claim_rubric.md"
    assert rubric_path.exists(), f"rubric file missing: {rubric_path}"
    content = rubric_path.read_text()
    for dim in DIMENSIONS:
        assert dim in content, f"rubric missing dimension: {dim}"


def test_candidate_score_computes_verdict_from_total():
    # apply: total >= 80
    cs_apply = CandidateScore(
        candidate_id="a",
        dimensions={d: DimensionScore(d, 16, evidence="x", critique="x") for d in DIMENSIONS},
    )
    cs_apply.finalize()
    assert cs_apply.total == 80
    assert cs_apply.verdict == "apply"

    # consider: 60-79
    cs_consider = CandidateScore(
        candidate_id="c",
        dimensions={d: DimensionScore(d, 13, evidence="x", critique="x") for d in DIMENSIONS},
    )
    cs_consider.finalize()
    assert cs_consider.total == 65
    assert cs_consider.verdict == "consider"

    # reject: < 60
    cs_reject = CandidateScore(
        candidate_id="r",
        dimensions={d: DimensionScore(d, 10, evidence="x", critique="x") for d in DIMENSIONS},
    )
    cs_reject.finalize()
    assert cs_reject.total == 50
    assert cs_reject.verdict == "reject"


def test_verdict_rejects_if_any_dimension_too_low():
    # total would be 80 (apply), but one dim is 3 (≤ 4 threshold → reject per rubric)
    dims = {d: DimensionScore(d, 19, evidence="x", critique="x") for d in DIMENSIONS}
    dims["scope"] = DimensionScore("scope", 4, evidence="x", critique="x")
    cs = CandidateScore(candidate_id="borderline", dimensions=dims)
    cs.finalize()
    assert cs.total == 19 * 4 + 4
    assert cs.verdict == "reject"  # any dim ≤ 4 forces reject


@pytest.mark.integration
def test_score_candidate_returns_all_five_dimensions():
    candidate = {
        "id": "test_candidate_1",
        "claim_text": "A method comprising storing a cryptographic commitment on a blockchain and verifying a zero-knowledge proof of membership.",
        "rationale": "Narrows 101 risk by anchoring to concrete cryptographic operations.",
        "targets_weakness": "W1",
    }
    score = score_candidate(candidate, context_patent_text="(patent excerpt...)", context_priorart=[])
    assert isinstance(score, CandidateScore)
    assert set(score.dimensions.keys()) == set(DIMENSIONS)
    for dim_score in score.dimensions.values():
        assert 0 <= dim_score.points <= MAX_PER_DIMENSION
    assert 0 <= score.total <= MAX_TOTAL
    assert score.verdict in {"apply", "consider", "reject"}


@pytest.mark.integration
def test_score_candidate_returns_evidence():
    candidate = {"id": "t", "claim_text": "A method...", "rationale": "Fixes X.", "targets_weakness": "W1"}
    score = score_candidate(candidate, context_patent_text="...", context_priorart=[])
    for dim_score in score.dimensions.values():
        assert dim_score.evidence, "each dimension must have evidence"
        assert dim_score.critique, "each dimension must have critique"
