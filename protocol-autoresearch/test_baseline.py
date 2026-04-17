"""Tests for baseline.py — protocol state scorer."""
import json
import pytest

from baseline import (
    _parse_baseline_response,
    score_baseline,
    DIMENSIONS,
)
from scoring import MAX_PER_DIMENSION, MAX_TOTAL


def test_parse_baseline_valid():
    raw = json.dumps({
        "correctness": {"points": 15, "critique": "good"},
        "completeness": {"points": 18, "critique": "ok"},
        "adoption": {"points": 10, "critique": "needs work"},
        "standards": {"points": 12, "critique": "partial"},
        "total": 55,
    })
    data = _parse_baseline_response(raw)
    assert data["total"] == 55
    assert data["correctness"]["points"] == 15


def test_parse_baseline_missing_key():
    raw = json.dumps({
        "correctness": {"points": 15, "critique": "x"},
        "total": 15,
    })
    with pytest.raises(ValueError, match="missing key"):
        _parse_baseline_response(raw)


def test_parse_baseline_out_of_range():
    raw = json.dumps({
        "correctness": {"points": 30, "critique": "x"},
        "completeness": {"points": 10, "critique": "x"},
        "adoption": {"points": 10, "critique": "x"},
        "standards": {"points": 10, "critique": "x"},
        "total": 60,
    })
    with pytest.raises(ValueError, match="out of range"):
        _parse_baseline_response(raw)


def test_parse_baseline_missing_points():
    raw = json.dumps({
        "correctness": {"critique": "x"},
        "completeness": {"points": 10, "critique": "x"},
        "adoption": {"points": 10, "critique": "x"},
        "standards": {"points": 10, "critique": "x"},
        "total": 30,
    })
    with pytest.raises(ValueError, match="missing 'points'"):
        _parse_baseline_response(raw)


@pytest.mark.integration
def test_score_baseline_returns_all_dimensions():
    data = score_baseline()
    for dim in DIMENSIONS:
        assert dim in data
        assert 0 <= data[dim]["points"] <= MAX_PER_DIMENSION
    assert 0 <= data["total"] <= MAX_TOTAL
