"""Tests for baseline.py — whole-patent scorer."""
import json
import pytest

from baseline import score_baseline, _parse_baseline_response


def test_parse_baseline_response_valid():
    raw = '''Here is my assessment.
{
  "alice_101": {"points": 14, "per_claim": {"1": 15, "9": 14, "15": 12, "16": 15}, "critique": "C"},
  "obviousness_103": {"points": 12, "per_claim": {"1": 13, "9": 11, "15": 12, "16": 12}, "critique": "D"},
  "support_112": {"points": 18, "per_claim": {"1": 19, "9": 18, "15": 17, "16": 18}, "critique": "E"},
  "design_around": {"points": 10, "critique": "F"},
  "scope": {"points": 14, "critique": "G"},
  "total": 68
}'''
    result = _parse_baseline_response(raw)
    assert result["alice_101"]["points"] == 14
    assert result["alice_101"]["per_claim"]["15"] == 12
    assert result["total"] == 68


def test_parse_baseline_response_missing_key_raises():
    """Any missing top-level dimension or total → ValueError."""
    raw = '{"alice_101": {"points": 10, "critique": "x"}}'  # missing others
    with pytest.raises((ValueError, KeyError)):
        _parse_baseline_response(raw)


def test_parse_baseline_response_total_out_of_range():
    raw = '''{
      "alice_101": {"points": 30, "critique": "x"},
      "obviousness_103": {"points": 10, "critique": "x"},
      "support_112": {"points": 10, "critique": "x"},
      "design_around": {"points": 10, "critique": "x"},
      "scope": {"points": 10, "critique": "x"},
      "total": 150
    }'''
    with pytest.raises(ValueError, match="out of range"):
        _parse_baseline_response(raw)


def test_parse_baseline_handles_markdown_fence():
    raw = '''```json
{
  "alice_101": {"points": 14, "critique": "x"},
  "obviousness_103": {"points": 12, "critique": "x"},
  "support_112": {"points": 18, "critique": "x"},
  "design_around": {"points": 10, "critique": "x"},
  "scope": {"points": 14, "critique": "x"},
  "total": 68
}
```'''
    result = _parse_baseline_response(raw)
    assert result["total"] == 68


@pytest.mark.integration
def test_score_baseline_real_patent():
    """End-to-end: score the real patent via Claude CLI."""
    from pathlib import Path
    patent_path = Path(__file__).parent.parent / "drafts" / "provisional-patent-identityos.md"
    patent_text = patent_path.read_text()
    result = score_baseline(patent_text)
    assert "alice_101" in result
    assert "total" in result
    assert 0 <= result["total"] <= 100
