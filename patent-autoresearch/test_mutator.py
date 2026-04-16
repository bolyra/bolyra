"""Tests for mutator.py — strict exact-string mutation applier."""
import json
import pytest
from pathlib import Path

from mutator import apply_mutation, apply_winners, MutationResult


def test_apply_mutation_replaces_exact_text():
    patent = "Claim 1. A method comprising: (a) foo; (b) bar."
    winner = {
        "original_language": "(a) foo;",
        "claim_text": "(a) foo with additional technical anchor;",
        "targets_weakness": "w1",
    }
    new_text = apply_mutation(patent, winner)
    assert "(a) foo with additional technical anchor;" in new_text
    assert "(b) bar." in new_text
    # The original text is gone
    assert patent != new_text


def test_apply_mutation_replaces_only_first_occurrence():
    """If original_language appears multiple times, only the first is replaced."""
    patent = "foo bar foo baz foo"
    winner = {
        "original_language": "foo",
        "claim_text": "FIRST",
        "targets_weakness": "w1",
    }
    new_text = apply_mutation(patent, winner)
    # First "foo" → "FIRST"; other two untouched
    assert new_text == "FIRST bar foo baz foo"


def test_apply_mutation_fails_loudly_on_missing_text():
    with pytest.raises(ValueError, match="not found"):
        apply_mutation(
            "patent text",
            {"original_language": "missing", "claim_text": "new", "targets_weakness": "w1"},
        )


def test_apply_mutation_error_includes_weakness_id():
    """The error should tell operator which weakness failed, for debuggability."""
    try:
        apply_mutation(
            "some text",
            {"original_language": "missing", "claim_text": "x", "targets_weakness": "w_alice_42"},
        )
        pytest.fail("Should have raised")
    except ValueError as e:
        assert "w_alice_42" in str(e)


def test_apply_mutation_preserves_surrounding_text():
    """Mutation should be surgical — only the original_language span is changed."""
    patent = "Before text.\n\nClaim 1. (a) old; (b) keep.\n\nAfter text."
    winner = {
        "original_language": "(a) old;",
        "claim_text": "(a) new with anchor;",
        "targets_weakness": "w1",
    }
    new_text = apply_mutation(patent, winner)
    assert "Before text." in new_text
    assert "(a) new with anchor;" in new_text
    assert "(b) keep." in new_text
    assert "After text." in new_text
    assert "(a) old;" not in new_text


def test_apply_winners_happy_path(tmp_path):
    """apply_winners writes the mutated patent, returns applied/skipped lists."""
    patent_path = tmp_path / "patent.md"
    patent_path.write_text("Claim 1. (a) foo; (b) bar; (c) baz.")

    output_path = tmp_path / "patent_after.md"

    winners = [
        {"id": "c1", "original_language": "(a) foo;", "claim_text": "(a) FOO;", "targets_weakness": "w1"},
        {"id": "c2", "original_language": "(b) bar;", "claim_text": "(b) BAR;", "targets_weakness": "w2"},
    ]

    result = apply_winners(patent_path, winners, output_path)
    assert isinstance(result, MutationResult)
    assert result.applied == ["c1", "c2"]
    assert result.skipped == []

    new_text = output_path.read_text()
    assert "(a) FOO;" in new_text
    assert "(b) BAR;" in new_text
    assert "(c) baz." in new_text


def test_apply_winners_skips_mismatch(tmp_path):
    """One good winner + one with missing original_language → good applied, bad skipped."""
    patent_path = tmp_path / "patent.md"
    patent_path.write_text("Claim 1. (a) foo; (b) bar.")
    output_path = tmp_path / "patent_after.md"

    winners = [
        {"id": "good", "original_language": "(a) foo;", "claim_text": "(a) FOO;", "targets_weakness": "w1"},
        {"id": "bad", "original_language": "does not exist", "claim_text": "x", "targets_weakness": "w2"},
    ]

    result = apply_winners(patent_path, winners, output_path)
    assert result.applied == ["good"]
    assert len(result.skipped) == 1
    assert result.skipped[0]["id"] == "bad"
    assert "not found" in result.skipped[0]["reason"].lower()

    new_text = output_path.read_text()
    assert "(a) FOO;" in new_text
    # bad mutation didn't apply
    assert "does not exist" not in new_text


def test_apply_winners_does_not_modify_source(tmp_path):
    """The source patent file is untouched; only output_path is written."""
    patent_path = tmp_path / "patent.md"
    original = "Claim 1. (a) foo;"
    patent_path.write_text(original)
    output_path = tmp_path / "patent_after.md"

    winners = [{"id": "c1", "original_language": "(a) foo;", "claim_text": "(a) FOO;",
                "targets_weakness": "w1"}]
    apply_winners(patent_path, winners, output_path)

    # Source is unchanged
    assert patent_path.read_text() == original
    # Output has the mutation
    assert output_path.read_text() == "Claim 1. (a) FOO;"


def test_apply_winners_empty(tmp_path):
    """No winners → output is a copy of input, no applied/skipped."""
    patent_path = tmp_path / "patent.md"
    original = "Claim 1. (a) foo;"
    patent_path.write_text(original)
    output_path = tmp_path / "patent_after.md"

    result = apply_winners(patent_path, [], output_path)
    assert result.applied == []
    assert result.skipped == []
    assert output_path.read_text() == original


def test_apply_winners_mutations_are_sequential(tmp_path):
    """Multiple mutations apply in order; later ones see the output of earlier ones.

    This is important because two winners could touch overlapping regions.
    The current design applies them sequentially in the order given — callers
    are responsible for ordering winners sensibly if overlap is a concern.
    """
    patent_path = tmp_path / "patent.md"
    patent_path.write_text("ORIGINAL TEXT A. ORIGINAL TEXT B.")
    output_path = tmp_path / "patent_after.md"

    winners = [
        {"id": "w1", "original_language": "ORIGINAL TEXT A", "claim_text": "REPLACED A",
         "targets_weakness": "weak1"},
        {"id": "w2", "original_language": "ORIGINAL TEXT B", "claim_text": "REPLACED B",
         "targets_weakness": "weak2"},
    ]
    result = apply_winners(patent_path, winners, output_path)
    assert result.applied == ["w1", "w2"]
    assert output_path.read_text() == "REPLACED A. REPLACED B."


def test_apply_winners_mutations_skipped_when_later_depends_on_earlier_miss(tmp_path):
    """If winner N fails, winner N+1 still gets to try (both are independent attempts).

    But if two winners both try to modify the same region and the second's
    original_language was the post-first-mutation state, the second will fail
    because we replay from the original.

    This test verifies: second winner is applied even after first is skipped.
    """
    patent_path = tmp_path / "patent.md"
    patent_path.write_text("(a) keep; (b) replace;")
    output_path = tmp_path / "patent_after.md"

    winners = [
        {"id": "bad", "original_language": "(c) missing;", "claim_text": "(c) new;",
         "targets_weakness": "w1"},
        {"id": "good", "original_language": "(b) replace;", "claim_text": "(b) REPLACED;",
         "targets_weakness": "w2"},
    ]
    result = apply_winners(patent_path, winners, output_path)
    assert result.applied == ["good"]
    assert result.skipped[0]["id"] == "bad"
    assert output_path.read_text() == "(a) keep; (b) REPLACED;"
