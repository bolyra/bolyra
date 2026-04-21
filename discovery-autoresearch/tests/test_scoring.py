"""Tests for the opportunity scoring module."""

import pytest

from scoring import OpportunityScore, format_score_summary, score_opportunity


class TestVerdictPromote:
    """PROMOTE requires total >= 70 AND all dimensions >= 12."""

    def test_promote_exact_boundary(self):
        """70 total with all dims exactly at minimum (12) should not reach 70.
        Use values that sum to 70 with all >= 12."""
        # 18 + 18 + 18 + 16 = 70, all >= 12
        score = score_opportunity(18, 18, 18, 16, "BUILD_NOW")
        assert score.verdict == "PROMOTE"
        assert score.total == 70

    def test_promote_high_scores(self):
        score = score_opportunity(25, 25, 25, 25, "BUILD_NOW")
        assert score.verdict == "PROMOTE"
        assert score.total == 100

    def test_promote_all_dims_at_minimum(self):
        """All dims at 12 = 48 total, which is < 70 so this is actually DROP (< 50)."""
        score = score_opportunity(12, 12, 12, 12, "BUILD_NOW")
        assert score.verdict == "DROP"  # total=48 < 50

    def test_promote_barely_above_boundary(self):
        # 18 + 18 + 18 + 17 = 71
        score = score_opportunity(18, 18, 18, 17, "GREY_ZONE")
        assert score.verdict == "PROMOTE"
        assert score.total == 71


class TestVerdictConsider:
    """CONSIDER: total 50-69, OR total >= 70 but a dim < 12."""

    def test_consider_mid_range(self):
        score = score_opportunity(15, 15, 15, 15, "BUILD_NOW")
        assert score.verdict == "CONSIDER"
        assert score.total == 60

    def test_consider_at_50(self):
        # 13 + 13 + 13 + 11 = 50 — but 11 < 12, still CONSIDER if no dim <= 5
        score = score_opportunity(13, 13, 13, 11, "BUILD_NOW")
        assert score.verdict == "CONSIDER"
        assert score.total == 50

    def test_consider_at_69(self):
        # 18 + 18 + 18 + 15 = 69
        score = score_opportunity(18, 18, 18, 15, "BUILD_NOW")
        assert score.verdict == "CONSIDER"
        assert score.total == 69

    def test_consider_high_total_but_weak_dim(self):
        """Total >= 70 but one dim < 12 -> CONSIDER, not PROMOTE."""
        # 25 + 20 + 20 + 11 = 76, but 11 < 12
        score = score_opportunity(25, 20, 20, 11, "WAIT_FOR_EAD")
        assert score.verdict == "CONSIDER"
        assert score.total == 76


class TestVerdictDrop:
    """DROP: total < 50 OR any dimension <= 5."""

    def test_drop_low_total(self):
        score = score_opportunity(10, 10, 10, 10, "BUILD_NOW")
        assert score.verdict == "DROP"
        assert score.total == 40

    def test_drop_at_49(self):
        # 13 + 12 + 12 + 12 = 49
        score = score_opportunity(13, 12, 12, 12, "BUILD_NOW")
        assert score.verdict == "DROP"
        assert score.total == 49

    def test_drop_any_dim_at_5(self):
        """A dimension at exactly 5 triggers DROP regardless of total."""
        # 25 + 25 + 25 + 5 = 80, but feasibility=5 -> DROP
        score = score_opportunity(25, 25, 25, 5, "BUILD_NOW")
        assert score.verdict == "DROP"
        assert score.total == 80

    def test_drop_any_dim_below_5(self):
        # 25 + 25 + 25 + 3 = 78, feasibility=3 -> DROP
        score = score_opportunity(25, 25, 25, 3, "BUILD_NOW")
        assert score.verdict == "DROP"
        assert score.total == 78

    def test_drop_zero_dim(self):
        score = score_opportunity(0, 20, 20, 20, "BUILD_NOW")
        assert score.verdict == "DROP"

    def test_drop_all_zeros(self):
        score = score_opportunity(0, 0, 0, 0, "BUILD_NOW")
        assert score.verdict == "DROP"
        assert score.total == 0


class TestEADClassification:
    """EAD classification is stored but does not affect verdict."""

    def test_build_now(self):
        score = score_opportunity(20, 20, 20, 20, "BUILD_NOW")
        assert score.ead_classification == "BUILD_NOW"

    def test_wait_for_ead(self):
        score = score_opportunity(20, 20, 20, 20, "WAIT_FOR_EAD")
        assert score.ead_classification == "WAIT_FOR_EAD"

    def test_grey_zone(self):
        score = score_opportunity(20, 20, 20, 20, "GREY_ZONE")
        assert score.ead_classification == "GREY_ZONE"

    def test_invalid_classification(self):
        with pytest.raises(ValueError, match="ead_classification"):
            score_opportunity(20, 20, 20, 20, "INVALID")


class TestInputValidation:
    """Out-of-range dimensions should raise ValueError."""

    def test_negative_demand(self):
        with pytest.raises(ValueError, match="demand"):
            score_opportunity(-1, 20, 20, 20, "BUILD_NOW")

    def test_over_25(self):
        with pytest.raises(ValueError, match="timing"):
            score_opportunity(20, 26, 20, 20, "BUILD_NOW")


class TestFormatScoreSummary:
    """format_score_summary produces readable output."""

    def test_contains_verdict(self):
        score = score_opportunity(20, 20, 20, 20, "BUILD_NOW")
        summary = format_score_summary(score)
        assert "PROMOTE" in summary
        assert "80/100" in summary

    def test_contains_ead_classification(self):
        score = score_opportunity(15, 15, 15, 15, "GREY_ZONE")
        summary = format_score_summary(score)
        assert "GREY_ZONE" in summary

    def test_contains_all_dimensions(self):
        score = score_opportunity(10, 10, 10, 10, "BUILD_NOW")
        summary = format_score_summary(score)
        assert "Demand" in summary
        assert "Timing" in summary
        assert "Fit" in summary
        assert "Feasibility" in summary


class TestOpportunityScoreDataclass:
    """OpportunityScore is a proper dataclass."""

    def test_fields_accessible(self):
        score = OpportunityScore(
            demand=20, timing=18, fit=22, feasibility=15,
            total=75, verdict="PROMOTE", ead_classification="BUILD_NOW",
        )
        assert score.demand == 20
        assert score.timing == 18
        assert score.fit == 22
        assert score.feasibility == 15
        assert score.total == 75
        assert score.verdict == "PROMOTE"
        assert score.ead_classification == "BUILD_NOW"
