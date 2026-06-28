"""Tests for the theseus-autoresearch scoring module."""

import sys
from pathlib import Path

# Ensure the parent package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scoring import IntegrationScore, format_score_summary, score_integration


class TestScoreIntegration:
    """Tests for score_integration verdict logic."""

    def test_high_scores_promote(self) -> None:
        """All dimensions high -> PROMOTE."""
        result = score_integration(20, 20, 20, 20)
        assert result.verdict == "PROMOTE"
        assert result.total == 80

    def test_low_total_drop(self) -> None:
        """Total below 50 -> DROP."""
        result = score_integration(10, 10, 10, 10)
        assert result.verdict == "DROP"
        assert result.total == 40

    def test_one_dim_le5_drop(self) -> None:
        """One dimension <= 5 -> DROP regardless of total."""
        result = score_integration(25, 25, 25, 5)
        assert result.verdict == "DROP"
        assert result.total == 80

    def test_middle_ground_consider(self) -> None:
        """Middle ground scores -> CONSIDER."""
        result = score_integration(15, 15, 15, 15)
        assert result.verdict == "CONSIDER"
        assert result.total == 60

    def test_boundary_total_70_one_dim_11_consider(self) -> None:
        """Total=70 but one dim=11 -> CONSIDER (not PROMOTE)."""
        result = score_integration(20, 20, 19, 11)
        assert result.total == 70
        assert result.verdict == "CONSIDER"

    def test_boundary_total_50_no_dim_le5_consider(self) -> None:
        """Total=50, no dim<=5 -> CONSIDER."""
        result = score_integration(14, 14, 14, 8)
        assert result.total == 50
        assert result.verdict == "CONSIDER"

    def test_clamping_values_above_25(self) -> None:
        """Values > 25 get clamped to 25."""
        result = score_integration(30, 30, 30, 30)
        assert result.agent_need == 25
        assert result.zkp_edge == 25
        assert result.primitive_readiness == 25
        assert result.partnership_leverage == 25
        assert result.total == 100
        assert result.verdict == "PROMOTE"

    def test_format_score_summary_contains_all_dims(self) -> None:
        """format_score_summary returns a string with all dimensions."""
        score = score_integration(18, 20, 15, 17)
        summary = format_score_summary(score)
        assert isinstance(summary, str)
        assert "Agent Need" in summary
        assert "ZKP Edge" in summary
        assert "Primitive Readiness" in summary
        assert "Partnership Leverage" in summary
        assert "18/25" in summary
        assert "20/25" in summary
        assert "15/25" in summary
        assert "17/25" in summary
        assert str(score.total) in summary
        assert score.verdict in summary
