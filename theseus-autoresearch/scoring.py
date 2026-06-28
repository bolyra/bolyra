"""Scoring module for the Bolyra Theseus AutoResearch Loop.

Scores integration opportunities across four dimensions (0-25 each, 100 total)
and classifies them for the theseus pipeline.
"""

from dataclasses import dataclass


@dataclass
class IntegrationScore:
    """Scored integration opportunity with verdict."""

    agent_need: int
    zkp_edge: int
    primitive_readiness: int
    partnership_leverage: int
    total: int
    verdict: str


def score_integration(
    agent_need: int,
    zkp_edge: int,
    primitive_readiness: int,
    partnership_leverage: int,
) -> IntegrationScore:
    """Score an integration opportunity and assign a verdict.

    Args:
        agent_need: How strongly agents need this integration (0-25).
        zkp_edge: How much ZKP adds over alternatives (0-25).
        primitive_readiness: Are the primitives ready to build this? (0-25).
        partnership_leverage: Does this unlock a partnership? (0-25).

    Returns:
        IntegrationScore with computed total and verdict.
    """
    dims = {
        "agent_need": agent_need,
        "zkp_edge": zkp_edge,
        "primitive_readiness": primitive_readiness,
        "partnership_leverage": partnership_leverage,
    }

    # Clamp each dimension to 0-25
    clamped = {name: max(0, min(25, val)) for name, val in dims.items()}

    dims_list = list(clamped.values())
    total = sum(dims_list)

    # Verdict logic:
    # - DROP if total < 50 OR any dimension <= 5
    # - PROMOTE if total >= 70 AND all dimensions >= 12
    # - CONSIDER otherwise (50-69 range, or 70+ with a weak dimension)
    if total < 50 or any(d <= 5 for d in dims_list):
        verdict = "DROP"
    elif total >= 70 and all(d >= 12 for d in dims_list):
        verdict = "PROMOTE"
    else:
        verdict = "CONSIDER"

    return IntegrationScore(
        agent_need=clamped["agent_need"],
        zkp_edge=clamped["zkp_edge"],
        primitive_readiness=clamped["primitive_readiness"],
        partnership_leverage=clamped["partnership_leverage"],
        total=total,
        verdict=verdict,
    )


def format_score_summary(score: IntegrationScore) -> str:
    """Format an IntegrationScore as a human-readable summary.

    Args:
        score: The scored integration opportunity.

    Returns:
        Multi-line string summary suitable for reports and logs.
    """
    bar_width = 25

    def bar(val: int) -> str:
        filled = round(val * bar_width / 25)
        return f"[{'#' * filled}{'.' * (bar_width - filled)}] {val}/25"

    lines = [
        f"Integration Score: {score.total}/100  |  Verdict: {score.verdict}",
        "",
        f"  Agent Need:           {bar(score.agent_need)}",
        f"  ZKP Edge:             {bar(score.zkp_edge)}",
        f"  Primitive Readiness:  {bar(score.primitive_readiness)}",
        f"  Partnership Leverage: {bar(score.partnership_leverage)}",
    ]
    return "\n".join(lines)
