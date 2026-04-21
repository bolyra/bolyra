"""Opportunity scoring module for the Bolyra Discovery AutoResearch Loop.

Scores discovered opportunities across four dimensions (0-25 each, 100 total)
and classifies them against EAD constraints.
"""

from dataclasses import dataclass


@dataclass
class OpportunityScore:
    """Scored opportunity with verdict and EAD classification."""

    demand: int
    timing: int
    fit: int
    feasibility: int
    total: int
    verdict: str
    ead_classification: str


def score_opportunity(
    demand: int,
    timing: int,
    fit: int,
    feasibility: int,
    ead_classification: str,
) -> OpportunityScore:
    """Score an opportunity and assign a verdict.

    Args:
        demand: Market demand signal strength (0-25).
        timing: Timing alignment — is the market ready? (0-25).
        fit: Strategic fit with Bolyra's positioning (0-25).
        feasibility: Can we build/ship this given current resources? (0-25).
        ead_classification: One of BUILD_NOW, WAIT_FOR_EAD, GREY_ZONE.

    Returns:
        OpportunityScore with computed total and verdict.

    Raises:
        ValueError: If any dimension is out of range or classification is invalid.
    """
    dims = {"demand": demand, "timing": timing, "fit": fit, "feasibility": feasibility}
    for name, val in dims.items():
        if not (0 <= val <= 25):
            raise ValueError(f"{name} must be 0-25, got {val}")

    valid_classifications = {"BUILD_NOW", "WAIT_FOR_EAD", "GREY_ZONE"}
    if ead_classification not in valid_classifications:
        raise ValueError(
            f"ead_classification must be one of {valid_classifications}, "
            f"got {ead_classification!r}"
        )

    total = demand + timing + fit + feasibility
    dims_list = [demand, timing, fit, feasibility]

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

    return OpportunityScore(
        demand=demand,
        timing=timing,
        fit=fit,
        feasibility=feasibility,
        total=total,
        verdict=verdict,
        ead_classification=ead_classification,
    )


def format_score_summary(score: OpportunityScore) -> str:
    """Format an OpportunityScore as a human-readable summary.

    Args:
        score: The scored opportunity.

    Returns:
        Multi-line string summary suitable for reports and logs.
    """
    bar_width = 25

    def bar(val: int) -> str:
        filled = round(val * bar_width / 25)
        return f"[{'#' * filled}{'.' * (bar_width - filled)}] {val}/25"

    lines = [
        f"Opportunity Score: {score.total}/100  |  Verdict: {score.verdict}",
        f"EAD Classification: {score.ead_classification}",
        "",
        f"  Demand:      {bar(score.demand)}",
        f"  Timing:      {bar(score.timing)}",
        f"  Fit:         {bar(score.fit)}",
        f"  Feasibility: {bar(score.feasibility)}",
    ]
    return "\n".join(lines)
