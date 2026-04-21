"""Tier 2: Validate promoted Tier 1 opportunities with deep evidence.

For each promoted candidate:
  1. Deep web search — targeted queries based on the opportunity
  2. Bolyra fit analysis — map opportunity to specific primitives from primitives.json
  3. MVP spec — concrete deliverables, day estimates, reuse vs. new
  4. Re-score with deeper evidence using tier2_validation_rubric.md
  5. Generate full opportunity cards (JSON)
  6. Save to runs/iter_NNN/tier2_cards.json and tier2_scored.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object
from scoring import score_opportunity, OpportunityScore

HERE = Path(__file__).resolve().parent
PRIMITIVES_PATH = HERE / "primitives.json"
RUBRIC_PATH = HERE / "rubrics" / "tier2_validation_rubric.md"
EAD_PATH = HERE / "context" / "ead_constraints.md"


def _load_primitives() -> str:
    return PRIMITIVES_PATH.read_text()


def _load_rubric() -> str:
    return RUBRIC_PATH.read_text()


def _load_ead() -> str:
    return EAD_PATH.read_text()


# ---------------------------------------------------------------------------
# Stage 1: Deep web search
# ---------------------------------------------------------------------------

SEARCH_PROMPT = """You are a market research analyst. Search the web for evidence about this opportunity.

OPPORTUNITY:
{opportunity_json}

Perform targeted web searches for:
1. Companies or teams actively building in this space (names, URLs, funding)
2. Standards activity (IETF drafts, W3C specs, NIST guidance) relevant to this
3. Competitor products that address similar needs
4. Conference talks, blog posts, or analyst reports from 2025-2026
5. GitHub repos, npm packages, or open-source projects in this space

Return ONLY a JSON object (no markdown fences):
{{
  "search_queries_used": ["query 1", "query 2", ...],
  "evidence": [
    {{"source": "url or description", "type": "company|standard|competitor|report|oss", "relevance": "high|medium|low", "summary": "one sentence"}}
  ],
  "demand_strength": "strong|moderate|weak|none",
  "timing_assessment": "now|6_months|12_months|18_plus_months"
}}
"""


def deep_search(opportunity: dict, *, model: str = "opus", timeout: int = 300) -> dict:
    """Run deep web search for evidence about an opportunity."""
    prompt = SEARCH_PROMPT.format(
        opportunity_json=json.dumps(opportunity, indent=2)[:4000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "search_queries_used": [],
            "evidence": [],
            "demand_strength": "none",
            "timing_assessment": "18_plus_months",
            "error": f"search failed: {e}",
        }


# ---------------------------------------------------------------------------
# Stage 2: Bolyra fit analysis
# ---------------------------------------------------------------------------

FIT_PROMPT = """You are a protocol architect for Bolyra, a ZKP identity protocol for humans and AI agents.

PRIMITIVES (what Bolyra already has):
{primitives}

OPPORTUNITY:
{opportunity_json}

Analyze how this opportunity maps to Bolyra's existing primitives.

Return ONLY a JSON object (no markdown fences):
{{
  "mapped_primitives": [
    {{"primitive_id": "HumanUniqueness|AgentPolicy|Delegation|IdentityRegistry|...", "usage": "how this primitive applies", "modification_needed": "none|minor|major"}}
  ],
  "new_components_needed": [
    {{"type": "circuit|contract|sdk|spec|integration", "description": "what needs to be built", "complexity": "low|medium|high"}}
  ],
  "fit_score_rationale": "why this scores X/25 on fit",
  "positioning_alignment": "how this aligns with privacy-layer-under-incumbents strategy"
}}
"""


def analyze_fit(
    opportunity: dict, *, model: str = "opus", timeout: int = 240
) -> dict:
    """Analyze how an opportunity maps to Bolyra's primitives."""
    prompt = FIT_PROMPT.format(
        primitives=_load_primitives()[:8000],
        opportunity_json=json.dumps(opportunity, indent=2)[:4000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "mapped_primitives": [],
            "new_components_needed": [],
            "fit_score_rationale": f"fit analysis failed: {e}",
            "positioning_alignment": "unknown",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Stage 3: MVP spec
# ---------------------------------------------------------------------------

MVP_PROMPT = """You are a pragmatic solo-founder engineer planning an MVP.

OPPORTUNITY:
{opportunity_json}

BOLYRA FIT ANALYSIS:
{fit_json}

WEB SEARCH EVIDENCE:
{search_json}

EAD CONSTRAINTS:
{ead_constraints}

Design a concrete MVP. Be ruthlessly realistic about solo-founder capacity.

Return ONLY a JSON object (no markdown fences):
{{
  "deliverables": [
    {{"name": "artifact name", "type": "circuit|contract|sdk|spec|docs|integration|demo", "description": "what it is", "days": <number>, "reuses": "existing primitive or 'new'"}}
  ],
  "total_days": <number>,
  "reuse_percentage": <0-100>,
  "ead_classification": "BUILD_NOW|WAIT_FOR_EAD|GREY_ZONE",
  "ead_rationale": "why this classification",
  "risks": ["risk 1", "risk 2"],
  "success_criteria": "how to know the MVP worked"
}}
"""


def spec_mvp(
    opportunity: dict,
    fit: dict,
    search: dict,
    *,
    model: str = "opus",
    timeout: int = 240,
) -> dict:
    """Generate MVP spec for an opportunity."""
    prompt = MVP_PROMPT.format(
        opportunity_json=json.dumps(opportunity, indent=2)[:3000],
        fit_json=json.dumps(fit, indent=2)[:3000],
        search_json=json.dumps(search, indent=2)[:3000],
        ead_constraints=_load_ead()[:2000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "deliverables": [],
            "total_days": 0,
            "reuse_percentage": 0,
            "ead_classification": "GREY_ZONE",
            "ead_rationale": f"mvp spec failed: {e}",
            "risks": [str(e)],
            "success_criteria": "unknown",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Stage 4: Re-score with deeper evidence
# ---------------------------------------------------------------------------

SCORE_PROMPT = """You are a scoring judge for the Bolyra Discovery AutoResearch Loop.

RUBRIC:
{rubric}

OPPORTUNITY:
{opportunity_json}

WEB SEARCH EVIDENCE:
{search_json}

BOLYRA FIT ANALYSIS:
{fit_json}

MVP SPEC:
{mvp_json}

Score this opportunity on all 4 dimensions using the rubric. Be calibrated — most opportunities should NOT score above 20 on any dimension.

Return ONLY a JSON object (no markdown fences):
{{
  "demand": <0-25>,
  "timing": <0-25>,
  "fit": <0-25>,
  "feasibility": <0-25>,
  "ead_classification": "BUILD_NOW|WAIT_FOR_EAD|GREY_ZONE",
  "rationale": {{
    "demand": "one sentence",
    "timing": "one sentence",
    "fit": "one sentence",
    "feasibility": "one sentence"
  }}
}}
"""


def rescore(
    opportunity: dict,
    search: dict,
    fit: dict,
    mvp: dict,
    *,
    model: str = "opus",
    timeout: int = 180,
) -> dict:
    """Re-score an opportunity with full Tier 2 evidence."""
    prompt = SCORE_PROMPT.format(
        rubric=_load_rubric()[:4000],
        opportunity_json=json.dumps(opportunity, indent=2)[:2000],
        search_json=json.dumps(search, indent=2)[:3000],
        fit_json=json.dumps(fit, indent=2)[:2000],
        mvp_json=json.dumps(mvp, indent=2)[:2000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "demand": 0,
            "timing": 0,
            "fit": 0,
            "feasibility": 0,
            "ead_classification": "GREY_ZONE",
            "error": f"scoring failed: {e}",
        }


# ---------------------------------------------------------------------------
# Stage 5: Assemble opportunity card
# ---------------------------------------------------------------------------


def build_card(
    opportunity: dict,
    search: dict,
    fit: dict,
    mvp: dict,
    scores: dict,
    score_obj: OpportunityScore,
) -> dict:
    """Assemble a full opportunity card from all Tier 2 stages."""
    return {
        "id": opportunity.get("id", "unknown"),
        "title": opportunity.get("title", "untitled"),
        "description": opportunity.get("description", ""),
        "category": opportunity.get("category", "unknown"),
        "source": opportunity.get("source", "unknown"),
        "scores": {
            "demand": score_obj.demand,
            "timing": score_obj.timing,
            "fit": score_obj.fit,
            "feasibility": score_obj.feasibility,
            "total": score_obj.total,
        },
        "verdict": score_obj.verdict,
        "ead_classification": score_obj.ead_classification,
        "rationale": scores.get("rationale", {}),
        "evidence": search.get("evidence", []),
        "demand_strength": search.get("demand_strength", "none"),
        "timing_assessment": search.get("timing_assessment", "unknown"),
        "mapped_primitives": fit.get("mapped_primitives", []),
        "new_components_needed": fit.get("new_components_needed", []),
        "positioning_alignment": fit.get("positioning_alignment", ""),
        "mvp": {
            "deliverables": mvp.get("deliverables", []),
            "total_days": mvp.get("total_days", 0),
            "reuse_percentage": mvp.get("reuse_percentage", 0),
            "risks": mvp.get("risks", []),
            "success_criteria": mvp.get("success_criteria", ""),
        },
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def validate_opportunity(
    opportunity: dict,
    *,
    model: str = "opus",
    timeout: int = 300,
) -> dict:
    """Run all Tier 2 validation stages for a single opportunity."""
    # Stage 1: Deep web search
    search = deep_search(opportunity, model=model, timeout=timeout)

    # Stage 2: Fit analysis
    fit = analyze_fit(opportunity, model=model, timeout=min(timeout, 240))

    # Stage 3: MVP spec
    mvp = spec_mvp(opportunity, fit, search, model=model, timeout=min(timeout, 240))

    # Stage 4: Re-score
    scores = rescore(opportunity, search, fit, mvp, model=model, timeout=min(timeout, 180))

    # Compute verdict via scoring module
    try:
        ead = scores.get("ead_classification", mvp.get("ead_classification", "GREY_ZONE"))
        if ead not in {"BUILD_NOW", "WAIT_FOR_EAD", "GREY_ZONE"}:
            ead = "GREY_ZONE"
        score_obj = score_opportunity(
            demand=max(0, min(25, int(scores.get("demand", 0)))),
            timing=max(0, min(25, int(scores.get("timing", 0)))),
            fit=max(0, min(25, int(scores.get("fit", 0)))),
            feasibility=max(0, min(25, int(scores.get("feasibility", 0)))),
            ead_classification=ead,
        )
    except (ValueError, TypeError):
        score_obj = OpportunityScore(
            demand=0, timing=0, fit=0, feasibility=0,
            total=0, verdict="DROP", ead_classification="GREY_ZONE",
        )

    # Stage 5: Build card
    card = build_card(opportunity, search, fit, mvp, scores, score_obj)
    return card


def run_tier2_validate(
    promoted: list[dict],
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 300,
    max_workers: int = 3,
) -> dict[str, Any]:
    """Run Tier 2 validation for all promoted Tier 1 opportunities.

    Returns dict with cards, scored list, and promoted/dropped lists.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    cards: list[dict] = []
    scored: list[dict] = []

    # Sequential to avoid Claude CLI contention (each call is expensive)
    for opp in promoted:
        card = validate_opportunity(opp, model=model, timeout=timeout)
        cards.append(card)
        scored.append({
            "id": card["id"],
            "title": card["title"],
            "scores": card["scores"],
            "verdict": card["verdict"],
            "ead_classification": card["ead_classification"],
        })

    # Sort by total score descending
    cards.sort(key=lambda c: c["scores"]["total"], reverse=True)
    scored.sort(key=lambda s: s["scores"]["total"], reverse=True)

    # Split by verdict
    tier2_promoted = [c for c in cards if c["verdict"] == "PROMOTE"]
    tier2_consider = [c for c in cards if c["verdict"] == "CONSIDER"]
    tier2_dropped = [c for c in cards if c["verdict"] == "DROP"]

    (output_dir / "tier2_cards.json").write_text(json.dumps(cards, indent=2))
    (output_dir / "tier2_scored.json").write_text(json.dumps(scored, indent=2))
    (output_dir / "tier2_promoted.json").write_text(
        json.dumps(tier2_promoted + tier2_consider, indent=2)
    )

    return {
        "cards": cards,
        "scored": scored,
        "promoted": tier2_promoted + tier2_consider,
        "dropped": tier2_dropped,
        "output_dir": str(output_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 2: validate promoted opportunities")
    ap.add_argument("--promoted", required=True, help="Path to tier1_promoted.json")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--model", default="opus")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    promoted = json.loads(Path(args.promoted).read_text())
    output_dir = Path(args.output_dir)
    result = run_tier2_validate(promoted, output_dir, model=args.model, timeout=args.timeout)
    print(f"Validated {len(result['cards'])} opportunities")
    print(f"Promoted {len(result['promoted'])}, dropped {len(result['dropped'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
