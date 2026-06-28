"""Tier 2: Validate promoted Tier 1 integration opportunities with deep evidence.

For each promoted candidate:
  1. Deep web search — targeted queries for Theseus-specific evidence
  2. Bolyra fit analysis — map opportunity to specific Bolyra primitives
  3. Integration spec — what code/circuit/contract changes needed, days estimate
  4. Re-score with deeper evidence using tier2_validation_rubric.md
  5. Build enriched integration card (JSON)

Uses Claude MAX login via `claude` CLI, never API keys or SDK.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object
from scoring import IntegrationScore, score_integration

HERE = Path(__file__).resolve().parent
PRIMITIVES_PATH = HERE / "primitives.json"
RUBRIC_PATH = HERE / "rubrics" / "tier2_validation_rubric.md"
THESEUS_CONTEXT_PATH = HERE / "theseus_context.md"


def _load_primitives() -> str:
    return PRIMITIVES_PATH.read_text()


def _load_rubric() -> str:
    return RUBRIC_PATH.read_text()


def _load_theseus_context() -> str:
    if THESEUS_CONTEXT_PATH.exists():
        return THESEUS_CONTEXT_PATH.read_text()
    return "(no theseus context available)"


# ---------------------------------------------------------------------------
# Stage 1: Deep web search
# ---------------------------------------------------------------------------

SEARCH_PROMPT = """You are a market research analyst specializing in AI agent infrastructure and identity.

OPPORTUNITY:
{opportunity_json}

THESEUS CONTEXT:
{theseus_context}

Perform targeted web searches for evidence about this integration opportunity
between Bolyra (ZKP identity protocol) and Theseus (agent-native L1 chain):

1. Theseus documentation, GitHub repos, or community discussions about their identity/auth approach
2. Competitor products addressing agent identity on L1 chains (Lit Protocol, Turnkey, Privy)
3. Standards or specifications for agent-to-agent authentication and delegation
4. Agent-native L1 projects with similar identity needs (Fetch.ai, SingularityNET, etc.)
5. ZKP-based identity solutions already deployed on L1 chains

Return ONLY a JSON object (no markdown fences):
{{
  "search_queries_used": ["query 1", "query 2", ...],
  "evidence": [
    {{"source": "url or description", "type": "theseus|competitor|standard|agent_l1|zkp_identity", "relevance": "high|medium|low", "summary": "one sentence"}}
  ],
  "demand_strength": "strong|moderate|weak|none",
  "timing_assessment": "sunday_demo|2_weeks|1_month|3_plus_months"
}}
"""


def deep_search(opportunity: dict, *, model: str = "opus", timeout: int = 300) -> dict:
    """Run deep web search for Theseus-specific evidence about an opportunity."""
    prompt = SEARCH_PROMPT.format(
        opportunity_json=json.dumps(opportunity, indent=2)[:4000],
        theseus_context=_load_theseus_context()[:3000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "search_queries_used": [],
            "evidence": [],
            "demand_strength": "none",
            "timing_assessment": "3_plus_months",
            "error": f"search failed: {e}",
        }


# ---------------------------------------------------------------------------
# Stage 2: Bolyra fit analysis — map to primitives
# ---------------------------------------------------------------------------

FIT_PROMPT = """You are Bolyra's principal architect. Map this integration opportunity to Bolyra's existing primitives.

PRIMITIVES (what Bolyra already has):
{primitives}

OPPORTUNITY:
{opportunity_json}

Analyze how this opportunity maps to Bolyra's existing circuits, contracts, and SDK.

Return ONLY a JSON object (no markdown fences):
{{
  "mapped_primitives": [
    {{"primitive_id": "HumanUniqueness|AgentPolicy|Delegation|IdentityRegistry|payment-protocols|...", "usage": "how this primitive applies to the Theseus integration", "modification_needed": "none|minor|major"}}
  ],
  "new_components_needed": [
    {{"type": "circuit|contract|sdk|spec|integration", "description": "what needs to be built", "complexity": "low|medium|high", "estimated_days": <number>}}
  ],
  "fit_score_rationale": "why this scores X/25 on primitive_readiness",
  "theseus_integration_surface": "how Bolyra connects to Theseus's chain — verifier contract, SDK bridge, API, etc."
}}
"""


def analyze_fit(
    opportunity: dict, *, model: str = "opus", timeout: int = 240
) -> dict:
    """Analyze how an opportunity maps to Bolyra's primitives for Theseus integration."""
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
            "theseus_integration_surface": "unknown",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Stage 3: Integration spec
# ---------------------------------------------------------------------------

SPEC_PROMPT = """You are a pragmatic solo-founder engineer planning an integration between Bolyra (ZKP identity) and Theseus (agent-native L1).

OPPORTUNITY:
{opportunity_json}

BOLYRA FIT ANALYSIS:
{fit_json}

WEB SEARCH EVIDENCE:
{search_json}

THESEUS CONTEXT:
{theseus_context}

Design a concrete integration plan. Be ruthlessly realistic about solo-founder capacity.

Return ONLY a JSON object (no markdown fences):
{{
  "deliverables": [
    {{"name": "artifact name", "type": "circuit|contract|sdk|spec|docs|integration|demo", "description": "what it is", "days": <number>, "reuses": "existing primitive or 'new'"}}
  ],
  "total_days": <number>,
  "reuse_percentage": <0-100>,
  "demo_readiness": "sunday|2_weeks|1_month|3_months",
  "demo_description": "what can be shown on the Sunday call",
  "risks": ["risk 1", "risk 2"],
  "success_criteria": "how to know the integration worked",
  "theseus_dependencies": "what Theseus needs to provide (API access, testnet, docs)"
}}
"""


def spec_integration(
    opportunity: dict,
    fit: dict,
    search: dict,
    *,
    model: str = "opus",
    timeout: int = 240,
) -> dict:
    """Generate integration spec for an opportunity."""
    prompt = SPEC_PROMPT.format(
        opportunity_json=json.dumps(opportunity, indent=2)[:3000],
        fit_json=json.dumps(fit, indent=2)[:3000],
        search_json=json.dumps(search, indent=2)[:3000],
        theseus_context=_load_theseus_context()[:2000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "deliverables": [],
            "total_days": 0,
            "reuse_percentage": 0,
            "demo_readiness": "3_months",
            "demo_description": f"spec failed: {e}",
            "risks": [str(e)],
            "success_criteria": "unknown",
            "theseus_dependencies": "unknown",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Stage 4: Re-score with deeper evidence
# ---------------------------------------------------------------------------

SCORE_PROMPT = """You are a scoring judge for the Bolyra Theseus AutoResearch Loop.

RUBRIC:
{rubric}

OPPORTUNITY:
{opportunity_json}

WEB SEARCH EVIDENCE:
{search_json}

BOLYRA FIT ANALYSIS:
{fit_json}

INTEGRATION SPEC:
{spec_json}

Score this integration opportunity on all 4 dimensions using the rubric.
Be calibrated -- most opportunities should NOT score above 20 on any dimension.

Return ONLY a JSON object (no markdown fences):
{{
  "agent_need": <0-25>,
  "zkp_edge": <0-25>,
  "primitive_readiness": <0-25>,
  "partnership_leverage": <0-25>,
  "rationale": {{
    "agent_need": "one sentence",
    "zkp_edge": "one sentence",
    "primitive_readiness": "one sentence",
    "partnership_leverage": "one sentence"
  }}
}}
"""


def rescore(
    opportunity: dict,
    search: dict,
    fit: dict,
    spec: dict,
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
        spec_json=json.dumps(spec, indent=2)[:2000],
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        return extract_json_object(raw)
    except Exception as e:
        return {
            "agent_need": 0,
            "zkp_edge": 0,
            "primitive_readiness": 0,
            "partnership_leverage": 0,
            "error": f"scoring failed: {e}",
        }


# ---------------------------------------------------------------------------
# Stage 5: Assemble integration card
# ---------------------------------------------------------------------------


def build_card(
    opportunity: dict,
    search: dict,
    fit: dict,
    spec: dict,
    scores: dict,
    score_obj: IntegrationScore,
) -> dict:
    """Assemble a full integration card from all Tier 2 stages."""
    return {
        "id": opportunity.get("id", "unknown"),
        "title": opportunity.get("title", "untitled"),
        "description": opportunity.get("description", ""),
        "category": opportunity.get("category", "unknown"),
        "persona": opportunity.get("persona", "unknown"),
        "time_horizon": opportunity.get("time_horizon", "unknown"),
        "scores": {
            "agent_need": score_obj.agent_need,
            "zkp_edge": score_obj.zkp_edge,
            "primitive_readiness": score_obj.primitive_readiness,
            "partnership_leverage": score_obj.partnership_leverage,
            "total": score_obj.total,
        },
        "verdict": score_obj.verdict,
        "rationale": scores.get("rationale", {}),
        "evidence": search.get("evidence", []),
        "demand_strength": search.get("demand_strength", "none"),
        "timing_assessment": search.get("timing_assessment", "unknown"),
        "mapped_primitives": fit.get("mapped_primitives", []),
        "new_components_needed": fit.get("new_components_needed", []),
        "theseus_integration_surface": fit.get("theseus_integration_surface", ""),
        "spec": {
            "deliverables": spec.get("deliverables", []),
            "total_days": spec.get("total_days", 0),
            "reuse_percentage": spec.get("reuse_percentage", 0),
            "demo_readiness": spec.get("demo_readiness", "unknown"),
            "demo_description": spec.get("demo_description", ""),
            "risks": spec.get("risks", []),
            "success_criteria": spec.get("success_criteria", ""),
            "theseus_dependencies": spec.get("theseus_dependencies", ""),
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
    """Run all Tier 2 validation stages for a single integration opportunity."""
    # Stage 1: Deep web search
    search = deep_search(opportunity, model=model, timeout=timeout)

    # Stage 2: Fit analysis
    fit = analyze_fit(opportunity, model=model, timeout=min(timeout, 240))

    # Stage 3: Integration spec
    spec = spec_integration(opportunity, fit, search, model=model, timeout=min(timeout, 240))

    # Stage 4: Re-score
    scores = rescore(opportunity, search, fit, spec, model=model, timeout=min(timeout, 180))

    # Compute verdict via scoring module
    try:
        score_obj = score_integration(
            agent_need=max(0, min(25, int(scores.get("agent_need", 0)))),
            zkp_edge=max(0, min(25, int(scores.get("zkp_edge", 0)))),
            primitive_readiness=max(0, min(25, int(scores.get("primitive_readiness", 0)))),
            partnership_leverage=max(0, min(25, int(scores.get("partnership_leverage", 0)))),
        )
    except (ValueError, TypeError):
        score_obj = IntegrationScore(
            agent_need=0, zkp_edge=0, primitive_readiness=0,
            partnership_leverage=0, total=0, verdict="DROP",
        )

    # Stage 5: Build card
    card = build_card(opportunity, search, fit, spec, scores, score_obj)
    return card


def run_tier2_validate(
    promoted: list[dict],
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 300,
    max_workers: int = 3,
) -> dict[str, Any]:
    """Run Tier 2 validation for all promoted Tier 1 integration opportunities.

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
    ap = argparse.ArgumentParser(description="Tier 2: validate promoted integration opportunities")
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
