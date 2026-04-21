"""Tier 1: Discovery runner for the Bolyra Discovery AutoResearch Loop.

Dispatches discovery personas in parallel via ThreadPoolExecutor. Each persona
analyzes web signals, strategy priors, and the primitives inventory to propose
3-5 opportunity candidates. Results are merged, deduplicated, and saved.

Uses Claude MAX login via `claude` CLI, never API keys or SDK.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
PERSONAS_PATH = HERE / "personas" / "discovery_personas.json"
STRATEGY_PRIORS_PATH = HERE / "context" / "strategy_priors.md"
PRIMITIVES_PATH = HERE / "primitives.json"


DISCOVER_PROMPT = """You are a discovery analyst playing the role: {role}

{prompt_template}

Focus areas: {focus}

WEB SIGNALS (recent, relevant to your focus):
{signals_block}

STRATEGY PRIORS:
{strategy_priors}

{primitives_block}

Based on these signals and your expertise, propose 3-5 concrete opportunity candidates
for Bolyra. Each opportunity should be specific enough to evaluate for build-vs-skip.

Return ONLY a JSON array (no markdown fences), one object per opportunity:
[
  {{
    "id": "{persona_id}_<short_slug>",
    "persona": "{persona_id}",
    "title": "short descriptive title (max 80 chars)",
    "category": "integration" | "standard" | "market_entry" | "developer_tool" | "competitive_response",
    "description": "2-4 sentences: what the opportunity is, why it matters, what evidence supports it",
    "signal_urls": ["url1", "url2"],
    "beachhead": "which beachhead market this serves (B2B procurement / enterprise travel / high-value marketplaces / developer tools / other)",
    "estimated_effort": "days" | "weeks" | "months"
  }}
]

Produce 3-5 proposals. Be specific and cite the signals that support each one.
"""


def _load_personas() -> list[dict[str, Any]]:
    """Load discovery personas. Handles both list format and {personas: [...]} wrapper."""
    data = json.loads(PERSONAS_PATH.read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "personas" in data:
        return data["personas"]
    raise ValueError(f"Unexpected personas format: {type(data)}")


def _load_strategy_priors() -> str:
    """Load strategy priors markdown. Returns empty string if not found."""
    if STRATEGY_PRIORS_PATH.exists():
        return STRATEGY_PRIORS_PATH.read_text()
    logger.warning("Strategy priors not found at %s", STRATEGY_PRIORS_PATH)
    return "(no strategy priors available)"


def _load_primitives() -> str:
    """Load primitives inventory JSON as formatted string."""
    if PRIMITIVES_PATH.exists():
        return PRIMITIVES_PATH.read_text()
    logger.warning("Primitives inventory not found at %s", PRIMITIVES_PATH)
    return "(no primitives inventory available)"


def _filter_signals_for_persona(
    persona: dict[str, Any],
    all_signals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Select signals relevant to a persona's focus areas."""
    focus_terms = [f.lower() for f in persona.get("focus", [])]
    if not focus_terms:
        return all_signals[:15]  # fallback: first 15

    relevant: list[dict[str, Any]] = []
    for sig in all_signals:
        text = " ".join([
            sig.get("title", ""),
            sig.get("snippet", ""),
            sig.get("source_category", ""),
            sig.get("source_query", ""),
        ]).lower()
        if any(term in text for term in focus_terms):
            relevant.append(sig)

    # If no matches, include a general sample
    if not relevant:
        relevant = all_signals[:10]

    return relevant[:20]  # cap at 20 to avoid prompt bloat


def _build_prompt(
    persona: dict[str, Any],
    signals: list[dict[str, Any]],
    strategy_priors: str,
    primitives: str,
) -> str:
    """Assemble the full prompt for a persona."""
    # Format signals block
    if signals:
        signals_block = json.dumps(signals, indent=2, default=str)[:10000]
    else:
        signals_block = "(no web signals available for this focus area)"

    # Include primitives only for technical personas
    persona_id = persona.get("id", "unknown")
    needs_primitives = persona_id in ("protocol_mapper", "solo_founder_realist")
    if needs_primitives:
        primitives_block = f"BOLYRA PRIMITIVES INVENTORY:\n{primitives[:8000]}"
    else:
        primitives_block = ""

    # Get focus as string
    focus = persona.get("focus", [])
    if isinstance(focus, list):
        focus_str = ", ".join(focus)
    else:
        focus_str = str(focus)

    return DISCOVER_PROMPT.format(
        role=persona.get("role", "Discovery Analyst"),
        prompt_template=persona.get("prompt_template", ""),
        focus=focus_str,
        signals_block=signals_block,
        strategy_priors=strategy_priors[:6000],
        primitives_block=primitives_block,
        persona_id=persona_id,
    )


def _run_persona(
    persona: dict[str, Any],
    all_signals: list[dict[str, Any]],
    strategy_priors: str,
    primitives: str,
    *,
    model: str = "opus",
    timeout: int = 360,
) -> list[dict[str, Any]]:
    """Dispatch one persona. Returns a list of opportunity candidate dicts.

    On parse failure, returns an error-stub entry rather than raising.
    """
    persona_id = persona.get("id", "unknown")
    relevant_signals = _filter_signals_for_persona(persona, all_signals)
    prompt = _build_prompt(persona, relevant_signals, strategy_priors, primitives)

    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
    except RuntimeError as e:
        logger.error("Claude CLI failed for persona %s: %s", persona_id, e)
        return [_error_stub(persona_id, f"CLI call failed: {e}")]

    try:
        candidates = extract_json_array(raw)
    except ValueError as e:
        logger.warning("Parse error for persona %s: %s", persona_id, e)
        return [_error_stub(persona_id, f"JSON parse failed: {e}")]

    # Tag each candidate with persona
    for c in candidates:
        c.setdefault("persona", persona_id)
    return candidates


def _error_stub(persona_id: str, reason: str) -> dict[str, Any]:
    """Create an error stub entry for failed persona execution."""
    return {
        "id": f"{persona_id}_error",
        "persona": persona_id,
        "title": "Error",
        "category": "meta",
        "description": reason,
        "signal_urls": [],
        "beachhead": "n/a",
        "estimated_effort": "unknown",
    }


def _deduplicate_by_title(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate candidates by normalized title similarity.

    Uses a simple approach: lowercase + strip whitespace, then compare.
    Keeps the first occurrence of each normalized title.
    """
    seen_titles: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        title = c.get("title", "").strip().lower()
        # Normalize: remove common filler words for comparison
        normalized = title.replace("the ", "").replace("a ", "").replace("an ", "").strip()
        if not normalized or normalized not in seen_titles:
            seen_titles.add(normalized)
            unique.append(c)
    return unique


def run_tier1_discover(
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 360,
    max_workers: int = 4,
) -> list[dict[str, Any]]:
    """Dispatch all discovery personas in parallel and merge results.

    Reads signals from output_dir/signals_raw.json (produced by fetch_signals).

    Writes:
      - tier1_opportunities.json (merged, deduplicated candidates)

    Returns:
        Merged list of opportunity candidates.
    """
    personas = _load_personas()
    strategy_priors = _load_strategy_priors()
    primitives = _load_primitives()

    # Load signals from the current run
    signals_path = output_dir / "signals_raw.json"
    if signals_path.exists():
        all_signals = json.loads(signals_path.read_text())
    else:
        logger.warning("No signals_raw.json found in %s, running without signals", output_dir)
        all_signals = []

    # Filter to personas with search_queries (or all if field missing)
    active_personas = [
        p for p in personas
        if p.get("search_queries") is not False  # include True, list, or missing
    ]
    # Also include non-search personas (they analyze signals from others)
    non_search_personas = [
        p for p in personas
        if p.get("search_queries") is False
    ]
    dispatch_personas = active_personas + non_search_personas

    logger.info("Dispatching %d personas (max_workers=%d)...", len(dispatch_personas), max_workers)
    all_candidates: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                _run_persona,
                p,
                all_signals,
                strategy_priors,
                primitives,
                model=model,
                timeout=timeout,
            ): p.get("id", "unknown")
            for p in dispatch_personas
        }
        for fut in as_completed(futures):
            persona_id = futures[fut]
            try:
                candidates = fut.result()
                logger.info("Persona %s returned %d candidates", persona_id, len(candidates))
                all_candidates.extend(candidates)
            except Exception as e:
                logger.error("Persona %s raised: %s", persona_id, e)
                all_candidates.append(_error_stub(persona_id, f"Exception: {type(e).__name__}: {e}"))

    # Deduplicate by title similarity
    merged = _deduplicate_by_title(all_candidates)
    logger.info("Merged %d candidates -> %d after dedup", len(all_candidates), len(merged))

    # Save
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tier1_opportunities.json").write_text(json.dumps(merged, indent=2))

    return merged


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Tier 1: parallel discovery exploration")
    ap.add_argument("--output-dir", required=True, help="Iteration output directory")
    ap.add_argument("--model", default="opus", help="Claude model for personas")
    ap.add_argument("--timeout", type=int, default=360, help="CLI timeout per persona (s)")
    ap.add_argument("--max-workers", type=int, default=4, help="Thread pool size")
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    results = run_tier1_discover(
        output_dir,
        model=args.model,
        timeout=args.timeout,
        max_workers=args.max_workers,
    )
    print(f"Wrote {len(results)} opportunities to {output_dir / 'tier1_opportunities.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
