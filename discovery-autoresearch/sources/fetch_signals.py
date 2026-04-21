"""Signal fetcher for the Bolyra Discovery AutoResearch Loop.

Reads source_registry.json, dispatches web-search prompts via Claude CLI,
deduplicates against history/seen_signals.jsonl, and saves new signals
to the current iteration's run directory.

Uses Claude MAX login via `claude` CLI, never API keys or SDK.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCE_REGISTRY = HERE / "source_registry.json"
SEEN_SIGNALS_PATH = ROOT / "history" / "seen_signals.jsonl"


def _load_registry() -> list[dict[str, str]]:
    """Flatten source_registry.json into a list of {id, query, category} dicts."""
    data = json.loads(SOURCE_REGISTRY.read_text())
    sources: list[dict[str, str]] = []
    for _category_key, entries in data.items():
        for entry in entries:
            sources.append(entry)
    return sources


def _load_seen_urls() -> set[str]:
    """Load previously seen signal URLs from the JSONL history file."""
    seen: set[str] = set()
    if not SEEN_SIGNALS_PATH.exists():
        return seen
    for line in SEEN_SIGNALS_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "url" in obj:
                seen.add(obj["url"])
        except json.JSONDecodeError:
            continue
    return seen


def _append_seen(signals: list[dict[str, Any]]) -> None:
    """Append newly seen signals to the JSONL history file."""
    SEEN_SIGNALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SEEN_SIGNALS_PATH.open("a") as f:
        for sig in signals:
            f.write(json.dumps(sig, default=str) + "\n")


def _fetch_one_source(
    source: dict[str, str],
    *,
    model: str = "sonnet",
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """Call Claude CLI with a web search prompt for a single source query.

    Returns a list of result dicts with fields: url, title, snippet, date.
    On failure, logs and returns an empty list.
    """
    query = source["query"]
    prompt = (
        f"Search the web for: {query}. "
        "Return results as JSON array with fields: url, title, snippet, date. "
        "Return only the top 5 most relevant results. "
        "Return ONLY the JSON array, no markdown fences or extra text."
    )
    try:
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        results = extract_json_array(raw)
    except (RuntimeError, ValueError) as e:
        logger.warning("Failed to fetch signals for %s: %s", source["id"], e)
        return []

    # Tag each result with source metadata
    for r in results:
        r["source_id"] = source["id"]
        r["source_category"] = source.get("category", "unknown")
        r["source_query"] = query
    return results


def fetch_signals(
    output_dir: Path,
    *,
    model: str = "sonnet",
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """Fetch signals for all sources, deduplicate, and save to output_dir.

    Writes:
      - signals_raw.json (all new, deduplicated signals)

    Returns:
        List of new signal dicts.
    """
    sources = _load_registry()
    seen_urls = _load_seen_urls()
    all_signals: list[dict[str, Any]] = []

    logger.info("Fetching signals for %d sources...", len(sources))
    for source in sources:
        results = _fetch_one_source(source, model=model, timeout=timeout)
        all_signals.extend(results)

    # Deduplicate against history
    new_signals: list[dict[str, Any]] = []
    for sig in all_signals:
        url = sig.get("url", "")
        if url and url not in seen_urls:
            new_signals.append(sig)
            seen_urls.add(url)

    logger.info(
        "Fetched %d total signals, %d new after dedup",
        len(all_signals),
        len(new_signals),
    )

    # Save outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "signals_raw.json").write_text(json.dumps(new_signals, indent=2))

    # Update history
    _append_seen(new_signals)

    return new_signals


def main() -> int:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ap = argparse.ArgumentParser(description="Fetch discovery signals from web sources")
    ap.add_argument("--output-dir", required=True, help="Iteration output directory")
    ap.add_argument("--model", default="sonnet", help="Claude model for web searches")
    ap.add_argument("--timeout", type=int, default=120, help="CLI timeout per source (s)")
    args = ap.parse_args()

    output_dir = Path(args.output_dir)
    signals = fetch_signals(output_dir, model=args.model, timeout=args.timeout)
    print(f"Fetched {len(signals)} new signals -> {output_dir / 'signals_raw.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
