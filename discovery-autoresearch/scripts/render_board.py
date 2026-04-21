"""Render the opportunity board as a Markdown report.

Reads output/opportunity_board.json, produces output/opportunity_board.md with:
  - Ranking table at top (rank, title, total score, EAD classification)
  - Full card for each opportunity below
  - Last updated timestamp
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
OUTPUT_DIR = HERE / "output"
BOARD_JSON = OUTPUT_DIR / "opportunity_board.json"
BOARD_MD = OUTPUT_DIR / "opportunity_board.md"


def load_board() -> list[dict]:
    if not BOARD_JSON.exists():
        return []
    return json.loads(BOARD_JSON.read_text())


def render_board(board: list[dict]) -> str:
    """Render the opportunity board as Markdown."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Bolyra Opportunity Board",
        "",
        f"*Last updated: {ts}*",
        "",
        f"**{len(board)} opportunities** ranked by total score.",
        "",
    ]

    if not board:
        lines.append("*No opportunities on the board yet. Run the discovery loop.*")
        return "\n".join(lines)

    # Ranking table
    lines.append("## Rankings")
    lines.append("")
    lines.append("| Rank | Title | Score | EAD | Tier 3 Verdict |")
    lines.append("|------|-------|-------|-----|----------------|")
    for i, card in enumerate(board, 1):
        title = card.get("title", "untitled")[:50]
        total = card.get("scores", {}).get("total", 0)
        ead = card.get("ead_classification", "?")
        verdict = card.get("tier3_verdict", card.get("verdict", "?"))
        lines.append(f"| {i} | {title} | {total}/100 | {ead} | {verdict} |")
    lines.append("")

    # Full cards
    lines.append("---")
    lines.append("")
    lines.append("## Opportunity Cards")
    lines.append("")

    for i, card in enumerate(board, 1):
        title = card.get("title", "untitled")
        cid = card.get("id", "unknown")
        desc = card.get("description", "")
        category = card.get("category", "unknown")
        source = card.get("source", "unknown")
        scores = card.get("scores", {})
        ead = card.get("ead_classification", "?")
        verdict = card.get("tier3_verdict", card.get("verdict", "?"))

        lines.append(f"### {i}. {title}")
        lines.append("")
        lines.append(f"**ID**: `{cid}` | **Category**: {category} | **Source**: {source}")
        lines.append("")
        lines.append(f"> {desc}")
        lines.append("")

        # Scores
        lines.append("**Scores**:")
        lines.append("")
        lines.append("| Dimension | Score |")
        lines.append("|-----------|-------|")
        for dim in ["demand", "timing", "fit", "feasibility"]:
            val = scores.get(dim, 0)
            bar = "#" * round(val * 20 / 25) + "." * (20 - round(val * 20 / 25))
            lines.append(f"| {dim.title()} | {val}/25 `[{bar}]` |")
        lines.append(f"| **Total** | **{scores.get('total', 0)}/100** |")
        lines.append("")
        lines.append(f"**Verdict**: {verdict} | **EAD**: {ead}")
        lines.append("")

        # Rationale
        rationale = card.get("rationale", {})
        if rationale:
            lines.append("**Rationale**:")
            lines.append("")
            for dim, text in rationale.items():
                lines.append(f"- **{dim.title()}**: {text}")
            lines.append("")

        # MVP
        mvp = card.get("mvp", {})
        if mvp and mvp.get("deliverables"):
            lines.append("**MVP Spec**:")
            lines.append("")
            lines.append(f"- Total days: {mvp.get('total_days', '?')}")
            lines.append(f"- Reuse: {mvp.get('reuse_percentage', '?')}%")
            lines.append(f"- Success criteria: {mvp.get('success_criteria', '?')}")
            lines.append("")
            lines.append("| Deliverable | Type | Days | Reuses |")
            lines.append("|-------------|------|------|--------|")
            for d in mvp.get("deliverables", []):
                lines.append(
                    f"| {d.get('name', '?')} | {d.get('type', '?')} | "
                    f"{d.get('days', '?')} | {d.get('reuses', 'new')} |"
                )
            lines.append("")

        # Mapped primitives
        mapped = card.get("mapped_primitives", [])
        if mapped:
            lines.append("**Mapped Primitives**:")
            lines.append("")
            for m in mapped:
                mod = m.get("modification_needed", "none")
                lines.append(f"- `{m.get('primitive_id', '?')}`: {m.get('usage', '?')} (mod: {mod})")
            lines.append("")

        # Tier 3 findings
        findings = card.get("tier3_findings", [])
        if findings:
            lines.append("**Tier 3 Findings**:")
            lines.append("")
            for f in findings:
                lines.append(f"- {f}")
            lines.append("")

        # Concerns (CONDITIONAL cards)
        concerns = card.get("concerns", [])
        if concerns:
            lines.append("**Concerns** (CONDITIONAL):")
            lines.append("")
            for c in concerns:
                lines.append(f"- {c}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    board = load_board()
    if not board:
        print("No opportunities on the board. Run the discovery loop first.")
        return 0

    md = render_board(board)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BOARD_MD.write_text(md)
    print(f"Rendered {len(board)} opportunities to {BOARD_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
