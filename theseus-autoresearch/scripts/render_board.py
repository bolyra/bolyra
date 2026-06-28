"""Render the integration board as a Markdown report.

Reads output/integration_board.json, produces output/integration_board.md with:
  - Ranking table at top (rank, title, total score, time horizon, verdict)
  - Full card for each integration opportunity below
  - Last updated timestamp
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
OUTPUT_DIR = HERE / "output"
BOARD_JSON = OUTPUT_DIR / "integration_board.json"
BOARD_MD = OUTPUT_DIR / "integration_board.md"

DIMENSIONS = ["agent_need", "zkp_edge", "primitive_readiness", "partnership_leverage"]
DIMENSION_LABELS = {
    "agent_need": "Agent Need",
    "zkp_edge": "ZKP Edge",
    "primitive_readiness": "Primitive Readiness",
    "partnership_leverage": "Partnership Leverage",
}


def load_board() -> list[dict]:
    if not BOARD_JSON.exists():
        return []
    return json.loads(BOARD_JSON.read_text())


def render_board(board: list[dict]) -> str:
    """Render the integration board as Markdown."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Bolyra x Theseus Integration Board",
        "",
        f"*Last updated: {ts}*",
        "",
        f"**{len(board)} integration opportunities** ranked by total score.",
        "",
    ]

    if not board:
        lines.append("*No opportunities on the board yet. Run the theseus autoresearch loop.*")
        return "\n".join(lines)

    # Ranking table
    lines.append("## Rankings")
    lines.append("")
    lines.append("| Rank | Title | Score | Time Horizon | Tier 3 Verdict |")
    lines.append("|------|-------|-------|--------------|----------------|")
    for i, card in enumerate(board, 1):
        title = card.get("title", "untitled")[:50]
        total = card.get("scores", {}).get("total", 0)
        horizon = card.get("time_horizon", card.get("spec", {}).get("demo_readiness", "?"))
        verdict = card.get("tier3_verdict", card.get("verdict", "?"))
        lines.append(f"| {i} | {title} | {total}/100 | {horizon} | {verdict} |")
    lines.append("")

    # Full cards
    lines.append("---")
    lines.append("")
    lines.append("## Integration Cards")
    lines.append("")

    for i, card in enumerate(board, 1):
        title = card.get("title", "untitled")
        cid = card.get("id", "unknown")
        desc = card.get("description", "")
        category = card.get("category", "unknown")
        persona = card.get("persona", "unknown")
        scores = card.get("scores", {})
        horizon = card.get("time_horizon", "?")
        verdict = card.get("tier3_verdict", card.get("verdict", "?"))

        lines.append(f"### {i}. {title}")
        lines.append("")
        lines.append(f"**ID**: `{cid}` | **Category**: {category} | **Persona**: {persona}")
        lines.append("")
        lines.append(f"> {desc}")
        lines.append("")

        # Scores
        lines.append("**Scores**:")
        lines.append("")
        lines.append("| Dimension | Score |")
        lines.append("|-----------|-------|")
        for dim in DIMENSIONS:
            val = scores.get(dim, 0)
            bar_len = round(val * 20 / 25) if val > 0 else 0
            bar = "#" * bar_len + "." * (20 - bar_len)
            label = DIMENSION_LABELS.get(dim, dim.title())
            lines.append(f"| {label} | {val}/25 `[{bar}]` |")
        lines.append(f"| **Total** | **{scores.get('total', 0)}/100** |")
        lines.append("")
        lines.append(f"**Verdict**: {verdict} | **Time Horizon**: {horizon}")
        lines.append("")

        # Rationale
        rationale = card.get("rationale", {})
        if rationale:
            lines.append("**Rationale**:")
            lines.append("")
            for dim, text in rationale.items():
                label = DIMENSION_LABELS.get(dim, dim.title())
                lines.append(f"- **{label}**: {text}")
            lines.append("")

        # Integration spec
        spec = card.get("spec", {})
        if spec and spec.get("deliverables"):
            lines.append("**Integration Spec**:")
            lines.append("")
            lines.append(f"- Total days: {spec.get('total_days', '?')}")
            lines.append(f"- Reuse: {spec.get('reuse_percentage', '?')}%")
            lines.append(f"- Demo readiness: {spec.get('demo_readiness', '?')}")
            lines.append(f"- Demo: {spec.get('demo_description', '?')}")
            lines.append(f"- Success criteria: {spec.get('success_criteria', '?')}")
            if spec.get("theseus_dependencies"):
                lines.append(f"- Theseus dependencies: {spec.get('theseus_dependencies')}")
            lines.append("")
            lines.append("| Deliverable | Type | Days | Reuses |")
            lines.append("|-------------|------|------|--------|")
            for d in spec.get("deliverables", []):
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

        # Theseus integration surface
        surface = card.get("theseus_integration_surface", "")
        if surface:
            lines.append(f"**Theseus Integration Surface**: {surface}")
            lines.append("")

        # Tier 3 findings
        findings = card.get("tier3_findings", [])
        if findings:
            lines.append("**Tier 3 Findings**:")
            lines.append("")
            for f in findings:
                lines.append(f"- {f}")
            lines.append("")

        # Tier 3 axis scores
        axis_scores = card.get("tier3_axis_scores", {})
        if axis_scores:
            lines.append("**Adversarial Axis Scores**:")
            lines.append("")
            lines.append("| Axis | Result |")
            lines.append("|------|--------|")
            for axis, result in axis_scores.items():
                lines.append(f"| {axis} | {result} |")
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
        print("No opportunities on the board. Run the theseus autoresearch loop first.")
        return 0

    md = render_board(board)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BOARD_MD.write_text(md)
    print(f"Rendered {len(board)} opportunities to {BOARD_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
