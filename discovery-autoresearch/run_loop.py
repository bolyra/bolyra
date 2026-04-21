"""Main orchestrator for the Bolyra Discovery AutoResearch Loop.

Flow per iteration:
  1. Create run directory: runs/iter_NNN_TIMESTAMP/
  2. Fetch signals from sources (sources/fetch_signals.py)
  3. Run Tier 1 discovery -> tier1_opportunities.json
  4. Judge/score -> tier1_scored.json, tier1_promoted.json
  5. Run Tier 2 validation -> tier2_cards.json, tier2_scored.json
  6. Run Tier 3 adversarial challenge -> tier3_challenged.json
  7. Merge APPROVED/CONDITIONAL cards into output/opportunity_board.json
  8. Re-rank by final score
  9. Append to history/opportunity_trajectory.jsonl
  10. Generate reports/discovery-r{N}.md
  11. Check plateau detector -> continue or stop

Exit conditions (from history/plateau_detector):
  - Max iterations reached (default 10)
  - 3 consecutive iterations with no opportunities scoring > 60
  - 3 consecutive iterations with no new opportunities at all
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Add history/ to import path
sys.path.insert(0, str(HERE / "history"))
sys.path.insert(0, str(HERE / "sources"))

from _shared import call_claude_cli  # noqa: E402
from scoring import score_opportunity, OpportunityScore  # noqa: E402
from run_tier2_validate import run_tier2_validate  # noqa: E402
from run_tier3_challenge import run_tier3_challenge  # noqa: E402
from history.plateau_detector import should_stop, load_trajectory, record_iteration  # noqa: E402

RUNS_DIR = HERE / "runs"
OUTPUT_DIR = HERE / "output"
REPORTS_DIR = HERE / "reports"
BOARD_PATH = OUTPUT_DIR / "opportunity_board.json"

MIN_SCORE_THRESHOLD = 60.0


# ---------------------------------------------------------------------------
# Signal fetching (imports sources/fetch_signals.py if available, else stub)
# ---------------------------------------------------------------------------


def fetch_signals(output_dir: Path, *, model: str = "opus", timeout: int = 300) -> dict:
    """Fetch market signals. Delegates to sources/fetch_signals.py if it exists."""
    fetch_module = HERE / "sources" / "fetch_signals.py"
    if fetch_module.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location("fetch_signals", fetch_module)
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        if hasattr(mod, "fetch_signals"):
            return mod.fetch_signals(output_dir, model=model, timeout=timeout)

    # Stub: read source registry and return it as-is
    registry_path = HERE / "sources" / "source_registry.json"
    if registry_path.exists():
        registry = json.loads(registry_path.read_text())
        (output_dir / "signals_raw.json").write_text(json.dumps(registry, indent=2))
        return {"sources": registry, "signal_count": sum(len(v) for v in registry.values())}
    return {"sources": {}, "signal_count": 0}


# ---------------------------------------------------------------------------
# Tier 1 discovery (imports run_tier1_discover.py if available, else stub)
# ---------------------------------------------------------------------------


def run_tier1(
    signals: dict,
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 300,
) -> dict:
    """Run Tier 1 discovery. Delegates to run_tier1_discover.py if it exists."""
    tier1_module = HERE / "run_tier1_discover.py"
    if tier1_module.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location("run_tier1_discover", tier1_module)
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        if hasattr(mod, "run_tier1"):
            return mod.run_tier1(signals, output_dir, model=model, timeout=timeout)

    # Stub: generate discovery prompt via Claude CLI
    prompt = (
        "You are a market opportunity scout for Bolyra, a ZKP identity protocol for "
        "humans and AI agents.\n\n"
        f"SIGNALS:\n{json.dumps(signals, indent=2)[:6000]}\n\n"
        "Identify 5-10 concrete market opportunities where Bolyra's ZKP identity "
        "primitives could solve a real problem. For each, provide:\n\n"
        "Return ONLY a JSON array (no markdown fences):\n"
        "[\n"
        '  {"id": "short_id", "title": "opportunity title", "description": "2-3 sentences", '
        '"category": "agentic_commerce|enterprise_auth|defi|developer_tools|standards|other", '
        '"source": "signal that triggered this", "preliminary_demand": 0-25, '
        '"preliminary_timing": 0-25, "preliminary_fit": 0-25, "preliminary_feasibility": 0-25}\n'
        "]\n"
    )
    try:
        from _shared import extract_json_array
        raw = call_claude_cli(prompt, model=model, timeout=timeout)
        opportunities = extract_json_array(raw)
    except Exception as e:
        opportunities = []
        print(f"  [tier1] discovery failed: {e}")

    (output_dir / "tier1_opportunities.json").write_text(json.dumps(opportunities, indent=2))
    return {"opportunities": opportunities, "count": len(opportunities)}


# ---------------------------------------------------------------------------
# Tier 1 judge/scoring
# ---------------------------------------------------------------------------


def judge_tier1(
    opportunities: list[dict],
    output_dir: Path,
) -> dict:
    """Score and filter Tier 1 opportunities."""
    scored: list[dict] = []
    promoted: list[dict] = []

    for opp in opportunities:
        try:
            s = score_opportunity(
                demand=max(0, min(25, int(opp.get("preliminary_demand", 0)))),
                timing=max(0, min(25, int(opp.get("preliminary_timing", 0)))),
                fit=max(0, min(25, int(opp.get("preliminary_fit", 0)))),
                feasibility=max(0, min(25, int(opp.get("preliminary_feasibility", 0)))),
                ead_classification=opp.get("ead_classification", "GREY_ZONE"),
            )
        except (ValueError, TypeError):
            s = OpportunityScore(
                demand=0, timing=0, fit=0, feasibility=0,
                total=0, verdict="DROP", ead_classification="GREY_ZONE",
            )

        entry = {
            **opp,
            "scores": {"demand": s.demand, "timing": s.timing, "fit": s.fit, "feasibility": s.feasibility, "total": s.total},
            "verdict": s.verdict,
            "ead_classification": s.ead_classification,
        }
        scored.append(entry)
        if s.verdict in ("PROMOTE", "CONSIDER"):
            promoted.append(entry)

    scored.sort(key=lambda x: x["scores"]["total"], reverse=True)
    promoted.sort(key=lambda x: x["scores"]["total"], reverse=True)

    (output_dir / "tier1_scored.json").write_text(json.dumps(scored, indent=2))
    (output_dir / "tier1_promoted.json").write_text(json.dumps(promoted, indent=2))

    return {"scored": scored, "promoted": promoted}


# ---------------------------------------------------------------------------
# Board management
# ---------------------------------------------------------------------------


def load_board() -> list[dict]:
    """Load the current opportunity board."""
    if BOARD_PATH.exists():
        return json.loads(BOARD_PATH.read_text())
    return []


def merge_into_board(
    board: list[dict],
    new_cards: list[dict],
) -> list[dict]:
    """Merge new APPROVED/CONDITIONAL cards into the board. Additive only.

    If a card with the same id already exists, update it if the new score is higher.
    """
    board_index = {card["id"]: i for i, card in enumerate(board)}

    for card in new_cards:
        cid = card.get("id", "unknown")
        if cid in board_index:
            existing = board[board_index[cid]]
            if card.get("scores", {}).get("total", 0) > existing.get("scores", {}).get("total", 0):
                board[board_index[cid]] = card
        else:
            board.append(card)

    # Re-rank by final score
    board.sort(key=lambda c: c.get("scores", {}).get("total", 0), reverse=True)
    return board


def save_board(board: list[dict]) -> None:
    """Save the opportunity board."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BOARD_PATH.write_text(json.dumps(board, indent=2))


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def write_report(
    *,
    iter_dir: Path,
    iter_num: int,
    ts: str,
    signals: dict,
    tier1_result: dict,
    judge_result: dict,
    tier2_result: dict,
    tier3_result: dict,
    board: list[dict],
) -> Path:
    """Generate the iteration report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    approved = tier3_result.get("approved", [])
    conditional = tier3_result.get("conditional", [])
    rejected = tier3_result.get("rejected", [])

    md = [
        f"# Discovery Iteration {iter_num} Report",
        "",
        f"- **Timestamp**: {ts}",
        f"- **Signal sources scanned**: {signals.get('signal_count', 0)}",
        "",
        "## Tier 1: Discovery",
        f"- Opportunities found: {tier1_result.get('count', 0)}",
        f"- Promoted to Tier 2: {len(judge_result.get('promoted', []))}",
        "",
        "## Tier 2: Validation",
        f"- Cards validated: {len(tier2_result.get('cards', []))}",
        f"- Promoted to Tier 3: {len(tier2_result.get('promoted', []))}",
        f"- Dropped: {len(tier2_result.get('dropped', []))}",
        "",
        "## Tier 3: Adversarial Challenge",
        f"- Challenged: {len(tier3_result.get('challenged', []))}",
        f"- Approved: {len(approved)}",
        f"- Conditional: {len(conditional)}",
        f"- Rejected: {len(rejected)}",
        "",
        "## Board Status",
        f"- Total opportunities on board: {len(board)}",
        "",
    ]

    # Top opportunities
    if approved or conditional:
        md.append("## Surviving Opportunities")
        md.append("")
        md.append("| Rank | Title | Score | EAD | Verdict |")
        md.append("|------|-------|-------|-----|---------|")
        for i, card in enumerate(approved + conditional, 1):
            title = card.get("title", "?")[:40]
            total = card.get("scores", {}).get("total", 0)
            ead = card.get("ead_classification", "?")
            v = card.get("tier3_verdict", "?")
            md.append(f"| {i} | {title} | {total} | {ead} | {v} |")
        md.append("")

    # Rejected findings for feedback
    if rejected:
        md.append("## Rejected (feedback for next iteration)")
        md.append("")
        for r in rejected:
            title = r.get("title", "?")
            findings = "; ".join(r.get("tier3_findings", [])[:3])
            md.append(f"- **{title}**: {findings}")
        md.append("")

    report_text = "\n".join(md)
    report_path = REPORTS_DIR / f"discovery-r{iter_num}.md"
    report_path.write_text(report_text)
    (iter_dir / "iteration_report.md").write_text(report_text)
    return report_path


# ---------------------------------------------------------------------------
# Single iteration
# ---------------------------------------------------------------------------


def run_iteration(
    iter_num: int,
    *,
    model: str = "opus",
    timeout: int = 300,
) -> dict:
    """Run one full discovery iteration."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    iter_dir = RUNS_DIR / f"iter_{iter_num:03d}_{ts}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    print(f"[iter {iter_num}] Fetching signals...")
    signals = fetch_signals(iter_dir, model=model, timeout=timeout)

    print(f"[iter {iter_num}] Tier 1: discovering opportunities...")
    tier1_result = run_tier1(signals, iter_dir, model=model, timeout=timeout)
    opportunities = tier1_result.get("opportunities", [])

    if not opportunities:
        print(f"[iter {iter_num}] No opportunities found. Recording empty iteration.")
        entry = record_iteration(
            iter_num=iter_num, ts=ts, new_opportunities=0,
            max_score=0, approved_count=0, conditional_count=0,
            rejected_count=0, high_scoring_count=0, board_size=len(load_board()),
        )
        return {"iter": iter_num, "empty": True, "trajectory_entry": entry}

    print(f"[iter {iter_num}] Judging {len(opportunities)} opportunities...")
    judge_result = judge_tier1(opportunities, iter_dir)
    promoted = judge_result.get("promoted", [])

    if not promoted:
        print(f"[iter {iter_num}] No opportunities promoted past Tier 1.")
        entry = record_iteration(
            iter_num=iter_num, ts=ts, new_opportunities=len(opportunities),
            max_score=max((o.get("scores", {}).get("total", 0) for o in judge_result.get("scored", [])), default=0),
            approved_count=0, conditional_count=0, rejected_count=0,
            high_scoring_count=0, board_size=len(load_board()),
        )
        return {"iter": iter_num, "tier1_only": True, "trajectory_entry": entry}

    print(f"[iter {iter_num}] Tier 2: validating {len(promoted)} opportunities...")
    tier2_result = run_tier2_validate(promoted, iter_dir, model=model, timeout=timeout)
    tier2_promoted = tier2_result.get("promoted", [])

    if not tier2_promoted:
        print(f"[iter {iter_num}] No opportunities survived Tier 2 validation.")
        entry = record_iteration(
            iter_num=iter_num, ts=ts, new_opportunities=len(opportunities),
            max_score=max((c.get("scores", {}).get("total", 0) for c in tier2_result.get("cards", [])), default=0),
            approved_count=0, conditional_count=0, rejected_count=0,
            high_scoring_count=0, board_size=len(load_board()),
        )
        return {"iter": iter_num, "tier2_only": True, "trajectory_entry": entry}

    print(f"[iter {iter_num}] Tier 3: challenging {len(tier2_promoted)} opportunities...")
    tier3_result = run_tier3_challenge(tier2_promoted, iter_dir, model=model, timeout=timeout)

    # Merge surviving cards into board
    approved = tier3_result.get("approved", [])
    conditional = tier3_result.get("conditional", [])
    rejected = tier3_result.get("rejected", [])

    surviving = approved + conditional
    board = load_board()
    board = merge_into_board(board, surviving)
    save_board(board)

    # Compute stats
    all_scores = [c.get("scores", {}).get("total", 0) for c in tier2_result.get("cards", [])]
    max_score = max(all_scores) if all_scores else 0
    high_scoring_count = sum(1 for s in all_scores if s > MIN_SCORE_THRESHOLD)

    # Record trajectory
    entry = record_iteration(
        iter_num=iter_num,
        ts=ts,
        new_opportunities=len(opportunities),
        max_score=max_score,
        approved_count=len(approved),
        conditional_count=len(conditional),
        rejected_count=len(rejected),
        high_scoring_count=high_scoring_count,
        board_size=len(board),
    )

    # Generate report
    report_path = write_report(
        iter_dir=iter_dir,
        iter_num=iter_num,
        ts=ts,
        signals=signals,
        tier1_result=tier1_result,
        judge_result=judge_result,
        tier2_result=tier2_result,
        tier3_result=tier3_result,
        board=board,
    )
    print(f"[iter {iter_num}] Report: {report_path}")

    return {
        "iter": iter_num,
        "approved": len(approved),
        "conditional": len(conditional),
        "rejected": len(rejected),
        "board_size": len(board),
        "trajectory_entry": entry,
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="Bolyra Discovery AutoResearch Loop orchestrator")
    ap.add_argument("--max-iterations", type=int, default=10,
                    help="Maximum number of iterations (default: 10)")
    ap.add_argument("--model", default="opus",
                    help="Claude model alias (default: opus)")
    ap.add_argument("--timeout", type=int, default=300,
                    help="Per-call timeout in seconds (default: 300)")
    args = ap.parse_args()

    print("=" * 60)
    print("  Bolyra Discovery AutoResearch Loop")
    print("=" * 60)
    print(f"  Max iterations: {args.max_iterations}")
    print(f"  Model: {args.model}")
    print(f"  Timeout: {args.timeout}s")
    print()

    for i in range(1, args.max_iterations + 1):
        # Check plateau detector
        trajectory = load_trajectory()
        stop, reason = should_stop(trajectory, max_iters=args.max_iterations)
        if stop:
            print(f"Stopping: {reason}")
            break

        print(f"\n{'='*40} Iteration {i} {'='*40}")
        result = run_iteration(i, model=args.model, timeout=args.timeout)
        print(f"[iter {i}] Complete. Board size: {result.get('board_size', '?')}")

    # Final summary
    board = load_board()
    print(f"\nLoop complete. Final board: {len(board)} opportunities.")
    if board:
        print("\nTop 5:")
        for i, card in enumerate(board[:5], 1):
            title = card.get("title", "?")[:50]
            total = card.get("scores", {}).get("total", 0)
            ead = card.get("ead_classification", "?")
            print(f"  {i}. [{total}] {title} ({ead})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
