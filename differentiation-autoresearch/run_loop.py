"""Orchestrator for the differentiation-autoresearch loop.

Per candidate, iterate tier1 -> tier2 -> tier3 -> judge -> mutator until strength=10
or a plateau/max-iters is hit.

CLI:
  python run_loop.py --candidate C2 --max-iters 5 --no-codex
  python run_loop.py --all
  python run_loop.py --candidate C5 --auto-approve

Trajectory: history/score_trajectory.jsonl (one entry per iteration per candidate).
Winners: winners/C{N}/ when strength=10.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import tier1_survey
import tier2_construct
import tier3_adversarial
import judge
import mutator
from plateau_detector import should_stop

HERE = Path(__file__).resolve().parent
RUNS_DIR = HERE / "runs"
HISTORY_DIR = HERE / "history"
TRAJECTORY_PATH = HISTORY_DIR / "score_trajectory.jsonl"
WINNERS_DIR = HERE / "winners"
CANDIDATES_PATH = HERE / "candidates.json"


def _load_candidates() -> list[dict]:
    return json.loads(CANDIDATES_PATH.read_text())["candidates"]


def _get_candidate(cid: str) -> dict:
    for c in _load_candidates():
        if c["id"] == cid:
            return c
    raise SystemExit(f"unknown candidate id: {cid}")


def _load_trajectory_for(candidate_id: str) -> list[dict]:
    if not TRAJECTORY_PATH.exists():
        return []
    entries: list[dict] = []
    for line in TRAJECTORY_PATH.read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("candidate_id") == candidate_id:
            entries.append(entry)
    return entries


def _record_trajectory(entry: dict) -> None:
    TRAJECTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with TRAJECTORY_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _promote_winner(candidate_id: str, iter_dir: Path) -> Path:
    dest = WINNERS_DIR / candidate_id
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("construction.md", "attacks.md", "score.json", "baseline.md"):
        src = iter_dir / name
        if src.exists():
            shutil.copy2(src, dest / name)
    return dest


def run_candidate(
    candidate_id: str,
    *,
    max_iters: int = 5,
    use_codex: bool = True,
    judge_model: str = "opus",
    construct_model: str = "opus",
    survey_model: str = "sonnet",
    attack_model: str = "sonnet",
) -> dict:
    """Run the loop for a single candidate. Return final score dict."""
    candidate = _get_candidate(candidate_id)
    print(f"\n========== {candidate_id}: {candidate['title']} ==========")
    print(f"Current strength: {candidate['current_strength']} → target: {candidate['target_strength']}")

    for iteration in range(1, max_iters + 1):
        # Plateau check BEFORE starting iteration
        trajectory = _load_trajectory_for(candidate_id)
        traj_for_plateau = [{"iter": e["iter"], "total": e["strength"]} for e in trajectory]
        stop, reason = should_stop(traj_for_plateau, max_iters=max_iters)
        if stop:
            print(f"[{candidate_id}] stop: {reason}")
            break

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        iter_dir = RUNS_DIR / f"iter_{iteration:03d}_{ts}" / candidate_id
        iter_dir.mkdir(parents=True, exist_ok=True)
        print(f"[{candidate_id}] iter {iteration} → {iter_dir}", flush=True)

        try:
            # Tier 1: baseline survey (only on first iteration; reuse thereafter)
            prev_iter_dir = _last_iter_dir(candidate_id, iteration - 1)
            if iteration == 1 or not (prev_iter_dir and (prev_iter_dir / "baseline.md").exists()):
                print(f"[{candidate_id}] Tier 1: survey baseline...", flush=True)
                tier1_survey.run(candidate, iter_dir, model=survey_model)
            else:
                shutil.copy2(prev_iter_dir / "baseline.md", iter_dir / "baseline.md")

            # Tier 2: construct (or refine if prior exists)
            prior_construction = None
            gaps: list[str] = []
            if prev_iter_dir and (prev_iter_dir / "construction.md").exists() and (prev_iter_dir / "score.json").exists():
                prior_construction = prev_iter_dir / "construction.md"
                prev_score = json.loads((prev_iter_dir / "score.json").read_text())
                gaps = prev_score.get("gaps", [])  # tier2 refinement uses only gaps[0]
                # Copy prior construction into current iter dir first — tier2 refines in place
                shutil.copy2(prior_construction, iter_dir / "construction.md")
                print(f"[{candidate_id}] Tier 2: refine with {len(gaps)} gap(s)...", flush=True)
                mutator.run(candidate, iter_dir, gaps=gaps, model=construct_model)
            else:
                print(f"[{candidate_id}] Tier 2: construct from baseline...", flush=True)
                tier2_construct.run(candidate, iter_dir, model=construct_model)

            # Tier 3: adversarial
            print(f"[{candidate_id}] Tier 3: adversarial ({len(list((HERE / 'personas').glob('*.json')))} personas{' + codex' if use_codex else ''})...", flush=True)
            tier3_adversarial.run(candidate, iter_dir, model=attack_model, use_codex=use_codex)

            # Judge
            print(f"[{candidate_id}] Judge: scoring...", flush=True)
            score = judge.run(candidate, iter_dir, model=judge_model)
        except Exception as exc:
            print(f"[{candidate_id}] iter {iteration} FAILED: {type(exc).__name__}: {exc}", flush=True)
            _record_trajectory({
                "candidate_id": candidate_id,
                "iter": iteration,
                "ts": ts,
                "strength": 0,
                "verdict": "error",
                "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                "iter_dir": str(iter_dir.relative_to(HERE)),
            })
            continue

        strength = score["strength"]
        print(f"[{candidate_id}] iter {iteration}: strength={strength}/10 verdict={score['verdict']}", flush=True)
        for dim, d in score["dims"].items():
            print(f"      {dim}: {d['points']}/2 — {d['justification'][:80]}", flush=True)

        # Record trajectory
        _record_trajectory({
            "candidate_id": candidate_id,
            "iter": iteration,
            "ts": ts,
            "strength": strength,
            "verdict": score["verdict"],
            "iter_dir": str(iter_dir.relative_to(HERE)),
        })

        if strength == 10:
            dest = _promote_winner(candidate_id, iter_dir)
            print(f"[{candidate_id}] PROMOTED → {dest}")
            return score

    # Loop exited without hitting 10
    traj = _load_trajectory_for(candidate_id)
    if traj:
        return {"candidate_id": candidate_id, "strength": traj[-1]["strength"], "verdict": "escalate"}
    return {"candidate_id": candidate_id, "strength": 0, "verdict": "escalate"}


def _last_iter_dir(candidate_id: str, iter_num: int) -> Path | None:
    """Find the most recent iter_NNN_TS/{candidate_id}/ directory for this candidate."""
    if iter_num < 1:
        return None
    matches = sorted(RUNS_DIR.glob(f"iter_{iter_num:03d}_*/{candidate_id}"))
    return matches[-1] if matches else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", help="Run a single candidate (e.g., C2)")
    ap.add_argument("--all", action="store_true", help="Run all candidates sequentially")
    ap.add_argument("--max-iters", type=int, default=5)
    ap.add_argument("--no-codex", action="store_true", help="Skip codex Tier 3 (faster, persona-only)")
    ap.add_argument("--judge-model", default="opus")
    ap.add_argument("--construct-model", default="opus")
    ap.add_argument("--survey-model", default="sonnet")
    ap.add_argument("--attack-model", default="sonnet")
    args = ap.parse_args()

    if not args.candidate and not args.all:
        ap.error("must pass --candidate or --all")

    candidates = _load_candidates() if args.all else [_get_candidate(args.candidate)]
    final_scores: dict[str, dict] = {}
    for c in candidates:
        score = run_candidate(
            c["id"],
            max_iters=args.max_iters,
            use_codex=not args.no_codex,
            judge_model=args.judge_model,
            construct_model=args.construct_model,
            survey_model=args.survey_model,
            attack_model=args.attack_model,
        )
        final_scores[c["id"]] = score

    print("\n========== SUMMARY ==========")
    for cid, score in final_scores.items():
        print(f"  {cid}: strength={score.get('strength', '?')}/10  verdict={score.get('verdict', '?')}")
    all_ten = all(s.get("strength") == 10 for s in final_scores.values())
    if all_ten:
        print("\nALL CANDIDATES AT 10/10 — convergence reached.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
