"""Tier 1: persona fan-out (Fable 5.1) + candidate ranking (Codex judge).

Six personas each get program.md + spec excerpts + reconciled boards + fresh
signals + prior REJECT findings, and emit typed candidates. Codex scores the
pooled candidates against rubrics/tier1_rubric.md. Winners land in
<iter_dir>/tier1_winners.json for the human gate.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_array
from _codex import call_codex_json, GENERATOR_MODEL
from _render import render

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SPEC_FILES = [
    "spec/external-verifier-contract-v1.md",
    "spec/draft-kondoju-evc-01.md",
]
MAX_CANDIDATES_PER_PERSONA = 4
SPEC_EXCERPT_CHARS = 24000

ENGAGEMENT_GRAPH = Path.home() / "Projects" / ".viswa" / "projects" / "bolyra-engagement-graph.md"
HOLD_MARKERS = re.compile(r"no nudges|ball in (his|her|their) court|BALL IN|awaiting|HOLD RULE", re.I)


def _spec_commit() -> str:
    p = subprocess.run(["git", "log", "-1", "--format=%H", "--", "spec/"],
                       capture_output=True, text=True, cwd=REPO)
    return p.stdout.strip()


def _spec_excerpt() -> str:
    parts = []
    for rel in SPEC_FILES:
        f = REPO / rel
        if f.exists():
            parts.append(f"### {rel}\n\n{f.read_text()[:SPEC_EXCERPT_CHARS]}")
    return "\n\n".join(parts) or "(no spec files found)"


def _vector_index() -> str:
    tv = REPO / "spec" / "test-vectors.json"
    if not tv.exists():
        return "(test-vectors.json missing)"
    doc = json.loads(tv.read_text())
    rows = [f"- {v['id']}: {v['description'][:110]}"
            for v in doc["vectors"] if v.get("type") == "host_behavior"]
    return f"vector set {doc['version']}, {len(rows)} host_behavior vectors:\n" + "\n".join(rows)


def _boards_summary() -> str:
    out = []
    for name in ("threat_board.json", "adoption_board.json"):
        path = HERE / "output" / name
        cards = json.loads(path.read_text()) if path.exists() else []
        lines = [f"- [{c.get('state')}] {c.get('id')}: {c.get('title')}" for c in cards]
        out.append(f"### {name} ({len(cards)} cards)\n" + ("\n".join(lines) or "(empty)"))
    return "\n\n".join(out)


def held_entities() -> list[str]:
    """Best-effort list of entity names near hold markers in the engagement graph."""
    if not ENGAGEMENT_GRAPH.exists():
        return []
    held: list[str] = []
    for line in ENGAGEMENT_GRAPH.read_text().splitlines():
        if line.lstrip().startswith("- **") and HOLD_MARKERS.search(line):
            m = re.match(r"\s*-\s*\*\*([^*]+)\*\*", line)
            if m:
                held.append(m.group(1).strip())
    return held


def run_personas(iter_dir: Path, *, timeout: int, signals: str,
                 reject_findings: str) -> list[dict[str, Any]]:
    program = (HERE / "program.md").read_text()
    template = (HERE / "templates" / "tier1_attack.md").read_text()
    personas = json.loads((HERE / "personas" / "personas.json").read_text())
    common = dict(
        program=program,
        spec_commit=_spec_commit(),
        spec_excerpt=_spec_excerpt(),
        vector_set="0.6.0",
        vector_index=_vector_index(),
        reconcile_ts="this iteration (Stage 0a)",
        boards_summary=_boards_summary(),
        signals=signals or "(none this iteration)",
        reject_findings=reject_findings or "(none)",
        max_candidates=MAX_CANDIDATES_PER_PERSONA,
    )
    all_candidates: list[dict[str, Any]] = []
    for group in ("attack", "scout"):
        for persona in personas[group]:
            prompt = render(template, persona_prompt=persona["prompt"], **common)
            try:
                raw = call_claude_cli(prompt, model=GENERATOR_MODEL, timeout=timeout)
                cands = extract_json_array(raw)
            except (RuntimeError, ValueError) as e:
                # error stub, never an exception (program.md 9)
                all_candidates.append({"id": f"{persona['id']}-error",
                                       "type": "error_stub", "error": str(e)[:300]})
                continue
            for c in cands:
                c["persona"] = persona["id"]
            all_candidates.extend(cands)
            print(f"  persona {persona['id']}: {len(cands)} candidates")
    (iter_dir / "tier1_candidates.json").write_text(json.dumps(all_candidates, indent=2))
    return all_candidates


def judge(candidates: list[dict], iter_dir: Path, *, timeout: int) -> list[dict]:
    real = [c for c in candidates if c.get("type") != "error_stub"]
    if not real:
        (iter_dir / "tier1_winners.json").write_text("[]\n")
        return []
    template = (HERE / "templates" / "tier1_judge.md").read_text()
    prompt = render(
        template,
        program=(HERE / "program.md").read_text(),
        rubric=(HERE / "rubrics" / "tier1_rubric.md").read_text(),
        held_entities=json.dumps(held_entities()),
        candidates=json.dumps(real, indent=2),
    )
    verdict = call_codex_json(prompt, timeout=timeout)
    scored = verdict.get("scored", [])
    (iter_dir / "tier1_scored.json").write_text(json.dumps(scored, indent=2))
    by_id = {c["id"]: c for c in real}
    winners = []
    for s in scored:
        if s.get("verdict") == "PROMOTE" and s.get("id") in by_id:
            w = dict(by_id[s["id"]])
            w["score"] = s
            winners.append(w)
    (iter_dir / "tier1_winners.json").write_text(json.dumps(winners, indent=2))
    return winners


def run_tier1(iter_dir: Path, *, timeout: int = 420,
              signals: str = "", reject_findings: str = "") -> dict[str, Any]:
    iter_dir.mkdir(parents=True, exist_ok=True)
    candidates = run_personas(iter_dir, timeout=timeout, signals=signals,
                              reject_findings=reject_findings)
    winners = judge(candidates, iter_dir, timeout=timeout + 180)
    return {"candidates": candidates, "winners": winners}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--timeout", type=int, default=420)
    args = ap.parse_args()
    result = run_tier1(Path(args.output_dir), timeout=args.timeout)
    print(f"Tier 1: {len(result['candidates'])} candidates, {len(result['winners'])} winners")
    return 0


if __name__ == "__main__":
    sys.exit(main())
