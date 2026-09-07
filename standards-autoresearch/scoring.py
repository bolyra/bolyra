"""Standard-ness score (0-100) per rubrics/standardness_rubric.md.

Four dims computed objectively from reconciled truth + repo state; only
ECOSYSTEM POSITION (20) is judged, by Codex, against the rubric anchors.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from _codex import call_codex_json

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE / "checks"))
import run_conformance  # noqa: E402

# Known independent implementations (external code passing conformance at a pin).
# Extend via evidence_ledger entries with kind=implementation.
KNOWN_IMPLEMENTATIONS = [
    {"who": "khandrew1/mcp-use-evc-example", "pinned": "17642a5",
     "rfc7942_listable": True, "external": True},
]


def _ledger_entries() -> list[dict]:
    path = HERE / "output" / "evidence_ledger.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def score_implementations() -> dict[str, Any]:
    ledger_impls = [e for e in _ledger_entries() if e.get("kind") == "implementation"]
    impls = {i["who"] for i in KNOWN_IMPLEMENTATIONS} | {e.get("subject") for e in ledger_impls}
    pts = min(len(impls) * 8, 16)
    if any(i.get("rfc7942_listable") for i in KNOWN_IMPLEMENTATIONS) or any(
            e.get("rfc7942_ready") for e in ledger_impls):
        pts += 5
    if (REPO / "spec" / "reference-host-rs").exists():
        pts += 4
    return {"points": min(pts, 25), "implementations": sorted(x for x in impls if x)}


def _must_coverage() -> float:
    """Fraction of normative MUST sentences with a plausibly-covering vector.

    Heuristic v1: count MUST/MUST NOT sentences in the contract; count
    host_behavior vectors; coverage = min(1, vectors / MUSTs). Refine later
    with an explicit clause->vector map.
    """
    contract = REPO / "spec" / "external-verifier-contract-v1.md"
    if not contract.exists():
        return 0.5
    musts = len(re.findall(r"\bMUST(?: NOT)?\b", contract.read_text()))
    tv = json.loads((REPO / "spec" / "test-vectors.json").read_text())
    vectors = sum(1 for v in tv["vectors"] if v.get("type") == "host_behavior")
    if musts == 0:
        return 1.0
    return max(0.5, min(1.0, vectors / musts))


def score_spec_hardness() -> dict[str, Any]:
    open_findings = 0
    staged = HERE / "output" / "staged"
    if staged.exists():
        for apply_md in staged.rglob("APPLY.md"):
            # type is authoritative in the title line: "# APPLY — <id> (<type>)"
            # (a substring grep miscounted: the boilerplate itself mentions
            # "spec_finding only" — Codex review, iteration 3)
            first = apply_md.read_text().splitlines()[0] if apply_md.read_text() else ""
            if first.rstrip().endswith("(spec_finding)"):
                open_findings += 1
    base = max(0, 20 - 3 * open_findings)
    coverage = _must_coverage()
    return {"points": round(base * coverage, 1),
            "open_confirmed_findings": open_findings, "must_coverage": round(coverage, 2)}


def score_interop_evidence() -> dict[str, Any]:
    entries = _ledger_entries()
    reproducible = [e for e in entries if e.get("pinned_commit") and e.get("reproduce_cmd")]
    pts = min(len(reproducible) * 4, 16)
    if sum(1 for e in entries if e.get("rfc7942_ready")) >= 2:
        pts += 4
    return {"points": min(pts, 20), "reproducible_entries": len(reproducible)}


def score_registry_closure(reconcile_result: dict | None) -> dict[str, Any]:
    pts = 0
    sync = run_conformance.run_sync_check()
    if sync.get("ok"):
        pts += 5
    tv = json.loads((REPO / "spec" / "test-vectors.json").read_text())
    if tv.get("version"):
        pts += 5  # vector-set version present/aligned (refine with spec version map)
    staged = HERE / "output" / "staged"
    has_02_material = staged.exists() and any(
        "rfc7942" in p.read_text().lower() or "implementation status" in p.read_text().lower()
        for p in staged.rglob("evidence.md"))
    if has_02_material:
        pts += 5
    return {"points": pts, "sync_check": sync.get("ok", False)}


def score_ecosystem_position(*, timeout: int = 600) -> dict[str, Any]:
    rubric = (HERE / "rubrics" / "standardness_rubric.md").read_text()
    boards = {}
    for name in ("threat_board.json", "adoption_board.json"):
        p = HERE / "output" / name
        boards[name] = json.loads(p.read_text()) if p.exists() else []
    prompt = (
        "Score ECOSYSTEM POSITION (0-20) for Bolyra/EVC per the anchors in this "
        "rubric. Judge conservatively; between anchors take the lower band. You "
        "have repo access; the boards below are reconciled ground truth.\n\n"
        + rubric + "\n\n## Boards\n" + json.dumps(boards, indent=2)[:12000]
        + '\n\nReturn ONE JSON object: {"points": 0, "band": "...", "reason": "..."}'
    )
    try:
        result = call_codex_json(prompt, timeout=timeout)
        pts = result.get("points", 0)
        if not isinstance(pts, (int, float)) or not (0 <= pts <= 20):
            return {"points": 0, "error": f"invalid points from judge: {pts!r}"}
        return result
    except RuntimeError as e:
        return {"points": 0, "error": str(e)[:300]}


def score_all(reconcile_result: dict | None = None, *, judge: bool = True) -> dict[str, Any]:
    dims = {
        "implementations": score_implementations(),
        "spec_hardness": score_spec_hardness(),
        "interop_evidence": score_interop_evidence(),
        "registry_closure": score_registry_closure(reconcile_result),
        "ecosystem_position": (score_ecosystem_position() if judge
                               else {"points": 0, "skipped": True}),
    }
    total = round(sum(d["points"] for d in dims.values()), 1)
    return {"total": total, **dims}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-judge", action="store_true",
                    help="skip the Codex ecosystem-position call")
    args = ap.parse_args()
    print(json.dumps(score_all(judge=not args.no_judge), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
