"""Tier 2: build typed artifacts (Fable 5.1) + objective checks + Codex acceptance.

Per Tier-1 winner:
  spec_finding         -> experiments/<id>/spec-diff.md   (check_spec_diff)
  vector_gap           -> experiments/<id>/vector.json    (check_vectors)
  evidence_opportunity -> experiments/<id>/evidence.md    (shape check)
  threat_update / adoption_target -> board card update (no artifact build)

Hard objective-check failure drops the candidate. Survivors get a Codex
acceptance verdict (APPROVE / REVISE once / DROP) before Tier 3.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import re

from _shared import extract_json_object
from _codex import call_codex_json
from _fable import call_fable
from _render import render

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
EXPERIMENTS = HERE / "experiments"

# Model-produced candidate IDs become directory names; constrain them hard
# (Codex review finding: path traversal via crafted IDs).
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,100}$")  # iter-2: len 64->100; iter-4: allow dots (ids carry version numbers); resolve() guard backstops traversal


def safe_experiment_dir(cid: str) -> Path:
    if not SAFE_ID.fullmatch(cid):
        raise ValueError(f"unsafe candidate id: {cid!r}")
    path = (EXPERIMENTS / cid).resolve()
    if not path.is_relative_to(EXPERIMENTS.resolve()):
        raise ValueError(f"candidate id escapes experiments/: {cid!r}")
    return path
sys.path.insert(0, str(HERE / "checks"))
import check_vectors  # noqa: E402
import check_spec_diff  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _spec_commit() -> str:
    p = subprocess.run(["git", "log", "-1", "--format=%H", "--", "spec/"],
                       capture_output=True, text=True, cwd=REPO)
    return p.stdout.strip()


def _vector_context() -> tuple[str, str]:
    doc = json.loads((REPO / "spec" / "test-vectors.json").read_text())
    hb = [v for v in doc["vectors"] if v.get("type") == "host_behavior"]
    schema = json.dumps(hb[:2], indent=2)
    fixture_dir = REPO / "spec" / "fixtures" / "host-conformance"
    example = ""
    for name in ("bad-kind.js", "well-behaved-allow.js"):
        f = fixture_dir / name
        if f.exists():
            example = f"// {name}\n{f.read_text()}"
            break
    return schema, example


def _build_spec_finding(candidate: dict, exp_dir: Path, *, timeout: int) -> dict:
    template = (HERE / "templates" / "tier2_spec_diff.md").read_text()
    target_rel = "spec/external-verifier-contract-v1.md"
    spec_files = f"### {target_rel}\n\n{(REPO / target_rel).read_text()[:30000]}"
    prompt = render(template, program=(HERE / "program.md").read_text(),
                             candidate=json.dumps(candidate, indent=2),
                             spec_commit=_spec_commit(), spec_files=spec_files)
    artifact = call_fable(prompt, timeout=timeout)
    path = exp_dir / "spec-diff.md"
    path.write_text(artifact)
    return check_spec_diff.check(path)


def _build_vector_gap(candidate: dict, exp_dir: Path, *, timeout: int) -> dict:
    template = (HERE / "templates" / "tier2_vector.md").read_text()
    schema, fixture_example = _vector_context()
    prompt = render(template, program=(HERE / "program.md").read_text(),
                             candidate=json.dumps(candidate, indent=2),
                             vector_set="0.6.0", vector_schema=schema,
                             fixture_example=fixture_example)
    raw = call_fable(prompt, timeout=timeout)
    artifact = extract_json_object(raw)
    (exp_dir / "vector.json").write_text(json.dumps(artifact, indent=2))
    return check_vectors.check(artifact)


def _build_evidence(candidate: dict, exp_dir: Path, *, timeout: int) -> dict:
    template = (HERE / "templates" / "tier2_evidence.md").read_text()
    ledger = HERE / "output" / "evidence_ledger.jsonl"
    tail = "\n".join(ledger.read_text().splitlines()[-5:]) if ledger.exists() else "(empty)"
    prompt = render(template, program=(HERE / "program.md").read_text(),
                             candidate=json.dumps(candidate, indent=2),
                             ledger_tail=tail)
    artifact = call_fable(prompt, timeout=timeout)
    (exp_dir / "evidence.md").write_text(artifact)
    if artifact.strip().startswith("BLOCKED"):
        return {"ok": False, "stage": "shape", "errors": ["builder reported outbound required"]}
    has_entry = '"kind"' in artifact and '"reproduce_cmd"' in artifact
    return {"ok": has_entry, "stage": "shape",
            "errors": [] if has_entry else ["no ledger entry JSON found"]}


BUILDERS = {
    "spec_finding": _build_spec_finding,
    "vector_gap": _build_vector_gap,
    "evidence_opportunity": _build_evidence,
}

ARTIFACT_FILE = {
    "spec_finding": "spec-diff.md",
    "vector_gap": "vector.json",
    "evidence_opportunity": "evidence.md",
}


def _codex_acceptance(candidate: dict, exp_dir: Path, checks: dict,
                      *, timeout: int) -> dict:
    artifact_file = ARTIFACT_FILE[candidate["type"]]
    artifact_text = (exp_dir / artifact_file).read_text()[:20000]
    prompt = (
        "Tier 2 acceptance gate for the Bolyra standards-autoresearch loop. "
        "Judge whether this artifact is worth adversarial review (Tier 3). "
        "APPROVE = advance; REVISE = one concrete revision instruction; DROP = not salvageable. "
        "Program rules (violations are DROP):\n\n"
        + (HERE / "program.md").read_text()
        + "\n\n## Candidate\n" + json.dumps(candidate, indent=2)
        + "\n\n## Artifact (" + artifact_file + ")\n" + artifact_text
        + "\n\n## Objective checks\n" + json.dumps(checks, indent=2)
        + '\n\nReturn ONE JSON object: {"verdict": "APPROVE|REVISE|DROP", '
          '"instruction": "only for REVISE", "reason": "one sentence"}'
    )
    return call_codex_json(prompt, timeout=timeout)


def _safe_acceptance(candidate: dict, exp_dir: Path, checks: dict,
                     *, timeout: int) -> tuple[dict, bool]:
    """Codex acceptance with outage containment: on any failure, persist the
    FULL exception to acceptance_error.txt and hold the artifact (never crash,
    never lose the diagnostic — applies to initial AND post-revision calls)."""
    try:
        return _codex_acceptance(candidate, exp_dir, checks, timeout=timeout), False
    except Exception as e:
        (exp_dir / "acceptance_error.txt").write_text(f"{type(e).__name__}: {e}")
        return {"verdict": "ERROR",
                "reason": f"{type(e).__name__}: {str(e)[:280]}",
                "full_error": str(exp_dir / "acceptance_error.txt")}, True


def build_one(candidate: dict, iter_dir: Path, *, timeout: int) -> dict[str, Any]:
    cid = candidate["id"]
    ctype = candidate.get("type", "")
    entry: dict[str, Any] = {"candidate": candidate, "id": cid, "type": ctype}

    if ctype in ("threat_update", "adoption_target"):
        entry["action"] = "board_update"
        return entry

    builder = BUILDERS.get(ctype)
    if builder is None:
        entry.update(action="dropped", reason=f"unknown type {ctype}")
        return entry

    try:
        exp_dir = safe_experiment_dir(cid)
    except ValueError as e:
        entry.update(action="dropped", reason=str(e))
        return entry
    exp_dir.mkdir(parents=True, exist_ok=True)
    entry["experiment_dir"] = str(exp_dir)
    try:
        checks = builder(candidate, exp_dir, timeout=timeout)
    except Exception as e:  # error stub, never a crash: model artifacts are
        # untrusted input and any malformed shape must drop, not halt the loop
        checks = {"ok": False, "stage": "build",
                  "errors": [f"{type(e).__name__}: {str(e)[:280]}"]}
    (exp_dir / "checks.json").write_text(json.dumps(checks, indent=2))
    entry["checks"] = checks

    if not checks.get("ok"):
        entry["action"] = "dropped_objective_check"
        return entry

    verdict, held = _safe_acceptance(candidate, exp_dir, checks, timeout=timeout + 180)
    if held:
        entry["acceptance"] = verdict
        entry["action"] = "held_judge_unavailable"
        return entry
    entry["acceptance"] = verdict

    if verdict.get("verdict") == "REVISE" and verdict.get("instruction"):
        # one revision pass, then re-check + re-judge once
        revise_prompt = (
            "Revise the artifact below per the single instruction. Return ONLY the "
            "corrected artifact in the same format.\n\nInstruction: "
            + verdict["instruction"] + "\n\nArtifact:\n"
            + (exp_dir / ARTIFACT_FILE[ctype]).read_text()
        )
        try:
            revised = call_fable(revise_prompt, timeout=timeout)
            if ctype == "vector_gap":
                artifact = extract_json_object(revised)
                (exp_dir / "vector.json").write_text(json.dumps(artifact, indent=2))
                checks = check_vectors.check(artifact)
            else:
                (exp_dir / ARTIFACT_FILE[ctype]).write_text(revised)
                checks = (check_spec_diff.check(exp_dir / "spec-diff.md")
                          if ctype == "spec_finding" else {"ok": True, "stage": "shape"})
            (exp_dir / "checks.json").write_text(json.dumps(checks, indent=2))
            entry["checks"] = checks
            if checks.get("ok"):
                verdict, held = _safe_acceptance(candidate, exp_dir, checks,
                                                 timeout=timeout + 180)
                entry["acceptance"] = verdict
                if held:
                    entry["action"] = "held_judge_unavailable"
                    return entry
        except (RuntimeError, ValueError) as e:
            entry["revision_error"] = str(e)[:300]

    entry["action"] = ("advance" if entry.get("acceptance", {}).get("verdict") == "APPROVE"
                       and entry["checks"].get("ok") else "dropped_acceptance")
    return entry


def run_tier2(winners: list[dict], iter_dir: Path, *, timeout: int = 600) -> dict[str, Any]:
    iter_dir.mkdir(parents=True, exist_ok=True)
    results = [build_one(w, iter_dir, timeout=timeout) for w in winners]
    advanced = [r for r in results if r.get("action") == "advance"]
    board_updates = [r for r in results if r.get("action") == "board_update"]
    (iter_dir / "tier2_results.json").write_text(json.dumps(results, indent=2, default=str))
    (iter_dir / "tier2_winners.json").write_text(json.dumps(advanced, indent=2, default=str))
    return {"experiments": results, "winners": advanced, "board_updates": board_updates}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--winners", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()
    winners = json.loads(Path(args.winners).read_text())
    result = run_tier2(winners, Path(args.output_dir), timeout=args.timeout)
    print(f"Tier 2: {len(result['experiments'])} built, {len(result['winners'])} advanced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
