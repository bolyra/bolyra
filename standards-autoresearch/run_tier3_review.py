"""Tier 3: Codex adversarial review of Tier-2 survivors.

APPROVE     -> copy artifact package to output/staged/<date>/<id>/ + APPLY.md
CONDITIONAL -> concerns recorded; artifact stays in experiments/
REJECT      -> findings feed the next iteration's Tier 1
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from _codex import call_codex_json
from run_tier2_build import SAFE_ID

HERE = Path(__file__).resolve().parent
STAGED = HERE / "output" / "staged"
EXPERIMENTS = HERE / "experiments"

ARTIFACT_FILE = {
    "spec_finding": "spec-diff.md",
    "vector_gap": "vector.json",
    "evidence_opportunity": "evidence.md",
}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _apply_md(entry: dict, artifact_file: str) -> str:
    ctype = entry["type"]
    base = ""
    if ctype == "spec_finding":
        base = entry.get("checks", {}).get("base", "(see spec-diff.md header)")
    steps = {
        "spec_finding": (
            "1. Re-validate the pin: `git log -1 --format=%H -- spec/` must still start with the Base-Commit above; if not, REGENERATE via the loop, do not hand-port.\n"
            "2. Apply the ```diff block to the Target-File by hand (it is deliberately small).\n"
            "3. `node spec/conformance-runner.js --type host_behavior` — must stay green.\n"
            "4. `node integrations/evc-conformance/scripts/sync.js` then `npm run sync:check` equivalent.\n"
            "5. CODEOWNERS gates spec/ — self-review carefully; commit with `git commit -s`."
        ),
        "vector_gap": (
            "1. Copy `fixture_js` (if present) to `spec/fixtures/host-conformance/<fixture_name>` (chmod +x).\n"
            "2. Append the `vector` object to `spec/test-vectors.json` vectors[] and bump the vector-set MINOR version (additive).\n"
            "3. `node spec/conformance-runner.js --type host_behavior` — all vectors incl. the new one must pass.\n"
            "4. `node integrations/evc-conformance/scripts/sync.js`; plan an @bolyra/evc-conformance minor release (annotated tag).\n"
            "5. CODEOWNERS gates these paths; commit with `git commit -s`."
        ),
        "evidence_opportunity": (
            "1. Execute the pinned commands in evidence.md and confirm outputs match.\n"
            "2. Append the ledger-entry JSON (bottom of evidence.md) to standards-autoresearch/output/evidence_ledger.jsonl with today's date and the iter number.\n"
            "3. If rfc7942_ready: fold into the -02 implementation-status material."
        ),
    }[ctype]
    return (
        f"# APPLY — {entry['id']} ({ctype})\n\n"
        f"Staged by standards-autoresearch on {_today()}. The loop never applies;\n"
        f"you do. Base commit (spec_finding only): `{base}`\n\n"
        f"## Steps\n\n{steps}\n\n"
        f"## Codex Tier-3 verdict\n\n```json\n{json.dumps(entry.get('tier3', {}), indent=2)}\n```\n"
    )


def review_one(entry: dict, iter_dir: Path, *, timeout: int) -> dict[str, Any]:
    ctype = entry["type"]
    exp_dir = Path(entry["experiment_dir"]).resolve()
    # id + path containment (Codex review finding: traversal via crafted ids)
    if not SAFE_ID.fullmatch(str(entry.get("id", ""))) or not exp_dir.is_relative_to(
            EXPERIMENTS.resolve()):
        return {**entry, "tier3": {"verdict": "REJECT",
                "findings": ["unsafe id or experiment path"], "summary": "containment"},
                "action": "rejected"}
    artifact_file = ARTIFACT_FILE[ctype]
    artifact_path = exp_dir / artifact_file
    if not artifact_path.exists():
        return {**entry, "tier3": {"verdict": "REJECT",
                "findings": ["artifact file missing"], "summary": "missing artifact"},
                "action": "rejected"}

    template = (HERE / "templates" / "tier3_review.md").read_text()
    prompt = template.format(
        program=(HERE / "program.md").read_text(),
        rubric=(HERE / "rubrics" / "tier3_adversarial_rubric.md").read_text(),
        artifact_type=ctype,
        candidate_id=entry["id"],
        artifact=artifact_path.read_text()[:24000],
        checks=json.dumps(entry.get("checks", {}), indent=2),
    )
    try:
        verdict = call_codex_json(prompt, timeout=timeout)
    except RuntimeError as e:
        verdict = {"verdict": "REJECT", "findings": [f"review failed: {e}"][:1],
                   "summary": "review error"}

    result = {**entry, "tier3": verdict}
    v = verdict.get("verdict")
    if v == "APPROVE":
        dest = STAGED / _today() / entry["id"]
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copytree(exp_dir, dest, dirs_exist_ok=True)
        result_for_apply = {k: result[k] for k in ("id", "type", "checks", "tier3") if k in result}
        (dest / "APPLY.md").write_text(_apply_md(result_for_apply, artifact_file))
        result["action"] = "staged"
        result["staged_to"] = str(dest)
    elif v == "CONDITIONAL":
        (exp_dir / "conditional_findings.json").write_text(
            json.dumps(verdict.get("findings", []), indent=2))
        result["action"] = "conditional"
    else:
        result["action"] = "rejected"
    return result


def run_tier3(tier2_winners: list[dict], iter_dir: Path, *, timeout: int = 700) -> dict[str, Any]:
    iter_dir.mkdir(parents=True, exist_ok=True)
    reviews = [review_one(w, iter_dir, timeout=timeout) for w in tier2_winners]
    promoted = [r for r in reviews if r.get("action") == "staged"]
    rejected = [{"experiment_id": r["id"],
                 "findings": r.get("tier3", {}).get("findings", []),
                 "summary": r.get("tier3", {}).get("summary", "")}
                for r in reviews if r.get("action") == "rejected"]
    slim = [{k: v for k, v in r.items() if k != "candidate"} for r in reviews]
    (iter_dir / "tier3_reviews.json").write_text(json.dumps(slim, indent=2, default=str))
    (iter_dir / "tier3_rejected.json").write_text(json.dumps(rejected, indent=2))
    return {"reviews": reviews, "promoted": promoted, "rejected_findings": rejected}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--winners", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--timeout", type=int, default=700)
    args = ap.parse_args()
    winners = json.loads(Path(args.winners).read_text())
    result = run_tier3(winners, Path(args.output_dir), timeout=args.timeout)
    print(f"Tier 3: {len(result['reviews'])} reviewed, "
          f"{len(result['promoted'])} staged, {len(result['rejected_findings'])} rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
