"""Surgical one-iter refinement of C7 at peak (iter 3, 9/10).

The peak construction fails only on adversarial_survival (1/2) because claim 7 ('Model
provenance for regulated AI: FDA/EU AI Act demands provable chain from deployed model
weights to each inference output') overreaches — Bolyra can prove *authorization*
binding but cannot prove *execution* binding without a TEE/hardware attestation gadget.

Fix: narrow the claim explicitly to AUTHORIZATION binding and drop the FDA/EU AI Act
execution-binding scenario. Re-run Tier 3 + Judge. Target: 10/10.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import _imports  # noqa: F401
import judge
import tier3_adversarial
from _shared import call_claude_cli

HERE = Path(__file__).resolve().parent
ITER_DIR = HERE / "runs" / "iter_006_20260422T195000_surgical" / "C7"


def run_surgical_refinement() -> None:
    cand = next(c for c in json.loads((HERE / "candidates.json").read_text())["candidates"] if c["id"] == "C7")
    print(f"Surgical C7 refinement in {ITER_DIR}")

    prior = (ITER_DIR / "construction.md").read_text()
    prior_score = json.loads((ITER_DIR / "score.json").read_text())
    top_gap = prior_score["gaps"][0]
    print(f"Target gap: {top_gap[:120]}...")

    prompt = (
        "You are hardening a Bolyra ZK construction that scored 9/10. All dimensions are "
        "at 2/2 EXCEPT adversarial_survival at 1/2. The single remaining attack is that "
        "the claim overreaches by bundling authorization binding + execution binding.\n\n"
        "SURGICAL FIX — HARDEN, DO NOT EXPAND:\n"
        "1. Preserve sections 1, 2, 3, 4, 5, 6 VERBATIM from the prior construction.\n"
        "2. In section 1 (Statement of claim), add ONE sentence explicitly narrowing scope: "
        "'Bolyra proves AUTHORIZATION binding (which model/operator/permission set was "
        "AUTHORIZED to make this call); it does NOT attest that the authorized model was "
        "the one that ACTUALLY executed the inference — execution binding requires TEE or "
        "hardware attestation and is out of scope.'\n"
        "3. In section 7 (Concrete deployment scenario), DELETE the FDA/EU AI Act "
        "execution-binding scenario. Replace with a fourth authorization-binding scenario: "
        "SEC/FINRA audit where firm must prove 'only approved models (Sonnet, Opus) were "
        "AUTHORIZED to access customer order flow, never unapproved models' — authorization, "
        "not execution.\n"
        "4. In section 3 (Threat model), add: 'Out of scope: runtime execution binding. "
        "Adversary who compromises model loader between authorization and execution can "
        "substitute the model; this requires TEE and is orthogonal to the ZK claim.'\n"
        "5. In section 8 (Why the baseline cannot match), restate the narrowed claim: "
        "RFC 8693 + DPoP cannot provide AS-blind authorization binding of model identity "
        "even when narrowed to authorization-only.\n"
        "6. Do NOT add new circuits. Do NOT add new games. Do NOT add new assumptions.\n\n"
        "Return ONLY the refined markdown. No preamble. No fences.\n\n"
        f"PRIOR CONSTRUCTION (9/10, refine surgically):\n{prior}"
    )

    raw = call_claude_cli(prompt, model="opus", timeout=1200)
    (ITER_DIR / "construction.md").write_text(raw.strip() + "\n")
    print(f"Wrote refined construction ({len(raw)} chars)")

    # Re-run Tier 3 (same personas, no codex)
    print("Tier 3: re-running adversarial personas...")
    tier3_adversarial.run(cand, ITER_DIR, model="sonnet", use_codex=False)

    # Re-judge
    print("Judge: scoring refined construction...")
    score = judge.run(cand, ITER_DIR, model="opus", timeout=400)
    print(f"Final strength: {score['strength']}/10 verdict={score['verdict']}")
    for dim, d in score["dims"].items():
        print(f"  {dim}: {d['points']}/2")
    if score["strength"] == 10:
        dest = HERE / "winners" / "C7"
        dest.mkdir(parents=True, exist_ok=True)
        for name in ("baseline.md", "construction.md", "attacks.md", "score.json"):
            src = ITER_DIR / name
            if src.exists():
                shutil.copy2(src, dest / name)
        print(f"PROMOTED to {dest}")

    # Append to trajectory
    traj_path = HERE / "history" / "score_trajectory.jsonl"
    entry = {
        "candidate_id": "C7",
        "iter": 6,
        "ts": "20260422T195000surgical",
        "strength": score["strength"],
        "verdict": score["verdict"],
        "iter_dir": str(ITER_DIR.relative_to(HERE)),
        "note": "surgical refinement from iter 3 peak (9/10), narrow claim to auth-only",
    }
    with traj_path.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"Recorded trajectory entry")


if __name__ == "__main__":
    run_surgical_refinement()
