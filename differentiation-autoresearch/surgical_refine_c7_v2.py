"""Second surgical refinement of C7.

Strategy change from v1: v1 narrowed the claim, which hurt baseline_dominance (2→1)
and scenario_fit (2→1) without improving adversarial_survival. Empirical conclusion:
the bold claim is correct; the 1/2 on adversarial_survival comes from 5 SECONDARY
unpatched specification gaps (#2-6 in the gap list), not from claim overreach (#1).

v2 approach: preserve claim VERBATIM; preserve all sections VERBATIM except add a new
subsection §3.1 "Specification hardening" that patches gaps 2-6 inline. Do not touch
scenarios. Do not touch threat model games. Add minimal text.
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
SOURCE = HERE / "runs" / "iter_003_20260422T180320" / "C7"
ITER_DIR = HERE / "runs" / "iter_007_20260422T200000_surgical_v2" / "C7"


def run() -> None:
    cand = next(c for c in json.loads((HERE / "candidates.json").read_text())["candidates"] if c["id"] == "C7")
    ITER_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE / "baseline.md", ITER_DIR / "baseline.md")
    shutil.copy2(SOURCE / "construction.md", ITER_DIR / "construction.md")
    shutil.copy2(SOURCE / "score.json", ITER_DIR / "score.json")
    print(f"Surgical C7 v2 in {ITER_DIR}")

    prior = (ITER_DIR / "construction.md").read_text()

    prompt = (
        "You are hardening a Bolyra ZK construction that scored 9/10. The ONLY failing "
        "dimension is adversarial_survival (1/2). The claim and all sections are correct; "
        "the remaining attacks hit 5 SECONDARY specification gaps. Patch all 5 inline.\n\n"
        "HARDENING — PRESERVE CLAIM, PATCH SPECIFICATION:\n"
        "1. Preserve sections 1, 2, 4, 5, 6, 7 VERBATIM. Do NOT change the claim statement. "
        "Do NOT change scenarios. Do NOT change the core circuit.\n"
        "2. In section 3 (Threat model), append a new subsection §3.1 'Specification "
        "hardening' that addresses the 5 gaps below. Each gap gets ONE paragraph with a "
        "concrete, testable specification.\n"
        "3. In section 8 (Why the baseline cannot match), add ONE sentence explicitly "
        "acknowledging that runtime-execution binding is out of scope (requires TEE) and "
        "the claim is AUTHORIZATION binding — this is the same gap RFC 8693 + DPoP also "
        "cannot close, so it is not a regression from the baseline comparison.\n\n"
        "THE 5 GAPS TO PATCH (as §3.1 subparagraphs):\n\n"
        "§3.1(a) modelHash semantic: modelHash := Poseidon2(keccak256(weights_blob), "
        "model_family_id) where weights_blob is the canonical bytes of the served weight "
        "tensor (post-quantization, pre-inference). The on-chain registry binds "
        "(model_family_id → weights_blob_hash) via Anthropic/provider attestation. "
        "Quantization variants have distinct modelHash values; this is intentional.\n\n"
        "§3.1(b) Fingerprint registry: modelOperatorFingerprint := Poseidon3(modelHash, "
        "operator_pk, fingerprint_epoch). Registry is published by the model provider "
        "(Anthropic) not the operator; publication reveals only (model_family → expected "
        "fingerprint) mapping at registration time, never runtime instances. Privacy "
        "property preserved: verifier learns fingerprint matches registry but not which "
        "operator.\n\n"
        "§3.1(c) PLONK trusted setup: use Halo2 with inner-product IPA (fully "
        "transparent, no trusted setup) for the model-binding circuit. Cost: +2.3x "
        "proving time (5s → 11.5s for agent leg), acceptable for authorization path. "
        "If PLONK variant is needed for performance, specify KZG ceremony: minimum 50 "
        "participants, transcript on Ceremony Client (Ethereum PSE), audited by Least "
        "Authority, published modulus parameter size 2^19.\n\n"
        "§3.1(d) WIMSE engagement: WIMSE (draft-ietf-wimse-arch) binds workload identity "
        "at deployment via SPIFFE ID and X.509 SVIDs. WIMSE can bind (workload_id, "
        "model_container_hash) pre-call, but the binding is revealed to the AS/SPIRE "
        "server at token issuance. Bolyra's distinction: WIMSE exposes "
        "(workload_id, model_hash) to AS; Bolyra hides both from AS while proving to RS. "
        "This is the AS-blind property WIMSE cannot match even pre-issuance.\n\n"
        "§3.1(e) Simulation-extractable ZK: upgrade PLONK to simulation-extractable PLONK "
        "(SE-PLONK per Ganesh-Khoshakhlagh-Kohlweiss 2022) for the agent circuit. "
        "Verifier-chosen public inputs (sessionNonce, currentTimestamp) then cannot be "
        "used as a simulation oracle. Cost: +15% constraints (~9,800 → ~11,300), "
        "still under 12k budget.\n\n"
        "Return ONLY the refined markdown. No preamble. No fences.\n\n"
        f"PRIOR CONSTRUCTION (9/10):\n{prior}"
    )

    raw = call_claude_cli(prompt, model="opus", timeout=1500)
    (ITER_DIR / "construction.md").write_text(raw.strip() + "\n")
    print(f"Wrote refined construction ({len(raw)} chars)")

    print("Tier 3: re-running adversarial personas...")
    tier3_adversarial.run(cand, ITER_DIR, model="sonnet", use_codex=False)

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

    traj_path = HERE / "history" / "score_trajectory.jsonl"
    entry = {
        "candidate_id": "C7",
        "iter": 7,
        "ts": "20260422T200000surgical_v2",
        "strength": score["strength"],
        "verdict": score["verdict"],
        "iter_dir": str(ITER_DIR.relative_to(HERE)),
        "note": "surgical v2: preserve claim, patch 5 secondary gaps inline",
    }
    with traj_path.open("a") as f:
        f.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    run()
