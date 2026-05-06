"""Tier 2 — Propose a ZK construction that strictly beats the baseline.

Input:  candidate + baseline.md + (optional) prior construction.md + (optional) gaps from judge
Output: construction.md with
  - Construction sketch (gadgets, circuits, public/private inputs)
  - Threat model (adversary model, game definition if possible)
  - Security argument (named assumption + reduction sketch)
  - Bolyra primitive mapping (Poseidon / Groth16 / PLONK / BabyJubjub / nullifier)
  - Circuit cost estimate (constraints, proving time target)
  - At least one concrete deployment scenario with a named stakeholder

Uses Claude CLI (opus for this tier — it's the hardest tier and needs reasoning depth).
"""
from __future__ import annotations

import json
from pathlib import Path

import _imports  # noqa: F401
from _shared import call_claude_cli

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # identityos/


def _load_bolyra_spec() -> str:
    """Load the Bolyra spec sections relevant to Tier 2 (primitives + circuit schema)."""
    spec_path = ROOT / "spec" / "draft-bolyra-mutual-zkp-auth-01.md"
    if not spec_path.exists():
        return "(spec not found at " + str(spec_path) + ")"
    text = spec_path.read_text()
    # Truncate to stay under token budget; spec is long
    return text[:18000]


def _load_formal_properties() -> str:
    """Load circuit-level formal properties if available."""
    fp_path = ROOT / "circuits" / "FORMAL-PROPERTIES.md"
    if not fp_path.exists():
        return ""
    return fp_path.read_text()[:6000]


def run(
    candidate: dict,
    out_dir: Path,
    *,
    prior_construction: Path | None = None,
    gaps: list[str] | None = None,
    model: str = "opus",
    timeout: int = 1200,
) -> Path:
    """Write construction.md for this candidate. Return path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = out_dir / "baseline.md"
    if not baseline_path.exists():
        raise RuntimeError(f"baseline.md missing in {out_dir} — run Tier 1 first")
    baseline_md = baseline_path.read_text()
    bolyra_spec = _load_bolyra_spec()
    formal_props = _load_formal_properties()

    refinement_section = ""
    if prior_construction and prior_construction.exists():
        prior = prior_construction.read_text()
        # HARDENING — not expansion. Pass 2 data showed multi-gap refinement regresses
        # scores (C2: 8→8→err→err→5). Address ONE gap (the highest-priority) per iter
        # and preserve the claim statement verbatim.
        top_gap = (gaps or ["(no specific gap — harden threat model and security argument)"])[0]
        refinement_section = (
            "\n\nREFINEMENT MODE — HARDEN, DO NOT EXPAND.\n"
            "You MUST: (1) preserve section 1 (Statement of claim) VERBATIM from the prior construction; "
            "(2) address ONLY the ONE gap listed below; (3) prefer to narrow or defend the existing "
            "threat model rather than add new gadgets or claims; (4) if the gap cannot be addressed "
            "without breaking the claim, say so explicitly in section 3 (Threat model) — do NOT retreat "
            "the claim statement. A tight 10/10 is better than a bloated 6/10.\n\n"
            "PRIOR CONSTRUCTION (refine this — do not start from scratch):\n"
            f"{prior}\n\n"
            f"THE ONE GAP TO CLOSE THIS ITERATION:\n- {top_gap}\n"
        )

    prompt = (
        "You are a cryptography engineer designing a ZK construction for the Bolyra protocol. "
        "Your job: produce a construction that strictly beats the baseline on the candidate's claim.\n\n"
        "Output a construction.md with these sections (use these exact headers):\n"
        "  # Construction\n"
        "  ## 1. Statement of claim\n"
        "  ## 2. Construction (gadgets, circuits, public/private inputs)\n"
        "  ## 3. Threat model (adversary capabilities, game definition)\n"
        "  ## 4. Security argument (named assumption + reduction sketch)\n"
        "  ## 5. Bolyra primitive mapping\n"
        "  ## 6. Circuit cost estimate\n"
        "  ## 7. Concrete deployment scenario\n"
        "  ## 8. Why the baseline cannot match\n\n"
        "Rules:\n"
        "- Be specific. Name circuits, public signals, private inputs.\n"
        "- Name the cryptographic assumption (DL on Baby Jubjub, Poseidon collision resistance, "
        "knowledge soundness of Groth16/PLONK, ROM, etc.)\n"
        "- State the threat model as a game if possible (adversary controls X, sees Y, wins by Z).\n"
        "- Use Bolyra primitives only (Poseidon, Groth16 human, PLONK agent, BabyJubjub EdDSA, "
        "nullifier = Poseidon(scope_id, secret)).\n"
        "- Circuit cost estimate: number of constraints, proving time target (Groth16 human <15s, "
        "PLONK agent <5s).\n"
        "- Scenario must name a real stakeholder (credit union, healthcare org, regulator).\n"
        f"\nCANDIDATE:\n{json.dumps(candidate, indent=2)}\n\n"
        f"BASELINE (BAR TO BEAT):\n{baseline_md}\n\n"
        f"BOLYRA SPEC (primitives source of truth):\n{bolyra_spec}\n\n"
        f"CIRCUIT FORMAL PROPERTIES:\n{formal_props}"
        f"{refinement_section}\n\n"
        "Return ONLY the markdown. No preamble. No fences."
    )
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    path = out_dir / "construction.md"
    path.write_text(raw.strip() + "\n")
    return path
