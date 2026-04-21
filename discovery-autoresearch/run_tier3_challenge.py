"""Tier 3: Adversarial challenge of Tier 2 validated opportunities.

Follows protocol-autoresearch/adversarial.py pattern:
  1. Try codex exec with read-only challenge prompt (5 attack axes)
  2. If codex unavailable, fall back to Claude CLI with adversarial persona
  3. Parse verdict: APPROVE / CONDITIONAL / REJECT
  4. CONDITIONAL: append concerns to the opportunity card
  5. REJECT: log reason, exclude from final board
  6. Save to runs/iter_NNN/tier3_challenged.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object

HERE = Path(__file__).resolve().parent
RUBRIC_PATH = HERE / "rubrics" / "tier3_adversarial_rubric.md"
EAD_PATH = HERE / "context" / "ead_constraints.md"

VALID_VERDICTS = {"APPROVE", "CONDITIONAL", "REJECT"}


@dataclass
class ChallengeVerdict:
    verdict: str  # APPROVE | CONDITIONAL | REJECT
    findings: list[str] = field(default_factory=list)
    axis_scores: dict[str, str] = field(default_factory=dict)
    summary: str = ""
    source: str = "claude_cli"  # "codex" | "claude_cli"


_RUBRIC_CACHE: str | None = None
_EAD_CACHE: str | None = None


def _load_rubric() -> str:
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        _RUBRIC_CACHE = RUBRIC_PATH.read_text()
    return _RUBRIC_CACHE


def _load_ead() -> str:
    global _EAD_CACHE
    if _EAD_CACHE is None:
        _EAD_CACHE = EAD_PATH.read_text()
    return _EAD_CACHE


def _parse_verdict(raw: str) -> ChallengeVerdict:
    """Parse structured verdict from LLM/codex output."""
    data = extract_json_object(raw)
    verdict_str = str(data.get("verdict", "REJECT")).upper()
    if verdict_str not in VALID_VERDICTS:
        verdict_str = "REJECT"
    findings = data.get("findings", [])
    if isinstance(findings, str):
        findings = [findings]
    axis_scores = data.get("axis_scores", {})
    summary = str(data.get("summary", ""))
    return ChallengeVerdict(
        verdict=verdict_str,
        findings=[str(f) for f in findings],
        axis_scores={str(k): str(v) for k, v in axis_scores.items()},
        summary=summary,
    )


def _build_challenge_prompt(card: dict, rubric: str, ead: str) -> str:
    """Build the adversarial challenge prompt for a single opportunity card."""
    return (
        "You are an adversarial reviewer for the Bolyra Discovery AutoResearch Loop.\n\n"
        "Your job is to KILL bad ideas before they waste founder time. "
        "Assume every opportunity is over-hyped until proven otherwise.\n\n"
        f"ADVERSARIAL RUBRIC:\n{rubric[:6000]}\n\n"
        f"EAD/IMMIGRATION CONSTRAINTS:\n{ead[:2000]}\n\n"
        f"OPPORTUNITY CARD TO CHALLENGE:\n{json.dumps(card, indent=2)[:8000]}\n\n"
        "Attack this opportunity on all 5 axes from the rubric. Be brutal but fair.\n\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "verdict": "APPROVE" | "CONDITIONAL" | "REJECT",\n'
        '  "findings": ["finding 1", "finding 2", ...],\n'
        '  "axis_scores": {\n'
        '    "demand_falsification": "PASS" | "CONCERN" | "FAIL",\n'
        '    "competitive_moat": "PASS" | "CONCERN" | "FAIL",\n'
        '    "timing_risk": "PASS" | "CONCERN" | "FAIL",\n'
        '    "execution_feasibility": "PASS" | "CONCERN" | "FAIL",\n'
        '    "ead_compliance": "PASS" | "CONCERN" | "FAIL"\n'
        "  },\n"
        '  "summary": "one sentence overall assessment"\n'
        "}\n"
    )


def _try_codex(card: dict, rubric: str, ead: str, *, timeout: int = 300) -> ChallengeVerdict | None:
    """Attempt codex exec in read-only mode. Returns None if unavailable."""
    if not shutil.which("codex"):
        return None

    prompt = _build_challenge_prompt(card, rubric, ead)

    try:
        result = subprocess.run(
            ["codex", "exec", "--read-only", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None
        verdict = _parse_verdict(result.stdout)
        verdict.source = "codex"
        return verdict
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return None


def _claude_fallback(card: dict, rubric: str, ead: str, *, model: str = "opus", timeout: int = 300) -> ChallengeVerdict:
    """Use Claude CLI as fallback adversarial reviewer."""
    prompt = _build_challenge_prompt(card, rubric, ead)
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    verdict = _parse_verdict(raw)
    verdict.source = "claude_cli"
    return verdict


def challenge_opportunity(
    card: dict, *, model: str = "opus", timeout: int = 300
) -> ChallengeVerdict:
    """Challenge a single opportunity card. Tries codex first, falls back to Claude CLI."""
    rubric = _load_rubric()
    ead = _load_ead()

    codex_result = _try_codex(card, rubric, ead, timeout=timeout)
    if codex_result is not None:
        return codex_result

    return _claude_fallback(card, rubric, ead, model=model, timeout=timeout)


def run_tier3_challenge(
    tier2_cards: list[dict],
    output_dir: Path,
    *,
    model: str = "opus",
    timeout: int = 300,
) -> dict[str, Any]:
    """Run Tier 3 adversarial challenge on all Tier 2 promoted cards.

    Returns dict with challenged cards, approved, conditional, and rejected lists.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    challenged: list[dict] = []
    approved: list[dict] = []
    conditional: list[dict] = []
    rejected: list[dict] = []

    for card in tier2_cards:
        try:
            verdict = challenge_opportunity(card, model=model, timeout=timeout)
        except Exception as e:
            verdict = ChallengeVerdict(
                verdict="REJECT",
                findings=[f"challenge failed: {type(e).__name__}: {e}"],
                summary="adversarial review error",
                source="error",
            )

        challenged_card = {
            **card,
            "tier3_verdict": verdict.verdict,
            "tier3_findings": verdict.findings,
            "tier3_axis_scores": verdict.axis_scores,
            "tier3_summary": verdict.summary,
            "tier3_source": verdict.source,
        }

        if verdict.verdict == "APPROVE":
            approved.append(challenged_card)
        elif verdict.verdict == "CONDITIONAL":
            # Append concerns to the card
            challenged_card.setdefault("concerns", [])
            challenged_card["concerns"].extend(verdict.findings)
            conditional.append(challenged_card)
        else:  # REJECT
            rejected.append(challenged_card)

        challenged.append(challenged_card)

    (output_dir / "tier3_challenged.json").write_text(json.dumps(challenged, indent=2))
    (output_dir / "tier3_approved.json").write_text(json.dumps(approved, indent=2))
    (output_dir / "tier3_conditional.json").write_text(json.dumps(conditional, indent=2))
    (output_dir / "tier3_rejected.json").write_text(json.dumps(rejected, indent=2))

    return {
        "challenged": challenged,
        "approved": approved,
        "conditional": conditional,
        "rejected": rejected,
        "output_dir": str(output_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tier 3: adversarial challenge of opportunities")
    ap.add_argument("--cards", required=True, help="Path to tier2_promoted.json or tier2_cards.json")
    ap.add_argument("--output-dir", required=True, help="Iteration output dir")
    ap.add_argument("--model", default="opus")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    cards = json.loads(Path(args.cards).read_text())
    output_dir = Path(args.output_dir)
    result = run_tier3_challenge(cards, output_dir, model=args.model, timeout=args.timeout)
    print(f"Challenged {len(result['challenged'])} opportunities")
    print(f"Approved {len(result['approved'])}, conditional {len(result['conditional'])}, rejected {len(result['rejected'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
