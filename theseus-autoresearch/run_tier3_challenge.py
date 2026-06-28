"""Tier 3: Adversarial challenge of Tier 2 validated integration opportunities.

5 Theseus-specific attack axes:
  1. Theseus Builds It Themselves
  2. Standard Crypto Suffices
  3. No Agent Actually Needs This
  4. Integration Complexity vs Value
  5. Single-Partner Dependency

Tries codex exec first, falls back to Claude CLI.
Parses verdict: APPROVE / CONDITIONAL / REJECT.

Uses Claude MAX login via `claude` CLI, never API keys or SDK.
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
THESEUS_CONTEXT_PATH = HERE / "theseus_context.md"

VALID_VERDICTS = {"APPROVE", "CONDITIONAL", "REJECT"}


@dataclass
class ChallengeVerdict:
    verdict: str  # APPROVE | CONDITIONAL | REJECT
    findings: list[str] = field(default_factory=list)
    axis_scores: dict[str, str] = field(default_factory=dict)
    summary: str = ""
    source: str = "claude_cli"  # "codex" | "claude_cli"


_RUBRIC_CACHE: str | None = None
_THESEUS_CACHE: str | None = None


def _load_rubric() -> str:
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        _RUBRIC_CACHE = RUBRIC_PATH.read_text()
    return _RUBRIC_CACHE


def _load_theseus_context() -> str:
    global _THESEUS_CACHE
    if _THESEUS_CACHE is None:
        if THESEUS_CONTEXT_PATH.exists():
            _THESEUS_CACHE = THESEUS_CONTEXT_PATH.read_text()
        else:
            _THESEUS_CACHE = "(no theseus context available)"
    return _THESEUS_CACHE


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


def _build_challenge_prompt(card: dict, rubric: str, theseus_context: str) -> str:
    """Build the adversarial challenge prompt for a single integration card."""
    return (
        "You are an adversarial reviewer for the Bolyra Theseus AutoResearch Loop.\n\n"
        "Your job is to KILL bad ideas before they waste founder time. "
        "Assume every integration opportunity is over-hyped until proven otherwise.\n\n"
        f"ADVERSARIAL RUBRIC:\n{rubric[:6000]}\n\n"
        f"THESEUS CONTEXT:\n{theseus_context[:3000]}\n\n"
        f"INTEGRATION CARD TO CHALLENGE:\n{json.dumps(card, indent=2)[:8000]}\n\n"
        "Attack this integration opportunity on all 5 axes from the rubric:\n"
        "1. Theseus Builds It Themselves\n"
        "2. Standard Crypto Suffices\n"
        "3. No Agent Actually Needs This\n"
        "4. Integration Complexity vs Value\n"
        "5. Single-Partner Dependency\n\n"
        "Be brutal but fair.\n\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "verdict": "APPROVE" | "CONDITIONAL" | "REJECT",\n'
        '  "findings": ["finding 1", "finding 2", ...],\n'
        '  "axis_scores": {\n'
        '    "theseus_builds_it": "PASS" | "CONCERN" | "FAIL",\n'
        '    "standard_crypto_suffices": "PASS" | "CONCERN" | "FAIL",\n'
        '    "no_agent_needs_this": "PASS" | "CONCERN" | "FAIL",\n'
        '    "integration_complexity_vs_value": "PASS" | "CONCERN" | "FAIL",\n'
        '    "single_partner_dependency": "PASS" | "CONCERN" | "FAIL"\n'
        "  },\n"
        '  "summary": "one sentence overall assessment"\n'
        "}\n"
    )


def _try_codex(card: dict, rubric: str, theseus_context: str, *, timeout: int = 300) -> ChallengeVerdict | None:
    """Attempt codex exec in read-only mode. Returns None if unavailable."""
    if not shutil.which("codex"):
        return None

    prompt = _build_challenge_prompt(card, rubric, theseus_context)

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


def _claude_fallback(card: dict, rubric: str, theseus_context: str, *, model: str = "opus", timeout: int = 300) -> ChallengeVerdict:
    """Use Claude CLI as fallback adversarial reviewer."""
    prompt = _build_challenge_prompt(card, rubric, theseus_context)
    raw = call_claude_cli(prompt, model=model, timeout=timeout)
    verdict = _parse_verdict(raw)
    verdict.source = "claude_cli"
    return verdict


def challenge_opportunity(
    card: dict, *, model: str = "opus", timeout: int = 300
) -> ChallengeVerdict:
    """Challenge a single integration card. Tries codex first, falls back to Claude CLI."""
    rubric = _load_rubric()
    theseus_context = _load_theseus_context()

    codex_result = _try_codex(card, rubric, theseus_context, timeout=timeout)
    if codex_result is not None:
        return codex_result

    return _claude_fallback(card, rubric, theseus_context, model=model, timeout=timeout)


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
    ap = argparse.ArgumentParser(description="Tier 3: adversarial challenge of integration opportunities")
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
