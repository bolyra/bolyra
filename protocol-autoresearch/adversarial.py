"""Codex adversarial reviewer for Tier 3.

Dispatches `codex exec` in read-only mode against an experiment directory.
Parses APPROVE/CONDITIONAL/REJECT verdict JSON. Falls back to Claude subagent
if codex is unavailable.
"""
from __future__ import annotations

import json
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object


VALID_VERDICTS = {"APPROVE", "CONDITIONAL", "REJECT"}


@dataclass
class AdversarialVerdict:
    verdict: str  # "APPROVE" | "CONDITIONAL" | "REJECT"
    findings: list[str] = field(default_factory=list)
    summary: str = ""
    source: str = "claude_subagent"  # "codex" | "claude_subagent"


_RUBRIC_CACHE: str | None = None


def _load_rubric() -> str:
    global _RUBRIC_CACHE
    if _RUBRIC_CACHE is None:
        rubric_path = Path(__file__).parent / "rubrics" / "tier3_adversarial_rubric.md"
        _RUBRIC_CACHE = rubric_path.read_text()
    return _RUBRIC_CACHE


def _gather_experiment_summary(experiment_dir: Path) -> str:
    """Read experiment files into a summary for review context."""
    parts = []
    for pattern in ["*.circom", "*.sol", "*.ts", "*.py", "*.md", "*.json"]:
        for f in experiment_dir.rglob(pattern):
            try:
                content = f.read_text()
                parts.append(f"--- {f.relative_to(experiment_dir)} ---\n{content}\n")
            except Exception:
                continue
    return "\n".join(parts)[:30000]


def _parse_verdict(raw: str) -> AdversarialVerdict:
    """Parse a structured verdict from LLM/codex output."""
    data = extract_json_object(raw)
    verdict_str = str(data.get("verdict", "REJECT")).upper()
    if verdict_str not in VALID_VERDICTS:
        verdict_str = "REJECT"
    findings = data.get("findings", data.get("blocking_issues", []))
    if isinstance(findings, str):
        findings = [findings]
    summary = str(data.get("summary", ""))
    return AdversarialVerdict(
        verdict=verdict_str,
        findings=[str(f) for f in findings],
        summary=summary,
    )


def _try_codex(experiment_dir: Path, rubric: str, timeout: int) -> AdversarialVerdict | None:
    """Attempt to use codex exec for adversarial review. Returns None if unavailable."""
    if not shutil.which("codex"):
        return None

    prompt = (
        "You are an adversarial reviewer. Review this experiment directory for the "
        "Bolyra identity protocol. Use this rubric:\n\n"
        f"{rubric[:8000]}\n\n"
        f"Experiment directory: {experiment_dir}\n\n"
        "Return a JSON object with: verdict (APPROVE/CONDITIONAL/REJECT), "
        "findings (list of strings), summary (one sentence)."
    )

    try:
        result = subprocess.run(
            ["codex", "exec", "--read-only", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(experiment_dir),
        )
        if result.returncode != 0:
            return None
        verdict = _parse_verdict(result.stdout)
        verdict.source = "codex"
        return verdict
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return None


def _claude_fallback(experiment_dir: Path, rubric: str, timeout: int) -> AdversarialVerdict:
    """Use Claude CLI as fallback reviewer."""
    experiment_summary = _gather_experiment_summary(experiment_dir)

    prompt = (
        "You are an adversarial reviewer for the Bolyra identity protocol.\n\n"
        f"RUBRIC:\n{rubric[:8000]}\n\n"
        f"EXPERIMENT FILES:\n{experiment_summary}\n\n"
        "Review this experiment on all 6 axes from the rubric. Then return ONLY a JSON "
        "object (no markdown fences):\n"
        '{\n'
        '  "verdict": "APPROVE" | "CONDITIONAL" | "REJECT",\n'
        '  "findings": ["finding 1", "finding 2", ...],\n'
        '  "summary": "one sentence summary"\n'
        '}\n'
    )
    raw = call_claude_cli(prompt, model="opus", timeout=timeout)
    verdict = _parse_verdict(raw)
    verdict.source = "claude_subagent"
    return verdict


def review_experiment(experiment_dir: Path, *, timeout: int = 300) -> AdversarialVerdict:
    """Review an experiment via Codex (or Claude fallback). Returns verdict."""
    rubric = _load_rubric()

    # Try codex first
    codex_result = _try_codex(experiment_dir, rubric, timeout)
    if codex_result is not None:
        return codex_result

    # Fall back to Claude subagent
    return _claude_fallback(experiment_dir, rubric, timeout)
