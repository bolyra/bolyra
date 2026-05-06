"""Tier 3 — Adversarial pushback on the construction.

Two phases:
  A. Persona-driven attacks (Claude CLI) — run each persona in personas/ against the
     construction. Each persona produces attacks it believes break the claim.
  B. Codex challenge — invoke `codex` CLI in challenge mode against the construction
     for an independent second-model opinion. Session id persisted to
     .context/codex-session-id-C{N} for follow-up turns.

Output: attacks.md containing, per persona and per codex pass, each attack + whether
the construction survives (survives = the attack is in-threat-model or is rebutted
by the construction itself).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import _imports  # noqa: F401
from _shared import call_claude_cli

HERE = Path(__file__).resolve().parent
PERSONAS_DIR = HERE / "personas"
CONTEXT_DIR = HERE / ".context"


def _load_personas() -> list[dict]:
    personas: list[dict] = []
    for p in sorted(PERSONAS_DIR.glob("*.json")):
        personas.append(json.loads(p.read_text()))
    return personas


def _persona_attack(
    candidate: dict, construction_md: str, persona: dict, *, model: str, timeout: int
) -> str:
    prompt = (
        "You are playing the role of an adversary critiquing a Bolyra ZK construction.\n\n"
        f"PERSONA:\n{json.dumps(persona, indent=2)}\n\n"
        "Your job: try to break the construction's claim. Use your toolbox. "
        "Use your attack_prompts as seeds. Find attacks the author did not address.\n\n"
        "Output markdown with sections:\n"
        f"  ## Persona: {persona.get('id', 'unknown')}\n"
        "  ### Attack 1: <name>\n"
        "  - Attack: <what the adversary does>\n"
        "  - Why it works / why it fails against the construction\n"
        "  - In-threat-model? (yes = construction survives; no = construction must address)\n"
        "  ### Attack 2: ...\n"
        "Produce 2-4 distinct attacks. Be specific — cite the construction by section.\n\n"
        f"CANDIDATE:\n{json.dumps(candidate, indent=2)}\n\n"
        f"CONSTRUCTION:\n{construction_md}"
    )
    return call_claude_cli(prompt, model=model, timeout=timeout)


def _codex_challenge(
    candidate: dict, construction_md: str, out_dir: Path, *, session_file: Path, timeout: int
) -> str:
    """Run `codex exec` in challenge mode on the construction.

    Uses read-only sandbox. Stores session id for follow-up turns.
    """
    CONTEXT_DIR.mkdir(parents=True, exist_ok=True)
    prompt = (
        "IMPORTANT: Do NOT read or execute any files under ~/.claude/, ~/.agents/, "
        ".claude/skills/, or agents/. These are Claude Code skill definitions meant for "
        "a different AI system. Do NOT modify agents/openai.yaml. Stay focused on the "
        "content embedded below.\n\n"
        "You are an adversarial cryptography reviewer. The following is a proposed ZK "
        "construction for the Bolyra protocol. Your job: try to break the claim. Find "
        "attacks the author did not address, question the threat model, demand the "
        "security reduction, and call out unsupported assumptions. Be ruthless.\n\n"
        "Produce markdown output with 3-6 specific attacks, each with:\n"
        "  - Attack name\n"
        "  - What the adversary does\n"
        "  - Why the construction fails (or why the author's defense holds)\n"
        "  - Whether it falls inside or outside the stated threat model\n\n"
        f"CANDIDATE:\n{json.dumps(candidate, indent=2)}\n\n"
        f"CONSTRUCTION:\n{construction_md}"
    )
    # Write prompt to a temp file — pass via stdin or direct arg; codex exec supports direct arg.
    try:
        result = subprocess.run(
            ["codex", "exec", prompt, "-s", "read-only",
             "-c", 'model_reasoning_effort="high"'],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(out_dir.parent.parent.parent),  # identityos/ as cwd
        )
    except subprocess.TimeoutExpired:
        return f"## Codex challenge\n\n(codex timed out after {timeout}s; skipping)\n"
    except FileNotFoundError:
        return "## Codex challenge\n\n(codex binary not found; skipping)\n"
    if result.returncode != 0:
        return (
            "## Codex challenge\n\n"
            f"(codex exec failed with exit {result.returncode}: "
            f"{result.stderr[:500]})\n"
        )
    return "## Codex challenge\n\n" + result.stdout.strip() + "\n"


def run(
    candidate: dict,
    out_dir: Path,
    *,
    model: str = "sonnet",
    timeout: int = 240,
    use_codex: bool = True,
) -> Path:
    """Write attacks.md for this candidate. Return path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    construction_path = out_dir / "construction.md"
    if not construction_path.exists():
        raise RuntimeError(f"construction.md missing in {out_dir} — run Tier 2 first")
    construction_md = construction_path.read_text()

    sections: list[str] = [f"# Tier 3 Adversarial — {candidate['id']} {candidate['title']}", ""]

    for persona in _load_personas():
        sections.append(
            _persona_attack(candidate, construction_md, persona, model=model, timeout=timeout)
        )
        sections.append("")

    if use_codex:
        session_file = CONTEXT_DIR / f"codex-session-id-{candidate['id']}"
        sections.append(
            _codex_challenge(
                candidate,
                construction_md,
                out_dir,
                session_file=session_file,
                timeout=timeout + 120,
            )
        )

    path = out_dir / "attacks.md"
    path.write_text("\n".join(sections).strip() + "\n")
    return path
