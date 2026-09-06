"""Objective check for spec_finding artifacts (staged spec diffs).

Verifies: header block present (Base-Commit / Target-File / Finding), the
base commit matches the current spec/ HEAD (stale-base detection), the
target file exists, every diff context/removal line actually occurs in the
pinned file, and RFC 2119 keywords in added lines are uppercase-consistent.
Never applies anything.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

RFC2119_LOWER = re.compile(r"\b(must not|must|shall not|shall|should not|should|may)\b")

# Only spec markdown may be targeted by a staged diff (Codex review finding:
# an unconstrained Target-File let a diff aim anywhere in the repo).
ALLOWED_TARGETS = re.compile(r"^spec/[A-Za-z0-9._/-]+\.md$")


def _spec_head() -> str:
    p = subprocess.run(["git", "log", "-1", "--format=%H", "--", "spec/"],
                       capture_output=True, text=True, cwd=REPO)
    return p.stdout.strip()


def check(artifact_path: Path) -> dict[str, Any]:
    text = artifact_path.read_text()
    errors: list[str] = []
    warnings: list[str] = []

    m_base = re.search(r"^Base-Commit:\s*([0-9a-f]{7,40})", text, re.M)
    m_target = re.search(r"^Target-File:\s*(\S+)", text, re.M)
    if not m_base:
        errors.append("missing Base-Commit header")
    if not m_target:
        errors.append("missing Target-File header")
    if not re.search(r"^Finding:\s*\S+", text, re.M):
        errors.append("missing Finding header")
    if "```diff" not in text:
        errors.append("no ```diff block")
    if errors:
        return {"ok": False, "stage": "shape", "errors": errors}

    base = m_base.group(1)
    target = m_target.group(1)
    if not ALLOWED_TARGETS.fullmatch(target) or ".." in target:
        return {"ok": False, "stage": "verify",
                "errors": [f"Target-File outside the spec/*.md allowlist: {target}"]}
    head = _spec_head()
    if not head.startswith(base) and not base.startswith(head[:len(base)]):
        errors.append(f"stale base: artifact pinned {base[:12]}, spec/ HEAD is {head[:12]}")

    target_path = REPO / target
    if not target_path.exists():
        errors.append(f"target file does not exist: {target}")
    else:
        content = target_path.read_text()
        diff_block = text.split("```diff", 1)[1].split("```", 1)[0]
        for line in diff_block.splitlines():
            if line.startswith("-") and not line.startswith("---"):
                needle = line[1:].strip()
                if needle and needle not in content:
                    errors.append(f"removal line not found in pinned file: {needle[:80]!r}")
            elif line.startswith("+") and not line.startswith("+++"):
                added = line[1:]
                for kw in RFC2119_LOWER.finditer(added):
                    # lowercase modal in normative-looking added text is a smell
                    warnings.append(f"lowercase '{kw.group(1)}' in added line: {added.strip()[:80]!r}")

    return {"ok": not errors, "stage": "verify", "errors": errors,
            "warnings": warnings, "base": base, "target": target, "spec_head": head}


def main() -> int:
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact", help="Path to spec-diff.md")
    args = ap.parse_args()
    result = check(Path(args.artifact))
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
