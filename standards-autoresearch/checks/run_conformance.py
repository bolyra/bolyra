"""Objective check: does the CURRENT tree still pass its own conformance?

Two truths, per CLAUDE.md:
- local (vendored) truth: `node spec/conformance-runner.js --type host_behavior`
- published truth: `npx @bolyra/evc-conformance` run from a temp dir (release
  drift check — run once per iteration, it hits the network)

Used by scoring.py (REGISTRY CLOSURE) and as a preflight before Tier 2.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def run_local(*, timeout: int = 300) -> dict[str, Any]:
    try:
        p = subprocess.run(
            ["node", "spec/conformance-runner.js", "--type", "host_behavior"],
            capture_output=True, text=True, timeout=timeout, cwd=REPO,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s"}
    m = re.search(r"(\d+) passed, (\d+) failed", p.stdout)
    counts = f"{m.group(1)} passed, {m.group(2)} failed" if m else None
    return {"ok": p.returncode == 0, "exit": p.returncode, "counts": counts,
            "stdout_tail": "\n".join(p.stdout.splitlines()[-8:])}


def run_sync_check(*, timeout: int = 120) -> dict[str, Any]:
    """CI-parity: vendored evc-conformance snapshot matches spec/."""
    sync = REPO / "integrations" / "evc-conformance" / "scripts" / "sync.js"
    if not sync.exists():
        return {"ok": False, "error": "sync.js not found"}
    try:
        p = subprocess.run(["node", str(sync), "--check"], capture_output=True,
                           text=True, timeout=timeout, cwd=REPO)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s"}
    return {"ok": p.returncode == 0, "exit": p.returncode,
            "tail": (p.stdout + p.stderr)[-400:]}


def run_published(*, timeout: int = 600) -> dict[str, Any]:
    """Cold-run the published suite from an empty dir (network)."""
    with tempfile.TemporaryDirectory(prefix="sar-published-") as td:
        try:
            p = subprocess.run(
                ["npx", "-y", "@bolyra/evc-conformance", "--host",
                 f"node {REPO / 'spec' / 'reference-host.js'}"],
                capture_output=True, text=True, timeout=timeout, cwd=td,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"timeout after {timeout}s"}
        return {"ok": p.returncode == 0, "exit": p.returncode,
                "stdout_tail": "\n".join(p.stdout.splitlines()[-8:])}


def main() -> int:
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--published", action="store_true", help="also cold-run the npm package")
    args = ap.parse_args()
    out = {"local": run_local(), "sync_check": run_sync_check()}
    if args.published:
        out["published"] = run_published()
    print(json.dumps(out, indent=2))
    return 0 if all(v.get("ok") for v in out.values()) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
