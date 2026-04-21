#!/usr/bin/env python3
"""Compile Solidity contracts via solc or Hardhat.

Usage:
    python3 scripts/contract_compile.py experiments/tier2_001_example/contract.sol
    python3 scripts/contract_compile.py experiments/tier2_001_example/ --hardhat

Outputs JSON to stdout:
    {"success": bool, "compiler": "solc"|"hardhat", "errors": [], "warnings": []}

Requires: solc (>= 0.8.24) or npx hardhat on PATH.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def compile_with_solc(sol_path: Path) -> dict:
    """Compile a single .sol file with solc."""
    if not sol_path.exists():
        return {"success": False, "compiler": "solc", "errors": [f"file not found: {sol_path}"], "warnings": []}

    try:
        subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return {"success": False, "compiler": "solc", "errors": ["solc not found on PATH"], "warnings": []}

    try:
        result = subprocess.run(
            ["solc", "--abi", "--bin", "--overwrite", "-o", str(sol_path.parent / "build"), str(sol_path)],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "compiler": "solc", "errors": ["compilation timed out (60s)"], "warnings": []}

    errors = []
    warnings = []
    for line in (result.stdout + result.stderr).splitlines():
        line_stripped = line.strip()
        if "Error:" in line_stripped:
            errors.append(line_stripped)
        elif "Warning:" in line_stripped:
            warnings.append(line_stripped)

    return {
        "success": result.returncode == 0,
        "compiler": "solc",
        "errors": errors if errors else ([result.stderr[:500]] if result.returncode != 0 else []),
        "warnings": warnings,
    }


def compile_with_hardhat(project_dir: Path) -> dict:
    """Compile contracts using Hardhat (requires hardhat.config in project or parent)."""
    try:
        subprocess.run(["npx", "--version"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return {"success": False, "compiler": "hardhat", "errors": ["npx not found on PATH"], "warnings": []}

    # Find hardhat config by walking up
    search_dir = project_dir
    hardhat_dir = None
    for _ in range(5):
        if (search_dir / "hardhat.config.ts").exists() or (search_dir / "hardhat.config.js").exists():
            hardhat_dir = search_dir
            break
        search_dir = search_dir.parent
    if hardhat_dir is None:
        return {"success": False, "compiler": "hardhat", "errors": ["no hardhat.config found"], "warnings": []}

    try:
        result = subprocess.run(
            ["npx", "hardhat", "compile"],
            capture_output=True, text=True, timeout=120,
            cwd=str(hardhat_dir),
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "compiler": "hardhat", "errors": ["hardhat compile timed out (120s)"], "warnings": []}

    errors = []
    warnings = []
    for line in (result.stdout + result.stderr).splitlines():
        line_stripped = line.strip()
        if "Error" in line_stripped or "error" in line_stripped:
            errors.append(line_stripped)
        elif "Warning" in line_stripped or "warning" in line_stripped:
            warnings.append(line_stripped)

    return {
        "success": result.returncode == 0,
        "compiler": "hardhat",
        "errors": errors if errors else ([result.stderr[:500]] if result.returncode != 0 else []),
        "warnings": warnings,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compile Solidity contracts")
    ap.add_argument("path", help="Path to .sol file or project directory")
    ap.add_argument("--hardhat", action="store_true", help="Use Hardhat instead of solc")
    args = ap.parse_args()

    target = Path(args.path)
    if args.hardhat or target.is_dir():
        result = compile_with_hardhat(target if target.is_dir() else target.parent)
    else:
        result = compile_with_solc(target)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
