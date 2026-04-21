#!/usr/bin/env python3
"""Compile a circom circuit and report constraint count.

Usage:
    python3 scripts/circuit_compile.py experiments/tier2_001_example/circuit.circom

Requires: circom (>= 2.1.6) on PATH.

Outputs:
  - <name>.r1cs, <name>.wasm, <name>_js/ in same directory as source
  - JSON to stdout: {"success": bool, "constraints": int, "within_budget": bool, "error": str}
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


CONSTRAINT_BUDGET = 80_000


def compile_circuit(circom_path: Path) -> dict:
    """Compile a .circom file and return result metadata."""
    if not circom_path.exists():
        return {
            "success": False,
            "constraints": 0,
            "within_budget": False,
            "error": f"file not found: {circom_path}",
        }

    if not circom_path.suffix == ".circom":
        return {
            "success": False,
            "constraints": 0,
            "within_budget": False,
            "error": f"not a .circom file: {circom_path}",
        }

    output_dir = circom_path.parent
    stem = circom_path.stem

    # Check circom is available
    try:
        subprocess.run(["circom", "--version"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return {
            "success": False,
            "constraints": 0,
            "within_budget": False,
            "error": "circom not found on PATH",
        }

    # Compile: circom circuit.circom --r1cs --wasm --sym -o <dir>
    try:
        result = subprocess.run(
            [
                "circom", str(circom_path),
                "--r1cs", "--wasm", "--sym",
                "-o", str(output_dir),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(output_dir),
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "constraints": 0,
            "within_budget": False,
            "error": "circom compilation timed out (120s)",
        }

    if result.returncode != 0:
        return {
            "success": False,
            "constraints": 0,
            "within_budget": False,
            "error": f"circom failed (exit {result.returncode}): {result.stderr[:500]}",
        }

    # Extract constraint count from compiler output
    constraints = 0
    # Circom prints: "template instances: N" and "non-linear constraints: N"
    for line in (result.stdout + result.stderr).splitlines():
        match = re.search(r"non-linear constraints:\s*(\d+)", line, re.IGNORECASE)
        if match:
            constraints = int(match.group(1))
            break

    # Fallback: try snarkjs r1cs info
    r1cs_path = output_dir / f"{stem}.r1cs"
    if constraints == 0 and r1cs_path.exists():
        try:
            info_result = subprocess.run(
                ["snarkjs", "r1cs", "info", str(r1cs_path)],
                capture_output=True, text=True, timeout=30,
            )
            for line in info_result.stdout.splitlines():
                match = re.search(r"# of Constraints:\s*(\d+)", line)
                if match:
                    constraints = int(match.group(1))
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    within_budget = constraints <= CONSTRAINT_BUDGET

    return {
        "success": True,
        "constraints": constraints,
        "within_budget": within_budget,
        "r1cs_path": str(r1cs_path) if r1cs_path.exists() else None,
        "error": "" if within_budget else f"constraint budget exceeded: {constraints} > {CONSTRAINT_BUDGET}",
    }


def main() -> int:
    global CONSTRAINT_BUDGET
    ap = argparse.ArgumentParser(description="Compile circom circuit and check constraint budget")
    ap.add_argument("circuit", help="Path to .circom file")
    ap.add_argument("--budget", type=int, default=CONSTRAINT_BUDGET, help="Constraint budget")
    args = ap.parse_args()

    CONSTRAINT_BUDGET = args.budget

    result = compile_circuit(Path(args.circuit))
    print(json.dumps(result, indent=2))
    return 0 if result["success"] and result["within_budget"] else 1


if __name__ == "__main__":
    sys.exit(main())
