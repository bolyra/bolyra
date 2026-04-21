#!/usr/bin/env python3
"""Typecheck SDK modules (TypeScript via tsc, Python via pyright/mypy).

Usage:
    python3 scripts/sdk_typecheck.py experiments/tier2_001_example/sdk.ts
    python3 scripts/sdk_typecheck.py experiments/tier2_001_example/ --all

Outputs JSON to stdout:
    {"success": bool, "checker": str, "errors": [], "files_checked": int}

Requires: tsc (for .ts) and/or pyright or mypy (for .py) on PATH.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def typecheck_typescript(ts_path: Path) -> dict:
    """Typecheck a TypeScript file or directory with tsc --noEmit."""
    if ts_path.is_file() and ts_path.suffix not in (".ts", ".tsx"):
        return {"success": True, "checker": "tsc", "errors": [], "files_checked": 0, "note": "not a TS file"}

    # Check tsc availability
    try:
        subprocess.run(["npx", "tsc", "--version"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return {"success": False, "checker": "tsc", "errors": ["npx/tsc not found on PATH"], "files_checked": 0}

    target = str(ts_path)
    cmd = ["npx", "tsc", "--noEmit", "--strict", "--skipLibCheck"]
    if ts_path.is_file():
        cmd.append(target)
    else:
        # Check for tsconfig
        tsconfig = ts_path / "tsconfig.json"
        if tsconfig.exists():
            cmd.extend(["-p", str(tsconfig)])
        else:
            # Glob ts files
            ts_files = list(ts_path.rglob("*.ts")) + list(ts_path.rglob("*.tsx"))
            if not ts_files:
                return {"success": True, "checker": "tsc", "errors": [], "files_checked": 0, "note": "no TS files"}
            cmd.extend(str(f) for f in ts_files[:20])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"success": False, "checker": "tsc", "errors": ["tsc timed out (60s)"], "files_checked": 0}

    errors = [
        line.strip() for line in (result.stdout + result.stderr).splitlines()
        if "error TS" in line
    ]

    return {
        "success": result.returncode == 0,
        "checker": "tsc",
        "errors": errors[:20],
        "files_checked": len(list(ts_path.rglob("*.ts"))) if ts_path.is_dir() else 1,
    }


def typecheck_python(py_path: Path) -> dict:
    """Typecheck Python files with pyright or mypy."""
    if py_path.is_file() and py_path.suffix != ".py":
        return {"success": True, "checker": "none", "errors": [], "files_checked": 0, "note": "not a .py file"}

    # Try pyright first, then mypy
    for checker, cmd_base in [("pyright", ["pyright"]), ("mypy", ["mypy", "--ignore-missing-imports"])]:
        try:
            subprocess.run([cmd_base[0], "--version"], capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            continue

        cmd = cmd_base + [str(py_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return {"success": False, "checker": checker, "errors": [f"{checker} timed out (60s)"], "files_checked": 0}

        errors = [
            line.strip() for line in (result.stdout + result.stderr).splitlines()
            if "error" in line.lower() and not line.startswith("Found")
        ]

        file_count = len(list(py_path.rglob("*.py"))) if py_path.is_dir() else 1
        return {
            "success": result.returncode == 0,
            "checker": checker,
            "errors": errors[:20],
            "files_checked": file_count,
        }

    return {
        "success": False,
        "checker": "none",
        "errors": ["neither pyright nor mypy found on PATH"],
        "files_checked": 0,
    }


def typecheck_all(directory: Path) -> dict:
    """Typecheck all SDK files in a directory."""
    ts_result = typecheck_typescript(directory)
    py_result = typecheck_python(directory)

    combined_success = ts_result["success"] and py_result["success"]
    combined_errors = ts_result.get("errors", []) + py_result.get("errors", [])
    total_files = ts_result.get("files_checked", 0) + py_result.get("files_checked", 0)

    return {
        "success": combined_success,
        "checker": f"ts:{ts_result['checker']}+py:{py_result['checker']}",
        "errors": combined_errors[:30],
        "files_checked": total_files,
        "typescript": ts_result,
        "python": py_result,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Typecheck SDK modules")
    ap.add_argument("path", help="Path to .ts/.py file or directory")
    ap.add_argument("--all", action="store_true", help="Check both TS and Python in directory")
    args = ap.parse_args()

    target = Path(args.path)
    if args.all or target.is_dir():
        result = typecheck_all(target if target.is_dir() else target.parent)
    elif target.suffix in (".ts", ".tsx"):
        result = typecheck_typescript(target)
    elif target.suffix == ".py":
        result = typecheck_python(target)
    else:
        result = {"success": False, "checker": "none", "errors": [f"unknown file type: {target.suffix}"], "files_checked": 0}

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
