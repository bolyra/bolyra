#!/usr/bin/env python3
"""Benchmark circuit proving time, verification gas, and constraint counts.

Usage:
    python3 scripts/benchmark.py experiments/tier2_001_example/
    python3 scripts/benchmark.py experiments/tier2_001_example/ --circuit circuit.circom --input input.json

Outputs JSON to stdout:
    {
      "circuit_name": str,
      "constraints": int,
      "within_budget": bool,
      "prove_time_ms": float | null,
      "verify_time_ms": float | null,
      "gas_estimate": int | null,
      "witness_gen_ms": float | null,
      "error": str
    }

Requires: circom, snarkjs, and optionally solc/hardhat on PATH.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


CONSTRAINT_BUDGET = 80_000


def _run_timed(cmd: list[str], *, timeout: int = 120, cwd: str | None = None) -> tuple[float, subprocess.CompletedProcess]:
    """Run a command and return (elapsed_ms, CompletedProcess)."""
    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    elapsed = (time.monotonic() - start) * 1000
    return elapsed, result


def count_constraints(r1cs_path: Path) -> int | None:
    """Extract constraint count from r1cs via snarkjs."""
    if not r1cs_path.exists():
        return None
    try:
        _, result = _run_timed(["snarkjs", "r1cs", "info", str(r1cs_path)], timeout=30)
        for line in result.stdout.splitlines():
            if "# of Constraints:" in line:
                return int(line.split(":")[-1].strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass
    return None


def benchmark_witness_gen(wasm_dir: Path, input_path: Path) -> tuple[float | None, str]:
    """Generate witness and return (elapsed_ms, error)."""
    # Find the WASM file (circom outputs to <name>_js/generate_witness.js)
    wasm_candidates = list(wasm_dir.rglob("generate_witness.js"))
    if not wasm_candidates:
        return None, "no generate_witness.js found"
    if not input_path.exists():
        return None, f"input file not found: {input_path}"

    gen_script = wasm_candidates[0]
    wasm_file = gen_script.parent / (gen_script.parent.name.replace("_js", "") + ".wasm")
    if not wasm_file.exists():
        # Try alternative naming
        wasm_files = list(gen_script.parent.glob("*.wasm"))
        if not wasm_files:
            return None, "no .wasm circuit file found"
        wasm_file = wasm_files[0]

    witness_out = wasm_dir / "witness.wtns"
    try:
        elapsed, result = _run_timed(
            ["node", str(gen_script), str(wasm_file), str(input_path), str(witness_out)],
            timeout=60,
            cwd=str(wasm_dir),
        )
        if result.returncode != 0:
            return None, f"witness generation failed: {result.stderr[:300]}"
        return elapsed, ""
    except FileNotFoundError:
        return None, "node not found on PATH"
    except subprocess.TimeoutExpired:
        return None, "witness generation timed out (60s)"


def benchmark_prove(
    r1cs_path: Path, witness_path: Path, zkey_path: Path | None = None
) -> tuple[float | None, str]:
    """Run snarkjs groth16 prove and return (elapsed_ms, error)."""
    if not r1cs_path.exists():
        return None, f"r1cs not found: {r1cs_path}"
    if not witness_path.exists():
        return None, f"witness not found: {witness_path}"

    # If no zkey, we can't prove (would need a setup first)
    if zkey_path is None or not zkey_path.exists():
        return None, "no zkey found (run trusted setup first)"

    proof_out = r1cs_path.parent / "proof.json"
    public_out = r1cs_path.parent / "public.json"
    try:
        elapsed, result = _run_timed(
            ["snarkjs", "groth16", "prove", str(zkey_path), str(witness_path), str(proof_out), str(public_out)],
            timeout=300,
        )
        if result.returncode != 0:
            return None, f"proving failed: {result.stderr[:300]}"
        return elapsed, ""
    except FileNotFoundError:
        return None, "snarkjs not found on PATH"
    except subprocess.TimeoutExpired:
        return None, "proving timed out (300s)"


def benchmark_verify(
    vkey_path: Path, proof_path: Path, public_path: Path
) -> tuple[float | None, str]:
    """Run snarkjs groth16 verify and return (elapsed_ms, error)."""
    for p, name in [(vkey_path, "vkey"), (proof_path, "proof"), (public_path, "public")]:
        if not p.exists():
            return None, f"{name} not found: {p}"
    try:
        elapsed, result = _run_timed(
            ["snarkjs", "groth16", "verify", str(vkey_path), str(public_path), str(proof_path)],
            timeout=30,
        )
        if result.returncode != 0:
            return None, f"verification failed: {result.stderr[:300]}"
        return elapsed, ""
    except FileNotFoundError:
        return None, "snarkjs not found on PATH"
    except subprocess.TimeoutExpired:
        return None, "verification timed out (30s)"


def benchmark_experiment(
    experiment_dir: Path,
    *,
    circuit_name: str | None = None,
    input_name: str = "input.json",
) -> dict:
    """Run full benchmark suite on an experiment directory."""
    # Find circuit
    if circuit_name:
        circom_files = [experiment_dir / circuit_name]
    else:
        circom_files = list(experiment_dir.rglob("*.circom"))
    if not circom_files:
        return {
            "circuit_name": None,
            "constraints": None,
            "within_budget": None,
            "prove_time_ms": None,
            "verify_time_ms": None,
            "gas_estimate": None,
            "witness_gen_ms": None,
            "error": "no .circom files found in experiment directory",
        }

    circom_path = circom_files[0]
    stem = circom_path.stem
    r1cs_path = circom_path.parent / f"{stem}.r1cs"
    zkey_path = circom_path.parent / f"{stem}.zkey"
    vkey_path = circom_path.parent / "verification_key.json"
    witness_path = circom_path.parent / "witness.wtns"
    proof_path = circom_path.parent / "proof.json"
    public_path = circom_path.parent / "public.json"
    input_path = circom_path.parent / input_name

    result = {
        "circuit_name": stem,
        "constraints": None,
        "within_budget": None,
        "prove_time_ms": None,
        "verify_time_ms": None,
        "gas_estimate": None,
        "witness_gen_ms": None,
        "error": "",
    }

    # Count constraints if r1cs exists
    constraints = count_constraints(r1cs_path)
    if constraints is not None:
        result["constraints"] = constraints
        result["within_budget"] = constraints <= CONSTRAINT_BUDGET

    # Witness generation
    witness_ms, witness_err = benchmark_witness_gen(circom_path.parent, input_path)
    result["witness_gen_ms"] = witness_ms
    if witness_err:
        result["error"] += f"witness: {witness_err}; "

    # Proving
    prove_ms, prove_err = benchmark_prove(r1cs_path, witness_path, zkey_path)
    result["prove_time_ms"] = prove_ms
    if prove_err:
        result["error"] += f"prove: {prove_err}; "

    # Verification
    verify_ms, verify_err = benchmark_verify(vkey_path, proof_path, public_path)
    result["verify_time_ms"] = verify_ms
    if verify_err:
        result["error"] += f"verify: {verify_err}; "

    result["error"] = result["error"].rstrip("; ")
    return result


def main() -> int:
    global CONSTRAINT_BUDGET
    ap = argparse.ArgumentParser(description="Benchmark circuit/proof performance")
    ap.add_argument("experiment_dir", help="Path to experiment directory")
    ap.add_argument("--circuit", default=None, help="Circuit filename (auto-detected if omitted)")
    ap.add_argument("--input", default="input.json", help="Input JSON filename")
    ap.add_argument("--budget", type=int, default=CONSTRAINT_BUDGET, help="Constraint budget")
    args = ap.parse_args()

    CONSTRAINT_BUDGET = args.budget

    result = benchmark_experiment(
        Path(args.experiment_dir),
        circuit_name=args.circuit,
        input_name=args.input,
    )
    print(json.dumps(result, indent=2))

    if result.get("within_budget") is False:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
