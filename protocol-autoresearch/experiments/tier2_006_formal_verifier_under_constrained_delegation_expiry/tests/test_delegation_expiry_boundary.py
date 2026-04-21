#!/usr/bin/env python3
"""
Boundary witness test harness for DelegationExpiryCheck circuit.

Generates boundary witnesses and verifies expected accept/reject outcomes
for the delegation expiry narrowing constraints.

Requirements:
    - circom 2.1.6+
    - snarkjs
    - Node.js (for snarkjs CLI)

Usage:
    python tests/test_delegation_expiry_boundary.py
    pytest tests/test_delegation_expiry_boundary.py -v
"""

import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

import pytest

# ── Constants ────────────────────────────────────────────────────────────────
MAX_64 = (1 << 64) - 1  # 2^64 - 1 = 18446744073709551615
OVERFLOW_64 = 1 << 64   # 2^64 = 18446744073709551616
BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

CIRCUIT_DIR = Path(__file__).parent.parent / "circuits"
CIRCUIT_FILE = CIRCUIT_DIR / "DelegationExpiryCheck.circom"


@dataclass
class BoundaryCase:
    """A boundary test case for the DelegationExpiryCheck circuit."""
    name: str
    current_timestamp: int
    delegator_expiry: int
    delegatee_expiry: int
    should_accept: bool
    description: str


# ── Boundary test vectors ────────────────────────────────────────────────────
BOUNDARY_CASES = [
    # ── Valid cases (should accept) ──────────────────────────────────────
    BoundaryCase(
        name="nominal_valid",
        current_timestamp=1000,
        delegator_expiry=2000,
        delegatee_expiry=1500,
        should_accept=True,
        description="Normal case: ts=1000 < delegateeExp=1500 <= delegatorExp=2000",
    ),
    BoundaryCase(
        name="delegatee_equals_delegator_expiry",
        current_timestamp=1000,
        delegator_expiry=2000,
        delegatee_expiry=2000,
        should_accept=True,
        description="Boundary: delegateeExpiry == delegatorExpiry (valid, <= holds)",
    ),
    BoundaryCase(
        name="delegatee_one_less_than_delegator",
        current_timestamp=1000,
        delegator_expiry=2000,
        delegatee_expiry=1999,
        should_accept=True,
        description="delegateeExpiry = delegatorExpiry - 1",
    ),
    BoundaryCase(
        name="timestamp_one_less_than_delegatee",
        current_timestamp=1499,
        delegator_expiry=2000,
        delegatee_expiry=1500,
        should_accept=True,
        description="currentTimestamp = delegateeExpiry - 1 (just not expired)",
    ),
    BoundaryCase(
        name="zero_timestamp",
        current_timestamp=0,
        delegator_expiry=2000,
        delegatee_expiry=1500,
        should_accept=True,
        description="currentTimestamp = 0 (genesis)",
    ),
    BoundaryCase(
        name="expiry_zero_delegatee_valid",
        current_timestamp=0,
        delegator_expiry=1,
        delegatee_expiry=1,
        should_accept=True,
        description="Minimal valid: ts=0 < delegateeExp=1 <= delegatorExp=1",
    ),
    BoundaryCase(
        name="max_64_bit_expiry",
        current_timestamp=MAX_64 - 2,
        delegator_expiry=MAX_64,
        delegatee_expiry=MAX_64 - 1,
        should_accept=True,
        description="Near 64-bit boundary: all values near 2^64-1",
    ),
    BoundaryCase(
        name="max_64_both_expiries",
        current_timestamp=MAX_64 - 1,
        delegator_expiry=MAX_64,
        delegatee_expiry=MAX_64,
        should_accept=True,
        description="Both expiries at 2^64-1, timestamp one below",
    ),

    # ── Invalid cases (should reject) ────────────────────────────────────
    BoundaryCase(
        name="delegatee_exceeds_delegator",
        current_timestamp=1000,
        delegator_expiry=2000,
        delegatee_expiry=2001,
        should_accept=False,
        description="delegateeExpiry = delegatorExpiry + 1 (violates narrowing)",
    ),
    BoundaryCase(
        name="expired_delegation",
        current_timestamp=1500,
        delegator_expiry=2000,
        delegatee_expiry=1500,
        should_accept=False,
        description="currentTimestamp == delegateeExpiry (expired, needs strict <)",
    ),
    BoundaryCase(
        name="expired_delegation_past",
        current_timestamp=2000,
        delegator_expiry=2000,
        delegatee_expiry=1500,
        should_accept=False,
        description="currentTimestamp > delegateeExpiry (clearly expired)",
    ),
    BoundaryCase(
        name="zero_delegatee_expiry",
        current_timestamp=0,
        delegator_expiry=1000,
        delegatee_expiry=0,
        should_accept=False,
        description="delegateeExpiry = 0, currentTimestamp = 0 (not strictly less)",
    ),
    BoundaryCase(
        name="all_zero",
        current_timestamp=0,
        delegator_expiry=0,
        delegatee_expiry=0,
        should_accept=False,
        description="All zeros: ts=0 is not < delegateeExp=0",
    ),
    BoundaryCase(
        name="overflow_64_delegatee",
        current_timestamp=1000,
        delegator_expiry=OVERFLOW_64,
        delegatee_expiry=OVERFLOW_64,
        should_accept=False,
        description="delegateeExpiry = 2^64 (exceeds range check)",
    ),
    BoundaryCase(
        name="overflow_64_delegator",
        current_timestamp=1000,
        delegator_expiry=OVERFLOW_64,
        delegatee_expiry=1500,
        should_accept=False,
        description="delegatorExpiry = 2^64 (exceeds range check)",
    ),
    BoundaryCase(
        name="overflow_64_timestamp",
        current_timestamp=OVERFLOW_64,
        delegator_expiry=OVERFLOW_64 + 1,
        delegatee_expiry=OVERFLOW_64 + 1,
        should_accept=False,
        description="All values exceed 2^64 (range check fails)",
    ),
    BoundaryCase(
        name="wraparound_attack_field_minus_one",
        current_timestamp=1000,
        delegator_expiry=2000,
        delegatee_expiry=BN254_P - 1,
        should_accept=False,
        description="Wraparound attack: delegateeExpiry = p-1 (huge field element)",
    ),
    BoundaryCase(
        name="wraparound_attack_near_p",
        current_timestamp=1000,
        delegator_expiry=BN254_P - 2,
        delegatee_expiry=BN254_P - 1,
        should_accept=False,
        description="Wraparound attack: both expiries near p (field-element trick)",
    ),
]


def generate_witness_input(case: BoundaryCase) -> dict:
    """Generate the circuit input JSON for a boundary case."""
    return {
        "currentTimestamp": str(case.current_timestamp),
        "delegatorExpiry": str(case.delegator_expiry),
        "delegateeExpiry": str(case.delegatee_expiry),
    }


def compile_circuit(work_dir: Path) -> Path:
    """Compile the DelegationExpiryCheck circuit. Returns path to wasm dir."""
    build_dir = work_dir / "build"
    build_dir.mkdir(exist_ok=True)

    result = subprocess.run(
        [
            "circom",
            str(CIRCUIT_FILE),
            "--r1cs",
            "--wasm",
            "--sym",
            "-o",
            str(build_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(CIRCUIT_DIR),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Circuit compilation failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    wasm_dir = build_dir / "DelegationExpiryCheck_js"
    assert wasm_dir.exists(), f"WASM directory not found at {wasm_dir}"
    return wasm_dir


def try_generate_witness(
    wasm_dir: Path, input_json: dict, work_dir: Path
) -> tuple[bool, str]:
    """Attempt witness generation. Returns (success, output)."""
    input_path = work_dir / "input.json"
    witness_path = work_dir / "witness.wtns"

    with open(input_path, "w") as f:
        json.dump(input_json, f)

    generate_js = wasm_dir / "generate_witness.js"
    wasm_file = wasm_dir / "DelegationExpiryCheck.wasm"

    result = subprocess.run(
        [
            "node",
            str(generate_js),
            str(wasm_file),
            str(input_path),
            str(witness_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    output = f"stdout: {result.stdout}\nstderr: {result.stderr}"
    success = result.returncode == 0 and witness_path.exists()
    return success, output


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def compiled_circuit(tmp_path_factory):
    """Compile circuit once for all tests."""
    work_dir = tmp_path_factory.mktemp("circuit_build")
    try:
        wasm_dir = compile_circuit(work_dir)
        return wasm_dir
    except (RuntimeError, FileNotFoundError) as e:
        pytest.skip(f"Circuit compilation unavailable: {e}")


# ── Parametrized tests ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "case",
    [c for c in BOUNDARY_CASES if c.should_accept],
    ids=[c.name for c in BOUNDARY_CASES if c.should_accept],
)
def test_valid_witness_accepted(compiled_circuit, case, tmp_path):
    """Valid boundary witnesses must produce a satisfying witness."""
    input_json = generate_witness_input(case)
    success, output = try_generate_witness(compiled_circuit, input_json, tmp_path)
    assert success, (
        f"Expected ACCEPT for '{case.name}': {case.description}\n"
        f"Input: {input_json}\n"
        f"Output: {output}"
    )


@pytest.mark.parametrize(
    "case",
    [c for c in BOUNDARY_CASES if not c.should_accept],
    ids=[c.name for c in BOUNDARY_CASES if not c.should_accept],
)
def test_invalid_witness_rejected(compiled_circuit, case, tmp_path):
    """Invalid boundary witnesses must fail witness generation."""
    input_json = generate_witness_input(case)
    success, output = try_generate_witness(compiled_circuit, input_json, tmp_path)
    assert not success, (
        f"Expected REJECT for '{case.name}': {case.description}\n"
        f"Input: {input_json}\n"
        f"Output: {output}"
    )


# ── Constraint count verification ────────────────────────────────────────────

def test_constraint_count(compiled_circuit, tmp_path):
    """Verify constraint count is in the expected range (~320-340)."""
    build_dir = compiled_circuit.parent
    r1cs_file = build_dir / "DelegationExpiryCheck.r1cs"

    if not r1cs_file.exists():
        pytest.skip("R1CS file not found")

    result = subprocess.run(
        ["snarkjs", "r1cs", "info", str(r1cs_file)],
        capture_output=True,
        text=True,
    )

    # Parse constraint count from snarkjs output
    for line in result.stdout.splitlines():
        if "Constraints" in line:
            count = int("".join(c for c in line.split(":")[-1] if c.isdigit()))
            # Expected: ~329 constraints
            # Allow range 280-400 to account for circomlib version differences
            assert 280 <= count <= 400, (
                f"Constraint count {count} outside expected range [280, 400].\n"
                f"Expected ~329: 3*Num2Bits(64) + LessEqThan(64) + LessThan(64) + 2 assertions"
            )
            print(f"Constraint count: {count} (expected ~329)")
            return

    pytest.skip("Could not parse constraint count from snarkjs output")


# ── Standalone runner ────────────────────────────────────────────────────────

def run_standalone():
    """Run all boundary cases and report results without pytest."""
    print("DelegationExpiryCheck Boundary Witness Test Harness")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        work_dir = Path(tmpdir)
        print("\nCompiling circuit...")
        try:
            wasm_dir = compile_circuit(work_dir)
        except (RuntimeError, FileNotFoundError) as e:
            print(f"SKIP: {e}")
            return

        print(f"Circuit compiled to {wasm_dir}")
        print("\nRunning boundary tests:")
        print("-" * 60)

        passed = 0
        failed = 0
        for case in BOUNDARY_CASES:
            input_json = generate_witness_input(case)
            case_dir = work_dir / case.name
            case_dir.mkdir()

            success, output = try_generate_witness(wasm_dir, input_json, case_dir)

            expected_result = "ACCEPT" if case.should_accept else "REJECT"
            actual_result = "ACCEPT" if success else "REJECT"
            test_passed = (success == case.should_accept)

            status = "PASS" if test_passed else "FAIL"
            icon = "  OK" if test_passed else "FAIL"

            print(f"  [{icon}] {case.name}")
            print(f"        {case.description}")
            print(f"        Expected: {expected_result}, Got: {actual_result}")

            if test_passed:
                passed += 1
            else:
                failed += 1
                print(f"        OUTPUT: {output[:200]}")

        print("\n" + "=" * 60)
        print(f"Results: {passed} passed, {failed} failed, {len(BOUNDARY_CASES)} total")

        if failed > 0:
            print("\nSOME TESTS FAILED")
            exit(1)
        else:
            print("\nALL TESTS PASSED")


if __name__ == "__main__":
    run_standalone()
