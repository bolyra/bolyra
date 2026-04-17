"""24-check protocol harness scoring across 4 dimensions.

Scores protocol experiments on CORRECTNESS, COMPLETENESS, ADOPTION, STANDARDS
(25 pts each, 100 total). File-existence checks work immediately; build-dependent
checks are stubbed; LLM-judged checks use call_claude_cli.

Uses Claude MAX login via the `claude` CLI, never API keys or the SDK.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from _shared import call_claude_cli, extract_json_object


# ---------------------------------------------------------------------------
# Dimensions and point allocations
# ---------------------------------------------------------------------------

DIMENSIONS: list[str] = ["correctness", "completeness", "adoption", "standards"]
MAX_PER_DIMENSION: int = 25
MAX_TOTAL: int = MAX_PER_DIMENSION * len(DIMENSIONS)  # 100

# Per-check point allocations (dimension → check_name → max_points)
CHECK_POINTS: dict[str, dict[str, int]] = {
    "correctness": {
        "check_circuit_compiles": 4,
        "check_witness_generation": 3,
        "check_proof_roundtrip": 4,
        "check_contract_compiles": 3,
        "check_existing_tests_pass": 5,
        "check_new_tests_pass": 4,
        "check_no_shared_modified": 2,
    },
    "completeness": {
        "check_circuit_exists": 3,
        "check_contract_exists": 3,
        "check_spec_section_exists": 4,
        "check_test_vectors_exist": 4,
        "check_cip_feature_implemented": 6,
        "check_constraint_budget": 5,
    },
    "adoption": {
        "check_sdk_module_exists": 4,
        "check_sdk_types": 3,
        "check_sdk_test_exists": 3,
        "check_framework_integration": 4,
        "check_tthw_estimate": 5,
        "check_error_messages": 3,
        "check_docs_exist": 3,
    },
    "standards": {
        "check_normative_language": 5,
        "check_test_vectors_conformance": 5,
        "check_interop_evidence": 5,
        "check_spec_completeness_llm": 10,
    },
}

# Checks that are LLM-judged (use call_claude_cli)
LLM_CHECKS: set[str] = {
    "check_cip_feature_implemented",
    "check_tthw_estimate",
    "check_spec_completeness_llm",
}

# Checks that require build tooling (stubbed for now)
BUILD_CHECKS: set[str] = {
    "check_circuit_compiles",
    "check_witness_generation",
    "check_proof_roundtrip",
    "check_contract_compiles",
    "check_existing_tests_pass",
    "check_new_tests_pass",
    "check_constraint_budget",
}

# Hard-fail checks: if they fail, total goes to 0
HARD_FAIL_CHECKS: set[str] = {
    "check_no_shared_modified",
    "check_circuit_compiles",
    "check_existing_tests_pass",
}

# Verdict thresholds (per program.md §4)
PROMOTE_TOTAL_MIN: int = 75
PROMOTE_ALL_DIMS_MIN: int = 15
CONSIDER_TOTAL_MIN: int = 60
DROP_IF_ANY_DIM_LE: int = 8


@dataclass
class CheckResult:
    name: str
    dimension: str
    points: int
    max_points: int
    note: str = ""
    hard_fail: bool = False


@dataclass
class DimensionScore:
    name: str
    points: int
    max_points: int = MAX_PER_DIMENSION
    checks: list[CheckResult] = field(default_factory=list)


@dataclass
class ExperimentScore:
    experiment_id: str
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    checks: list[CheckResult] = field(default_factory=list)
    total: int = 0
    verdict: str = "drop"
    hard_fail_triggered: bool = False

    def finalize(self) -> None:
        """Compute total and verdict from dimension scores."""
        # Check for hard fails
        for c in self.checks:
            if c.hard_fail:
                self.hard_fail_triggered = True
                self.total = 0
                self.verdict = "drop"
                return

        self.total = sum(d.points for d in self.dimensions.values())
        any_too_low = any(d.points <= DROP_IF_ANY_DIM_LE for d in self.dimensions.values())
        all_above_promote_floor = all(d.points >= PROMOTE_ALL_DIMS_MIN for d in self.dimensions.values())

        if any_too_low or self.total < CONSIDER_TOTAL_MIN:
            self.verdict = "drop"
        elif self.total >= PROMOTE_TOTAL_MIN and all_above_promote_floor:
            self.verdict = "promote"
        elif self.total >= CONSIDER_TOTAL_MIN:
            self.verdict = "consider"
        else:
            self.verdict = "drop"


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------

def _find_files(experiment_dir: Path, patterns: list[str]) -> list[Path]:
    """Find files matching any of the given glob patterns in experiment_dir."""
    found = []
    for pattern in patterns:
        found.extend(experiment_dir.rglob(pattern))
    return found


# --- CORRECTNESS checks ---

def check_circuit_compiles(experiment_dir: Path) -> CheckResult:
    """Check that circom compiles to r1cs. STUBBED — requires circom toolchain."""
    return CheckResult(
        name="check_circuit_compiles", dimension="correctness",
        points=0, max_points=4, note="not yet implemented: requires circom toolchain"
    )


def check_witness_generation(experiment_dir: Path) -> CheckResult:
    """Check witness generation from input.json. STUBBED."""
    return CheckResult(
        name="check_witness_generation", dimension="correctness",
        points=0, max_points=3, note="not yet implemented: requires witness generation toolchain"
    )


def check_proof_roundtrip(experiment_dir: Path) -> CheckResult:
    """Check prove + verify roundtrip. STUBBED."""
    return CheckResult(
        name="check_proof_roundtrip", dimension="correctness",
        points=0, max_points=4, note="not yet implemented: requires snarkjs"
    )


def check_contract_compiles(experiment_dir: Path) -> CheckResult:
    """Check hardhat compile succeeds. STUBBED."""
    return CheckResult(
        name="check_contract_compiles", dimension="correctness",
        points=0, max_points=3, note="not yet implemented: requires hardhat"
    )


def check_existing_tests_pass(experiment_dir: Path) -> CheckResult:
    """Check that existing 104+7 tests still pass. STUBBED."""
    return CheckResult(
        name="check_existing_tests_pass", dimension="correctness",
        points=0, max_points=5, note="not yet implemented: requires test runner"
    )


def check_new_tests_pass(experiment_dir: Path) -> CheckResult:
    """Check that experiment's own tests pass. STUBBED."""
    return CheckResult(
        name="check_new_tests_pass", dimension="correctness",
        points=0, max_points=4, note="not yet implemented: requires test runner"
    )


def check_no_shared_modified(experiment_dir: Path) -> CheckResult:
    """HARD FAIL: verify no files outside experiments/ were modified.

    For now, checks that experiment_dir is inside an experiments/ parent.
    """
    parts = experiment_dir.resolve().parts
    if "experiments" in parts:
        return CheckResult(
            name="check_no_shared_modified", dimension="correctness",
            points=2, max_points=2, note="experiment is contained within experiments/"
        )
    return CheckResult(
        name="check_no_shared_modified", dimension="correctness",
        points=0, max_points=2, note="experiment not in experiments/ directory",
        hard_fail=True,
    )


# --- COMPLETENESS checks ---

def check_circuit_exists(experiment_dir: Path) -> CheckResult:
    """Check that a circuit file (.circom) exists in the experiment."""
    found = _find_files(experiment_dir, ["*.circom"])
    if found:
        return CheckResult(
            name="check_circuit_exists", dimension="completeness",
            points=3, max_points=3, note=f"found: {[f.name for f in found]}"
        )
    return CheckResult(
        name="check_circuit_exists", dimension="completeness",
        points=0, max_points=3, note="no .circom files found"
    )


def check_contract_exists(experiment_dir: Path) -> CheckResult:
    """Check that a contract file (.sol) exists."""
    found = _find_files(experiment_dir, ["*.sol"])
    if found:
        return CheckResult(
            name="check_contract_exists", dimension="completeness",
            points=3, max_points=3, note=f"found: {[f.name for f in found]}"
        )
    return CheckResult(
        name="check_contract_exists", dimension="completeness",
        points=0, max_points=3, note="no .sol files found"
    )


def check_spec_section_exists(experiment_dir: Path) -> CheckResult:
    """Check that a spec/specification file exists with normative language."""
    found = _find_files(experiment_dir, ["*spec*", "*SPEC*", "*.md"])
    for f in found:
        try:
            content = f.read_text()
            if any(kw in content for kw in ["MUST", "SHOULD", "MAY"]):
                return CheckResult(
                    name="check_spec_section_exists", dimension="completeness",
                    points=4, max_points=4, note=f"found spec with normative language: {f.name}"
                )
        except Exception:
            continue
    if found:
        return CheckResult(
            name="check_spec_section_exists", dimension="completeness",
            points=2, max_points=4, note="found markdown/spec files but no normative language"
        )
    return CheckResult(
        name="check_spec_section_exists", dimension="completeness",
        points=0, max_points=4, note="no spec files found"
    )


def check_test_vectors_exist(experiment_dir: Path) -> CheckResult:
    """Check that JSON test vectors exist."""
    found = _find_files(experiment_dir, ["*test_vector*", "*test-vector*", "*vectors*"])
    json_found = [f for f in found if f.suffix == ".json"]
    if json_found:
        return CheckResult(
            name="check_test_vectors_exist", dimension="completeness",
            points=4, max_points=4, note=f"found: {[f.name for f in json_found]}"
        )
    if found:
        return CheckResult(
            name="check_test_vectors_exist", dimension="completeness",
            points=2, max_points=4, note="found test vector files but not JSON format"
        )
    return CheckResult(
        name="check_test_vectors_exist", dimension="completeness",
        points=0, max_points=4, note="no test vector files found"
    )


def check_cip_feature_implemented(experiment_dir: Path, candidate: dict | None = None) -> CheckResult:
    """LLM judge: is the CIP feature actually implemented?"""
    if candidate is None:
        return CheckResult(
            name="check_cip_feature_implemented", dimension="completeness",
            points=0, max_points=6, note="no candidate context provided"
        )
    # Gather experiment file contents for context
    files_content = _gather_experiment_files(experiment_dir)
    prompt = (
        "You are a protocol reviewer. The candidate proposed this improvement:\n\n"
        f"CANDIDATE:\n{json.dumps(candidate, indent=2)[:4000]}\n\n"
        f"EXPERIMENT FILES:\n{files_content[:12000]}\n\n"
        "Score the implementation completeness on 0-6:\n"
        "0: nothing implemented\n"
        "1-2: skeleton only\n"
        "3-4: partially implemented\n"
        "5-6: fully implemented with edge cases\n\n"
        'Return ONLY a JSON object: {"points": N, "reasoning": "..."}\n'
    )
    try:
        raw = call_claude_cli(prompt, model="sonnet", timeout=120)
        data = extract_json_object(raw)
        points = min(6, max(0, int(data.get("points", 0))))
        return CheckResult(
            name="check_cip_feature_implemented", dimension="completeness",
            points=points, max_points=6, note=str(data.get("reasoning", ""))[:200]
        )
    except Exception as e:
        return CheckResult(
            name="check_cip_feature_implemented", dimension="completeness",
            points=0, max_points=6, note=f"LLM judge failed: {e}"
        )


def check_constraint_budget(experiment_dir: Path) -> CheckResult:
    """Check circuit constraint count <= 80k. STUBBED."""
    return CheckResult(
        name="check_constraint_budget", dimension="completeness",
        points=0, max_points=5, note="not yet implemented: requires circom compilation"
    )


# --- ADOPTION checks ---

def check_sdk_module_exists(experiment_dir: Path) -> CheckResult:
    """Check that a TypeScript or Python SDK module exists."""
    ts_files = _find_files(experiment_dir, ["*.ts", "*.tsx"])
    py_files = _find_files(experiment_dir, ["*.py"])
    sdk_files = [f for f in ts_files + py_files if "sdk" in f.name.lower() or "sdk" in str(f.parent).lower()]
    if sdk_files:
        return CheckResult(
            name="check_sdk_module_exists", dimension="adoption",
            points=4, max_points=4, note=f"found SDK modules: {[f.name for f in sdk_files]}"
        )
    # Also accept any ts/py in a module-like structure
    if ts_files or py_files:
        return CheckResult(
            name="check_sdk_module_exists", dimension="adoption",
            points=2, max_points=4, note="found code files but not in SDK structure"
        )
    return CheckResult(
        name="check_sdk_module_exists", dimension="adoption",
        points=0, max_points=4, note="no SDK module files found"
    )


def check_sdk_types(experiment_dir: Path) -> CheckResult:
    """Check for exported TypeScript types or Python type hints."""
    ts_files = _find_files(experiment_dir, ["*.ts", "*.d.ts"])
    for f in ts_files:
        try:
            content = f.read_text()
            if "export " in content and ("interface " in content or "type " in content):
                return CheckResult(
                    name="check_sdk_types", dimension="adoption",
                    points=3, max_points=3, note=f"found typed exports in {f.name}"
                )
        except Exception:
            continue
    py_files = _find_files(experiment_dir, ["*.py"])
    for f in py_files:
        try:
            content = f.read_text()
            if ":" in content and ("def " in content or "class " in content):
                return CheckResult(
                    name="check_sdk_types", dimension="adoption",
                    points=3, max_points=3, note=f"found type hints in {f.name}"
                )
        except Exception:
            continue
    return CheckResult(
        name="check_sdk_types", dimension="adoption",
        points=0, max_points=3, note="no typed exports found"
    )


def check_sdk_test_exists(experiment_dir: Path) -> CheckResult:
    """Check that SDK unit tests exist."""
    found = _find_files(experiment_dir, ["test_*.py", "*_test.py", "*.test.ts", "*.spec.ts"])
    if found:
        return CheckResult(
            name="check_sdk_test_exists", dimension="adoption",
            points=3, max_points=3, note=f"found test files: {[f.name for f in found]}"
        )
    return CheckResult(
        name="check_sdk_test_exists", dimension="adoption",
        points=0, max_points=3, note="no test files found"
    )


def check_framework_integration(experiment_dir: Path) -> CheckResult:
    """Check for LangChain/CrewAI/AutoGen integration files."""
    all_files = _find_files(experiment_dir, ["*.py", "*.ts"])
    keywords = ["langchain", "crewai", "autogen", "BaseTool", "Tool"]
    for f in all_files:
        try:
            content = f.read_text().lower()
            if any(kw.lower() in content for kw in keywords):
                return CheckResult(
                    name="check_framework_integration", dimension="adoption",
                    points=4, max_points=4, note=f"found framework integration in {f.name}"
                )
        except Exception:
            continue
    return CheckResult(
        name="check_framework_integration", dimension="adoption",
        points=0, max_points=4, note="no framework integration found"
    )


def check_tthw_estimate(experiment_dir: Path) -> CheckResult:
    """LLM judge: how many lines to hello-world?"""
    files_content = _gather_experiment_files(experiment_dir)
    if not files_content.strip():
        return CheckResult(
            name="check_tthw_estimate", dimension="adoption",
            points=0, max_points=5, note="no experiment files to evaluate"
        )
    prompt = (
        "You are a developer experience reviewer. Given these SDK/library files, "
        "estimate how many lines of code a developer needs to write a hello-world.\n\n"
        f"FILES:\n{files_content[:12000]}\n\n"
        "Score on 0-5:\n"
        "0: >50 lines or unclear how to use\n"
        "1-2: 20-50 lines\n"
        "3-4: 10-20 lines\n"
        "5: <10 lines, obvious API\n\n"
        'Return ONLY: {"points": N, "reasoning": "...", "estimated_lines": N}\n'
    )
    try:
        raw = call_claude_cli(prompt, model="sonnet", timeout=120)
        data = extract_json_object(raw)
        points = min(5, max(0, int(data.get("points", 0))))
        return CheckResult(
            name="check_tthw_estimate", dimension="adoption",
            points=points, max_points=5, note=str(data.get("reasoning", ""))[:200]
        )
    except Exception as e:
        return CheckResult(
            name="check_tthw_estimate", dimension="adoption",
            points=0, max_points=5, note=f"LLM judge failed: {e}"
        )


def check_error_messages(experiment_dir: Path) -> CheckResult:
    """Check for custom error types/messages."""
    all_files = _find_files(experiment_dir, ["*.py", "*.ts", "*.sol"])
    for f in all_files:
        try:
            content = f.read_text()
            if any(kw in content for kw in ["Error(", "error ", "revert ", "raise ", "class Error", "custom_error"]):
                return CheckResult(
                    name="check_error_messages", dimension="adoption",
                    points=3, max_points=3, note=f"found error handling in {f.name}"
                )
        except Exception:
            continue
    return CheckResult(
        name="check_error_messages", dimension="adoption",
        points=0, max_points=3, note="no custom error handling found"
    )


def check_docs_exist(experiment_dir: Path) -> CheckResult:
    """Check for README or usage documentation."""
    found = _find_files(experiment_dir, ["README*", "readme*", "USAGE*", "docs/*"])
    if found:
        return CheckResult(
            name="check_docs_exist", dimension="adoption",
            points=3, max_points=3, note=f"found docs: {[f.name for f in found]}"
        )
    return CheckResult(
        name="check_docs_exist", dimension="adoption",
        points=0, max_points=3, note="no documentation files found"
    )


# --- STANDARDS checks ---

def check_normative_language(experiment_dir: Path) -> CheckResult:
    """Check for RFC 2119 MUST/SHOULD/MAY keywords."""
    found = _find_files(experiment_dir, ["*.md", "*spec*"])
    for f in found:
        try:
            content = f.read_text()
            keywords_found = [kw for kw in ["MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY"]
                              if kw in content]
            if len(keywords_found) >= 3:
                return CheckResult(
                    name="check_normative_language", dimension="standards",
                    points=5, max_points=5, note=f"found {keywords_found} in {f.name}"
                )
            elif keywords_found:
                return CheckResult(
                    name="check_normative_language", dimension="standards",
                    points=3, max_points=5, note=f"found {keywords_found} (partial) in {f.name}"
                )
        except Exception:
            continue
    return CheckResult(
        name="check_normative_language", dimension="standards",
        points=0, max_points=5, note="no normative language found"
    )


def check_test_vectors_conformance(experiment_dir: Path) -> CheckResult:
    """Check for machine-parseable JSON test vectors."""
    found = _find_files(experiment_dir, ["*vector*", "*test*"])
    json_vectors = [f for f in found if f.suffix == ".json"]
    if json_vectors:
        # Verify they actually parse
        valid = 0
        for f in json_vectors:
            try:
                data = json.loads(f.read_text())
                if isinstance(data, (list, dict)):
                    valid += 1
            except Exception:
                continue
        if valid:
            return CheckResult(
                name="check_test_vectors_conformance", dimension="standards",
                points=5, max_points=5, note=f"found {valid} valid JSON test vector files"
            )
    return CheckResult(
        name="check_test_vectors_conformance", dimension="standards",
        points=0, max_points=5, note="no conformant test vectors found"
    )


def check_interop_evidence(experiment_dir: Path) -> CheckResult:
    """Check for multi-chain or multi-prover interop evidence."""
    all_files = _find_files(experiment_dir, ["*.md", "*.json", "*.ts", "*.py", "*.sol"])
    interop_keywords = ["base", "arbitrum", "polygon", "groth16", "plonk", "halo2",
                        "cross-chain", "bridge", "interop", "multi-chain"]
    for f in all_files:
        try:
            content = f.read_text().lower()
            found = [kw for kw in interop_keywords if kw in content]
            if len(found) >= 2:
                return CheckResult(
                    name="check_interop_evidence", dimension="standards",
                    points=5, max_points=5, note=f"found interop keywords: {found[:5]}"
                )
        except Exception:
            continue
    return CheckResult(
        name="check_interop_evidence", dimension="standards",
        points=0, max_points=5, note="no interop evidence found"
    )


def check_spec_completeness_llm(experiment_dir: Path) -> CheckResult:
    """LLM judge: how complete and implementable is the spec?"""
    files_content = _gather_experiment_files(experiment_dir, patterns=["*.md", "*spec*"])
    if not files_content.strip():
        return CheckResult(
            name="check_spec_completeness_llm", dimension="standards",
            points=0, max_points=10, note="no spec files to evaluate"
        )
    prompt = (
        "You are an IETF spec reviewer. Evaluate this protocol specification.\n\n"
        f"SPEC FILES:\n{files_content[:15000]}\n\n"
        "Score on 0-10:\n"
        "0-2: No spec or just notes\n"
        "3-4: Outline only, no normative requirements\n"
        "5-6: Partial spec with some MUST/SHOULD statements\n"
        "7-8: Mostly complete, implementable without source code reference\n"
        "9-10: IETF/W3C working draft quality\n\n"
        'Return ONLY: {"points": N, "reasoning": "..."}\n'
    )
    try:
        raw = call_claude_cli(prompt, model="sonnet", timeout=120)
        data = extract_json_object(raw)
        points = min(10, max(0, int(data.get("points", 0))))
        return CheckResult(
            name="check_spec_completeness_llm", dimension="standards",
            points=points, max_points=10, note=str(data.get("reasoning", ""))[:200]
        )
    except Exception as e:
        return CheckResult(
            name="check_spec_completeness_llm", dimension="standards",
            points=0, max_points=10, note=f"LLM judge failed: {e}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gather_experiment_files(experiment_dir: Path, patterns: list[str] | None = None) -> str:
    """Read experiment files into a single string for LLM context."""
    if patterns is None:
        patterns = ["*.py", "*.ts", "*.sol", "*.circom", "*.md", "*.json"]
    files_content = []
    for pattern in patterns:
        for f in experiment_dir.rglob(pattern):
            try:
                content = f.read_text()
                files_content.append(f"--- {f.relative_to(experiment_dir)} ---\n{content}\n")
            except Exception:
                continue
    return "\n".join(files_content)


# ---------------------------------------------------------------------------
# Dispatch map: check_name → callable
# ---------------------------------------------------------------------------

CHECK_FUNCTIONS: dict[str, Any] = {
    "check_circuit_compiles": check_circuit_compiles,
    "check_witness_generation": check_witness_generation,
    "check_proof_roundtrip": check_proof_roundtrip,
    "check_contract_compiles": check_contract_compiles,
    "check_existing_tests_pass": check_existing_tests_pass,
    "check_new_tests_pass": check_new_tests_pass,
    "check_no_shared_modified": check_no_shared_modified,
    "check_circuit_exists": check_circuit_exists,
    "check_contract_exists": check_contract_exists,
    "check_spec_section_exists": check_spec_section_exists,
    "check_test_vectors_exist": check_test_vectors_exist,
    "check_cip_feature_implemented": check_cip_feature_implemented,
    "check_constraint_budget": check_constraint_budget,
    "check_sdk_module_exists": check_sdk_module_exists,
    "check_sdk_types": check_sdk_types,
    "check_sdk_test_exists": check_sdk_test_exists,
    "check_framework_integration": check_framework_integration,
    "check_tthw_estimate": check_tthw_estimate,
    "check_error_messages": check_error_messages,
    "check_docs_exist": check_docs_exist,
    "check_normative_language": check_normative_language,
    "check_test_vectors_conformance": check_test_vectors_conformance,
    "check_interop_evidence": check_interop_evidence,
    "check_spec_completeness_llm": check_spec_completeness_llm,
}


def score_experiment(
    experiment_dir: Path,
    candidate: dict | None = None,
    *,
    skip_llm: bool = False,
    skip_build: bool = False,
) -> ExperimentScore:
    """Run all 24 checks against an experiment directory.

    Args:
        experiment_dir: path to the experiment artifacts
        candidate: optional candidate dict for LLM-judged checks context
        skip_llm: skip LLM-judged checks (for fast testing)
        skip_build: skip build-dependent checks (they are stubbed anyway)

    Returns:
        ExperimentScore with all checks, dimension scores, and verdict.
    """
    experiment_id = experiment_dir.name
    all_checks: list[CheckResult] = []

    for dim_name, checks in CHECK_POINTS.items():
        for check_name, max_pts in checks.items():
            if skip_llm and check_name in LLM_CHECKS:
                all_checks.append(CheckResult(
                    name=check_name, dimension=dim_name,
                    points=0, max_points=max_pts, note="skipped: LLM checks disabled"
                ))
                continue
            if skip_build and check_name in BUILD_CHECKS:
                all_checks.append(CheckResult(
                    name=check_name, dimension=dim_name,
                    points=0, max_points=max_pts, note="skipped: build checks disabled"
                ))
                continue

            fn = CHECK_FUNCTIONS[check_name]
            # LLM checks get candidate context
            if check_name == "check_cip_feature_implemented":
                result = fn(experiment_dir, candidate)
            else:
                result = fn(experiment_dir)
            all_checks.append(result)

    # Aggregate by dimension
    dim_scores: dict[str, DimensionScore] = {}
    for dim_name in DIMENSIONS:
        dim_checks = [c for c in all_checks if c.dimension == dim_name]
        points = sum(c.points for c in dim_checks)
        dim_scores[dim_name] = DimensionScore(
            name=dim_name, points=points, checks=dim_checks
        )

    score = ExperimentScore(
        experiment_id=experiment_id,
        dimensions=dim_scores,
        checks=all_checks,
    )
    score.finalize()
    return score
