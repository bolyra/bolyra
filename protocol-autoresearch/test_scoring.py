"""Tests for scoring.py — 24-check protocol harness."""
import json
import pytest
from pathlib import Path

from scoring import (
    DIMENSIONS,
    MAX_PER_DIMENSION,
    MAX_TOTAL,
    CHECK_POINTS,
    ExperimentScore,
    DimensionScore,
    CheckResult,
    check_circuit_exists,
    check_contract_exists,
    check_spec_section_exists,
    check_test_vectors_exist,
    check_sdk_module_exists,
    check_sdk_test_exists,
    check_docs_exist,
    check_normative_language,
    check_no_shared_modified,
    score_experiment,
)


def test_dimensions_constant():
    assert set(DIMENSIONS) == {"correctness", "completeness", "adoption", "standards"}
    assert MAX_PER_DIMENSION == 25
    assert MAX_TOTAL == 100


def test_check_points_sum_to_25_per_dimension():
    """Each dimension's checks must sum to exactly 25 points."""
    for dim, checks in CHECK_POINTS.items():
        total = sum(checks.values())
        assert total == 25, f"{dim} checks sum to {total}, expected 25"


def test_total_checks_is_24():
    """There must be exactly 24 checks across all dimensions."""
    total = sum(len(checks) for checks in CHECK_POINTS.values())
    assert total == 24


def test_experiment_score_finalize_promote():
    """Score >= 75 with all dims >= 15 should promote."""
    score = ExperimentScore(experiment_id="test")
    score.dimensions = {
        d: DimensionScore(name=d, points=20)
        for d in DIMENSIONS
    }
    score.checks = []
    score.finalize()
    assert score.total == 80
    assert score.verdict == "promote"


def test_experiment_score_finalize_consider():
    """Score 60-74 should be consider."""
    score = ExperimentScore(experiment_id="test")
    score.dimensions = {
        d: DimensionScore(name=d, points=16)
        for d in DIMENSIONS
    }
    score.checks = []
    score.finalize()
    assert score.total == 64
    assert score.verdict == "consider"


def test_experiment_score_finalize_drop_low_total():
    """Score < 60 should be drop."""
    score = ExperimentScore(experiment_id="test")
    score.dimensions = {
        d: DimensionScore(name=d, points=10)
        for d in DIMENSIONS
    }
    score.checks = []
    score.finalize()
    assert score.total == 40
    assert score.verdict == "drop"


def test_experiment_score_finalize_drop_any_dim_low():
    """Any dimension <= 8 forces drop regardless of total."""
    score = ExperimentScore(experiment_id="test")
    dims = {d: DimensionScore(name=d, points=20) for d in DIMENSIONS}
    dims["adoption"] = DimensionScore(name="adoption", points=8)
    score.dimensions = dims
    score.checks = []
    score.finalize()
    assert score.total == 68
    assert score.verdict == "drop"  # adoption is 8, which is <= 8


def test_experiment_score_hard_fail():
    """Hard fail check zeroes total and forces drop."""
    score = ExperimentScore(experiment_id="test")
    score.dimensions = {d: DimensionScore(name=d, points=20) for d in DIMENSIONS}
    score.checks = [
        CheckResult(name="check_no_shared_modified", dimension="correctness",
                    points=0, max_points=2, note="bad", hard_fail=True)
    ]
    score.finalize()
    assert score.total == 0
    assert score.verdict == "drop"
    assert score.hard_fail_triggered


# --- File-existence checks ---

def test_check_circuit_exists_found(tmp_path):
    (tmp_path / "handshake.circom").write_text("template Handshake() {}")
    result = check_circuit_exists(tmp_path)
    assert result.points == 3
    assert "handshake.circom" in result.note


def test_check_circuit_exists_not_found(tmp_path):
    result = check_circuit_exists(tmp_path)
    assert result.points == 0


def test_check_contract_exists_found(tmp_path):
    (tmp_path / "Verifier.sol").write_text("contract Verifier {}")
    result = check_contract_exists(tmp_path)
    assert result.points == 3


def test_check_contract_exists_not_found(tmp_path):
    result = check_contract_exists(tmp_path)
    assert result.points == 0


def test_check_spec_section_with_normative(tmp_path):
    (tmp_path / "spec.md").write_text("Implementations MUST verify the proof. SHOULD log. MAY cache.")
    result = check_spec_section_exists(tmp_path)
    assert result.points == 4


def test_check_spec_section_without_normative(tmp_path):
    (tmp_path / "notes.md").write_text("Some notes about the design.")
    result = check_spec_section_exists(tmp_path)
    assert result.points == 2  # found md but no normative language


def test_check_test_vectors_json(tmp_path):
    (tmp_path / "test_vectors.json").write_text('[{"input": 1, "expected": 2}]')
    result = check_test_vectors_exist(tmp_path)
    assert result.points == 4


def test_check_sdk_module_exists_with_sdk(tmp_path):
    sdk_dir = tmp_path / "sdk"
    sdk_dir.mkdir()
    (sdk_dir / "index.ts").write_text("export function createIdentity() {}")
    result = check_sdk_module_exists(tmp_path)
    assert result.points == 4


def test_check_sdk_test_exists(tmp_path):
    (tmp_path / "test_sdk.py").write_text("def test_create(): pass")
    result = check_sdk_test_exists(tmp_path)
    assert result.points == 3


def test_check_docs_exist(tmp_path):
    (tmp_path / "README.md").write_text("# Usage")
    result = check_docs_exist(tmp_path)
    assert result.points == 3


def test_check_normative_language_full(tmp_path):
    (tmp_path / "spec.md").write_text(
        "Verifiers MUST check proofs. SHOULD cache. MAY skip for known roots. "
        "Clients MUST NOT reuse nullifiers."
    )
    result = check_normative_language(tmp_path)
    assert result.points == 5


def test_check_no_shared_modified_ok(tmp_path):
    exp_dir = tmp_path / "experiments" / "test_001"
    exp_dir.mkdir(parents=True)
    result = check_no_shared_modified(exp_dir)
    assert result.points == 2
    assert not result.hard_fail


def test_check_no_shared_modified_fail(tmp_path):
    result = check_no_shared_modified(tmp_path)
    assert result.points == 0
    assert result.hard_fail


def test_score_experiment_with_artifacts(tmp_path):
    """Score a well-populated experiment directory (skip LLM and build checks)."""
    exp_dir = tmp_path / "experiments" / "test_exp"
    exp_dir.mkdir(parents=True)
    (exp_dir / "handshake.circom").write_text("template T() {}")
    (exp_dir / "Verifier.sol").write_text("contract V {}")
    (exp_dir / "spec.md").write_text("Clients MUST verify. SHOULD log. MAY cache.")
    (exp_dir / "test_vectors.json").write_text('[{"a": 1}]')
    sdk_dir = exp_dir / "sdk"
    sdk_dir.mkdir()
    (sdk_dir / "index.ts").write_text("export interface Identity { id: string }")
    (sdk_dir / "index.test.ts").write_text("test('create', () => {})")
    (exp_dir / "README.md").write_text("# Usage docs")

    result = score_experiment(exp_dir, skip_llm=True, skip_build=True)
    assert result.experiment_id == "test_exp"
    assert result.total > 0
    # File-existence checks should contribute points
    assert result.dimensions["completeness"].points > 0
    assert result.dimensions["adoption"].points > 0
    assert result.dimensions["standards"].points > 0
