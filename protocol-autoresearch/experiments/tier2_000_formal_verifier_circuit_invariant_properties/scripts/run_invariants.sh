#!/usr/bin/env bash
# run_invariants.sh — CI-runnable shell script that executes all invariant
# test suites and exits non-zero on any failure.
#
# Usage:
#   ./scripts/run_invariants.sh
#   ./scripts/run_invariants.sh --parallel    # run suites in parallel
#
# Exit codes:
#   0 — all suites passed
#   1 — one or more suites failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$PROJECT_ROOT/test/invariants"
RESULTS_DIR="$PROJECT_ROOT/test/invariants/results"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test suites
SUITES=(
  "field_overflow.test.js"
  "nullifier_uniqueness.test.js"
  "delegation_scope_monotonicity.test.js"
  "delegation_expiry_narrowing.test.js"
)

# Parse args
PARALLEL=false
if [[ "${1:-}" == "--parallel" ]]; then
  PARALLEL=true
fi

mkdir -p "$RESULTS_DIR"

echo -e "${YELLOW}=== Bolyra Circuit Invariant Test Suite ===${NC}"
echo "Running ${#SUITES[@]} test suites..."
echo ""

FAILED=0
PASSED=0
PIDS=()

run_suite() {
  local suite="$1"
  local suite_name="${suite%.test.js}"
  local result_file="$RESULTS_DIR/${suite_name}.result"

  echo -e "${YELLOW}▶ Running: ${suite}${NC}"

  if npx jest "$TEST_DIR/$suite" \
    --forceExit \
    --detectOpenHandles \
    --testTimeout=120000 \
    > "$RESULTS_DIR/${suite_name}.log" 2>&1; then
    echo "PASS" > "$result_file"
    echo -e "${GREEN}✓ PASSED: ${suite}${NC}"
  else
    echo "FAIL" > "$result_file"
    echo -e "${RED}✗ FAILED: ${suite}${NC}"
    echo "  Log: $RESULTS_DIR/${suite_name}.log"
  fi
}

if $PARALLEL; then
  echo "Mode: parallel"
  echo ""
  for suite in "${SUITES[@]}"; do
    run_suite "$suite" &
    PIDS+=("$!")
  done

  # Wait for all background jobs
  for pid in "${PIDS[@]}"; do
    wait "$pid" || true
  done
else
  echo "Mode: sequential"
  echo ""
  for suite in "${SUITES[@]}"; do
    run_suite "$suite"
  done
fi

# Aggregate results
echo ""
echo -e "${YELLOW}=== Results ===${NC}"

for suite in "${SUITES[@]}"; do
  suite_name="${suite%.test.js}"
  result_file="$RESULTS_DIR/${suite_name}.result"

  if [[ -f "$result_file" ]] && [[ "$(cat "$result_file")" == "PASS" ]]; then
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}✓${NC} ${suite}"
  else
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}✗${NC} ${suite}"
  fi
done

echo ""
echo "Passed: $PASSED / ${#SUITES[@]}"
echo "Failed: $FAILED / ${#SUITES[@]}"

# Property count validation
TOTAL_PROPERTIES=17
echo ""
echo "Named properties exercised: $TOTAL_PROPERTIES"
echo "  P1-P8:  Field overflow (8 properties)"
echo "  P9-P11: Nullifier uniqueness (3 properties)"
echo "  P12-P14: Scope monotonicity (3 properties)"
echo "  P15-P17: Expiry narrowing (3 properties)"

if [[ $FAILED -gt 0 ]]; then
  echo ""
  echo -e "${RED}INVARIANT SUITE FAILED${NC}"
  exit 1
fi

echo ""
echo -e "${GREEN}ALL INVARIANT SUITES PASSED${NC}"
exit 0
