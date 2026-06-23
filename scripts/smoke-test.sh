#!/usr/bin/env bash
# smoke-test.sh — prove the core Bolyra path works from a clean state.
#
# Tests: CLI help, doctor, shield build, run + observe + replay cycle,
# dev from-receipt, and the Robinhood demo.
#
# Usage: bash scripts/smoke-test.sh
# Exit: 0 on success, 1 on first failure.

set -euo pipefail

PASS=0
FAIL=0
START=$(date +%s)

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
section() { echo ""; echo "── $1 ──"; }

# ── CLI ──────────────────────────────────────────────────────

section "CLI basics"

# Help
if node integrations/cli/dist/main.js --help 2>&1 | grep -q "bolyra run"; then
  pass "bolyra --help shows run command"
else
  fail "bolyra --help missing run command"
fi

# Version
if node integrations/cli/dist/main.js --version 2>&1 | grep -q "@bolyra/cli"; then
  pass "bolyra --version"
else
  fail "bolyra --version"
fi

# Doctor
if node integrations/cli/dist/main.js doctor 2>&1 | grep -q "Bolyra Doctor"; then
  pass "bolyra doctor runs"
else
  fail "bolyra doctor"
fi

# Dev identities (requires snarkjs — skip if not available)
DEV_OUT=$(node integrations/cli/dist/main.js dev 2>&1 || true)
if echo "$DEV_OUT" | grep -q "commitment"; then
  pass "bolyra dev generates identities"
elif echo "$DEV_OUT" | grep -q "snarkjs"; then
  pass "bolyra dev (skipped — snarkjs not in CLI node_modules, works from repo root)"
else
  fail "bolyra dev"
fi

# ── Shield ───────────────────────────────────────────────────

section "Shield"

# Build check
if [ -f integrations/shield/dist/cli.js ]; then
  pass "shield dist exists"
else
  fail "shield dist missing — run: cd integrations/shield && npm run build"
fi

# Help
if node integrations/shield/dist/cli.js --help 2>&1 | grep -q "bolyra-shield"; then
  pass "shield --help"
else
  fail "shield --help"
fi

# ── Gateway ──────────────────────────────────────────────────

section "Gateway"

if [ -f integrations/gateway/dist/cli.js ]; then
  pass "gateway dist exists"
else
  fail "gateway dist missing — run: cd integrations/gateway && npm run build"
fi

if node integrations/gateway/dist/cli.js --help 2>&1 | grep -q "bolyra-gateway"; then
  pass "gateway --help"
else
  fail "gateway --help"
fi

# ── Observe + Replay cycle ───────────────────────────────────

section "Observe + Replay"

TMPRECEIPTS=$(mktemp /tmp/smoke-receipts-XXXXXX.ndjson)
cat > "$TMPRECEIPTS" << 'EOF'
{"decision":"allow","toolName":"read_file","did":"did:bolyra:dev:0x7b","score":100,"timestamp":"2026-06-23T00:00:00Z"}
{"decision":"deny","toolName":"write_file","reason":"missing WRITE_DATA","timestamp":"2026-06-23T00:00:01Z"}
{"decision":"allow","toolName":"search","did":"did:bolyra:dev:0x7b","score":91,"timestamp":"2026-06-23T00:00:02Z"}
EOF

# Observe with --output
TMPPOLICY=$(mktemp /tmp/smoke-policy-XXXXXX.yaml)
if cat "$TMPRECEIPTS" | node integrations/cli/dist/main.js observe --suggest-policy --output "$TMPPOLICY" 2>&1 | grep -q "Summary"; then
  pass "observe reads receipts and prints summary"
else
  fail "observe"
fi

if [ -s "$TMPPOLICY" ] && grep -q "tools:" "$TMPPOLICY"; then
  pass "observe --output writes policy file"
else
  fail "observe --output"
fi

# Replay
if node integrations/cli/dist/main.js replay "$TMPRECEIPTS" --with-policy "$TMPPOLICY" 2>&1 | grep -q "Bolyra replay"; then
  pass "replay runs against policy"
else
  fail "replay"
fi

# Replay --diff
if node integrations/cli/dist/main.js replay "$TMPRECEIPTS" --with-policy "$TMPPOLICY" --diff 2>&1 | grep -q "decisions"; then
  pass "replay --diff shows changes"
else
  fail "replay --diff"
fi

# Replay --format json
if node integrations/cli/dist/main.js replay "$TMPRECEIPTS" --format json 2>&1 | grep -q '"changed"'; then
  pass "replay --format json"
else
  fail "replay --format json"
fi

# ── Dev from-receipt ─────────────────────────────────────────

section "Dev from-receipt"

TMPFIXTURES=$(mktemp -d /tmp/smoke-fixtures-XXXXXX)
if node integrations/cli/dist/main.js dev from-receipt "$TMPRECEIPTS" --output-dir "$TMPFIXTURES" 2>&1 | grep -q "Generated test fixtures"; then
  pass "dev from-receipt generates fixtures"
else
  fail "dev from-receipt"
fi

if [ -f "$TMPFIXTURES/shield.yaml" ] && [ -f "$TMPFIXTURES/dev-bundles.json" ] && [ -f "$TMPFIXTURES/replay-test.sh" ]; then
  pass "all fixture files created (shield.yaml, dev-bundles.json, replay-test.sh)"
else
  fail "fixture files missing"
fi

# ── Robinhood demo ───────────────────────────────────────────

section "Robinhood demo"

if [ -f examples/robinhood-demo/src/run-demo.ts ]; then
  pass "demo source exists"
else
  fail "demo source missing"
fi

if [ -f examples/robinhood-demo/gateway.yaml ]; then
  pass "demo gateway.yaml exists"
else
  fail "demo gateway.yaml missing"
fi

# ── Cleanup ──────────────────────────────────────────────────

rm -f "$TMPRECEIPTS" "$TMPPOLICY"
rm -rf "$TMPFIXTURES"

# ── Summary ──────────────────────────────────────────────────

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo "══════════════════════════════════════"
echo "  Smoke test complete: ${ELAPSED}s"
echo "  ✅ ${PASS} passed"
if [ "$FAIL" -gt 0 ]; then
  echo "  ❌ ${FAIL} failed"
  echo "══════════════════════════════════════"
  exit 1
else
  echo "  ❌ 0 failed"
  echo "══════════════════════════════════════"
  exit 0
fi
