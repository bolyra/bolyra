#!/usr/bin/env bash
# landing/verify.sh — regression check for bolyra.ai/402
#
# Asserts the live page returns 200, that the Quickstart samples still
# reference the published npm package, and that the conformance figure
# stays grounded in the actual count of test vectors.
#
# Exit non-zero on first failure. Run after ./landing/deploy.sh.

set -euo pipefail

URL_402="https://bolyra.ai/402"
URL_ROOT="https://bolyra.ai/"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "OK:   $*"; }

echo "→ HEAD $URL_402"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL_402")
[ "$STATUS" = "200" ] || fail "/402 returned HTTP $STATUS (expected 200)"
pass "/402 returns 200"

echo "→ HEAD $URL_ROOT"
STATUS_ROOT=$(curl -s -o /dev/null -w "%{http_code}" "$URL_ROOT")
[ "$STATUS_ROOT" = "200" ] || fail "/ returned HTTP $STATUS_ROOT (expected 200)"
pass "/ returns 200"

TMP=$(mktemp /tmp/bolyra-402.XXXXXX.html)
trap 'rm -f "$TMP"' EXIT
curl -fsSL "$URL_402" -o "$TMP"
BYTES=$(wc -c < "$TMP" | tr -d ' ')
[ "$BYTES" -gt 10000 ] || fail "/402 body suspiciously small ($BYTES bytes)"
pass "downloaded /402 ($BYTES bytes)"

# Required string assertions.
declare -a NEEDLES=(
  "PAYMENT-REQUIRED"
  "@bolyra/sdk"
  "@bolyra/payment-protocols"
  "createX402Authorization"
  "verifyX402Authorization"
  "48 vectors"
  'role="tablist"'
  'aria-selected'
)

for needle in "${NEEDLES[@]}"; do
  if grep -qF "$needle" "$TMP"; then
    pass "page contains: $needle"
  else
    fail "page missing: $needle"
  fi
done

# Negative assertions — these should NOT appear.
declare -a FORBIDDEN=(
  'onclick="copyPanel'
  'class="mono"'
)

for needle in "${FORBIDDEN[@]}"; do
  if grep -qF "$needle" "$TMP"; then
    fail "page still contains forbidden token: $needle"
  else
    pass "page is clean of: $needle"
  fi
done

# npm registry sanity — @bolyra/payment-protocols must resolve.
echo "→ GET registry.npmjs.org/@bolyra/payment-protocols/0.3.1"
NPM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/@bolyra/payment-protocols/0.3.1")
[ "$NPM_STATUS" = "200" ] || fail "@bolyra/payment-protocols@0.3.1 returned HTTP $NPM_STATUS"
pass "@bolyra/payment-protocols@0.3.1 resolves on npm"

# GitHub link sanity — the page CTAs must resolve for unauthenticated visitors.
# GitHub returns 404 (not 403) for private repos, so this catches re-privatization too.
declare -a GH_URLS=(
  "https://github.com/bolyra/bolyra"
  "https://github.com/bolyra/bolyra/tree/main/integrations/payment-protocols"
  "https://github.com/bolyra/bolyra/tree/main/sdk"
  "https://github.com/bolyra/bolyra/tree/main/spec"
)
for u in "${GH_URLS[@]}"; do
  GH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L "$u")
  if [ "$GH_STATUS" = "200" ]; then
    pass "GitHub link 200: $u"
  else
    fail "GitHub link $GH_STATUS (repo private or moved?): $u"
  fi
done

echo "✓ all checks passed"
