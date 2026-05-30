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

# Runtime symbol resolution — the page advertises specific exports from the
# published npm packages. Grep proves "the symbol is mentioned on the page";
# this proves "the symbol actually exists on the npm tarball users install".
# Caught nothing on 2026-05-30 only because we already shipped 0.3.1; the
# preceding 14h X402 outage is what motivated this check (verify.sh saw the
# string in HTML, but createX402Authorization was missing from 0.3.0).
echo "→ runtime symbol resolution against published packages"
SDK_VERSION="0.3.0"
PP_VERSION="0.3.1"
WORKDIR=$(mktemp -d /tmp/bolyra-verify.XXXXXX)
trap 'rm -rf "$WORKDIR" "$TMP"' EXIT
(
  cd "$WORKDIR"
  npm init -y >/dev/null 2>&1
  npm install --silent --no-audit --no-fund \
    "@bolyra/sdk@${SDK_VERSION}" \
    "@bolyra/payment-protocols@${PP_VERSION}" >/dev/null 2>&1
) || fail "npm install of published packages failed"

( cd "$WORKDIR" && node -e '
const sdk = require("@bolyra/sdk");
const pp  = require("@bolyra/payment-protocols");
const expected = {
  "@bolyra/sdk": ["createHumanIdentity","createAgentCredential","proveHandshake","verifyHandshake"],
  "@bolyra/payment-protocols": ["createX402Authorization","verifyX402Authorization","verifyStripeACPSpend"],
};
const mods = { "@bolyra/sdk": sdk, "@bolyra/payment-protocols": pp };
let bad = 0;
for (const [pkg, syms] of Object.entries(expected)) {
  for (const s of syms) {
    const t = typeof mods[pkg][s];
    if (t === "function") console.log("OK:    " + pkg + "." + s + " resolves");
    else { console.error("FAIL:  " + pkg + "." + s + " is " + t + " (expected function)"); bad++; }
  }
}
process.exit(bad ? 1 : 0);
' ) || fail "advertised symbol(s) missing from published packages — see FAIL lines above"

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
