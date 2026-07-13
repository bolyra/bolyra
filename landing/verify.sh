#!/usr/bin/env bash
# landing/verify.sh — regression check for bolyra.ai/402
#
# Asserts the live page returns 200, that the Quickstart samples still
# reference the published npm package, and that the conformance figure
# stays grounded in the actual count of test vectors.
#
# Exit non-zero on first failure. Run after ./landing/deploy.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

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
  "49 vectors"
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
SDK_VERSION="0.4.0"
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
  "@bolyra/sdk": ["createHumanIdentity","createAgentCredential","proveHandshake","verifyHandshake","createDevIdentities"],
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

# Tamper-rejection runtime gate — the #zk-demo section of bolyra.ai claims
# "flip one byte of a proof and the pairing check fails by construction".
# Prove it: run snarkjs.groth16.verify against the pinned proof fixtures
# under landing/fixtures/, using the vkeys shipped inside the published
# @bolyra/payment-protocols tarball. Then mutate one hex digit of
# agentProof.pi_a[0] and re-verify — the result MUST flip from true to
# false. If a tamper is silently accepted, the cryptographic claim on the
# landing is broken and we fail-fast before anyone trusts the site.
echo "→ runtime tamper-rejection test (1-byte flip of agentProof.pi_a[0])"
[ -f "$FIXTURES_DIR/humanProof.json" ] || fail "missing fixture: $FIXTURES_DIR/humanProof.json"
[ -f "$FIXTURES_DIR/agentProof.json" ] || fail "missing fixture: $FIXTURES_DIR/agentProof.json"
[ -f "$FIXTURES_DIR/nonce.txt" ]      || fail "missing fixture: $FIXTURES_DIR/nonce.txt"
cp -R "$FIXTURES_DIR" "$WORKDIR/fixtures"

( cd "$WORKDIR" && node -e '
const fs = require("fs");
const path = require("path");
const sdk = require("@bolyra/sdk");

const fixturesDir = path.join(process.cwd(), "fixtures");
// @bolyra/payment-protocols ships HumanUniqueness_vkey.json and
// AgentPolicy_groth16_vkey.json under vkeys/ — the same filenames the
// SDK looks for when circuitDir is set.
const vkeyDir     = path.join(process.cwd(), "node_modules/@bolyra/payment-protocols/vkeys");

const humanProof = JSON.parse(fs.readFileSync(path.join(fixturesDir, "humanProof.json"), "utf8"));
const agentProof = JSON.parse(fs.readFileSync(path.join(fixturesDir, "agentProof.json"), "utf8"));
const nonce      = BigInt(fs.readFileSync(path.join(fixturesDir, "nonce.txt"), "utf8").trim());

(async () => {
  // Leg 1: unmodified proofs must verify.
  const good = await sdk.verifyHandshake(humanProof, agentProof, nonce, { circuitDir: vkeyDir });
  if (!good.verified) {
    console.error("FAIL: pinned fixtures failed to verify against published vkeys (drift between @bolyra/sdk and @bolyra/payment-protocols vkeys?)");
    process.exit(1);
  }
  console.log("OK:    unmodified handshake verifies");

  // Leg 2: tamper agentProof.pi_a[0]. snarkjs decimal strings stay in
  // Fp regardless of which digit we flip; mutating a LOW-order digit
  // keeps the tampered value well-formed enough that the verifier
  // runs the pairing check and returns verified=false, rather than
  // throwing on a malformed encoding. We strictly assert
  // verified===false here (NOT "threw OR false") so the gate
  // distinguishes a real pairing rejection from an exception path.
  const tampered = JSON.parse(JSON.stringify(agentProof));
  const orig = tampered.proof.pi_a[0];
  // Flip the last digit; wraps 0..9 -> (d+1)%10.
  const lastDigit = parseInt(orig.slice(-1), 10);
  tampered.proof.pi_a[0] = orig.slice(0, -1) + ((lastDigit + 1) % 10).toString();

  const bad = await sdk.verifyHandshake(humanProof, tampered, nonce, { circuitDir: vkeyDir });
  if (bad.verified !== false) {
    console.error("FAIL: tampered agentProof.pi_a[0] was SILENTLY ACCEPTED (verified=" + bad.verified + ").");
    console.error("       The landing #zk-demo claim is broken — block this deploy.");
    process.exit(1);
  }
  console.log("OK:    tampered agentProof rejected (verified=false)");
  // snarkjs/ffjavascript leave worker threads + open handles after
  // groth16.verify. Without an explicit exit, node -e can sit idle
  // and block deploy.sh on the implicit shell timeout.
  process.exit(0);
})().catch((e) => { console.error("FAIL: tamper test threw unexpectedly:", e); process.exit(1); });
' ) || fail "tamper-rejection runtime gate failed"

# Version drift guard — the page must advertise the versions npm actually
# serves. Landing copy went stale twice in two days (still selling 0.2.x
# after 0.4.0 shipped, then 0.4.0 after 0.5.0); a third drift now blocks
# the deploy instead of shipping.
LIVE_HTML=$(curl -s "https://bolyra.ai/?vguard=$(date +%s)")
guard_version() { # $1=pkg  $2=literal prefix the page must show before the version
  local pkg="$1" prefix="$2" published
  published=$(npm view "$pkg" version 2>/dev/null) || fail "npm view $pkg failed — cannot verify advertised versions"
  # Herestring, not a pipe: under `set -o pipefail`, grep -q exiting on an
  # early match SIGPIPEs the echo and the successful check reads as failure.
  if grep -qF "${prefix}${published}" <<< "$LIVE_HTML"; then
    pass "version match: page advertises ${prefix}${published} ($pkg)"
  else
    fail "version drift: npm has $pkg@$published but page lacks '${prefix}${published}' — update landing/index.html"
  fi
}
guard_version "@bolyra/gateway" "@bolyra/gateway@"
guard_version "@bolyra/gateway" "npm v"
guard_version "@bolyra/sdk"     "TS SDK at v"
guard_version "@bolyra/cli"     "@bolyra/cli@"

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
