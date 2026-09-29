#!/usr/bin/env bash
# Pack the package and consume the tarball from a CommonJS consumer and an
# ESM consumer: require/import the public entry, build a local challenge
# from the observed Tavily header, bind the openssl-signed ES384 fixture
# through createIssuerQuotePayeeResolver, and run one full local-mode
# verify that must ALLOW. Proves the published artifact, not the source.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG_DIR=$(pwd)
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

npm run build --silent
TARBALL=$(npm pack --silent --pack-destination "$WORK" | tail -1)
echo "packed: $TARBALL"
cp test/fixtures/x402-issuer-quote/tavily-challenge-observed.json test/fixtures/x402-issuer-quote/openssl-ES384.json "$WORK/"

# The smoke body, identical for both module systems apart from the import line.
BODY='
const observed = JSON.parse(fs.readFileSync(new URL("./tavily-challenge-observed.json", base), "utf8"));
const fixture = JSON.parse(fs.readFileSync(new URL("./openssl-ES384.json", base), "utf8"));
const ISS = "https://x402.tavily.com", RESOURCE = "https://x402.tavily.com/search";
const decoded = JSON.parse(JSON.stringify(observed.decoded));
decoded.accepts[1].extra.quoteToken = fixture.compact;
const headerValue = Buffer.from(JSON.stringify(decoded)).toString("base64");
const resolvePayee = await pp.createIssuerQuotePayeeResolver({ issuers: new Map([[ISS, {
  payTo: "urn:x402:agent-pay:see-quote", scheme: "agent-pay", network: "aws:base", audience: "aws:marketplace", payToRole: "seller",
  keys: new Map([[fixture.kid, { alg: fixture.alg, jwk: fixture.publicJwk }]]),
  products: new Map([[RESOURCE, { reference: "tavily-search-advanced", "settlement.product_id": "prod-maeet6sajeg42" }]]),
  settlementFields: [{ challenge: "extra.reference", claim: "reference" }, { challenge: "extra.settlement.product_id", claim: "settlement.product_id" }],
}]]) });
const local = pp.x402LocalChallenge({ headerValue, resource: RESOURCE, legIndex: 1, now: fixture.now, maxSeconds: 900 });
const m = await mpp.issueMandate({ operatorPrivateKey: 42n, agentName: "search-agent", audience: ISS, model: "test-model", program: "x402", maxUsd: "99", expiry: fixture.now + 3600 });
const decision = await pp.verifyX402EvcAuthorization(m.presentation, { localChallenge: local, audience: ISS, resolvePayee, verifier: { kind: "classical", trustedOperators: [m.operatorPublicKey] }, now: () => fixture.now });
if (decision.allowed !== true) { console.error("SMOKE_FAIL", JSON.stringify(decision.problem)); process.exit(1); }
if (!decision.checkedLeg || decision.request.x402_evc.payee_binding.kid !== fixture.kid) { console.error("SMOKE_FAIL shape"); process.exit(1); }
console.log("SMOKE_OK", MODE, process.version, "jti", decision.request.x402_evc.payee_binding.jti);
'

run_consumer() {
  local mode=$1 type=$2 dir="$WORK/$1"
  mkdir -p "$dir"
  printf '{ "name": "consumer-%s", "private": true, "type": "%s" }\n' "$mode" "$type" > "$dir/package.json"
  (cd "$dir" && npm install --silent --no-audit --no-fund "$WORK/$TARBALL" >/dev/null)
  cp "$WORK/tavily-challenge-observed.json" "$WORK/openssl-ES384.json" "$dir/"
  if [ "$mode" = cjs ]; then
    {
      echo 'const fs = require("node:fs"); const { pathToFileURL } = require("node:url");'
      echo 'const pp = require("@bolyra/payment-protocols"); const mpp = require("@bolyra/mpp");'
      echo 'const base = pathToFileURL(__filename); const MODE = "cjs";'
      echo '(async () => {'; echo "$BODY"; echo '})().catch((e) => { console.error("SMOKE_FAIL", e); process.exit(1); });'
    } > "$dir/smoke.cjs"
    (cd "$dir" && node smoke.cjs)
  else
    {
      echo 'import fs from "node:fs";'
      echo 'import * as pp from "@bolyra/payment-protocols"; import * as mpp from "@bolyra/mpp";'
      echo 'const base = import.meta.url; const MODE = "esm";'
      echo "$BODY"
    } > "$dir/smoke.mjs"
    (cd "$dir" && node smoke.mjs)
  fi
}

run_consumer cjs commonjs
run_consumer esm module
