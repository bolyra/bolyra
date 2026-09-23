#!/usr/bin/env node
'use strict';
// Request builder for the x402-authority-verifier-kit verifier claims.
//
// A config-fault claim needs a request the verifier ALLOWS when healthy: its
// trust check runs after root recovery, so an invalid chain denies earlier and
// never reaches the fault. The suite cannot supply such a request (the bundle is
// opaque per spec), and a blob we authored would be evidence we made up.
//
// So this derives one from the implementer's OWN pinned corpus: the allow case
// `auth-01-amount-exactly-at-per-payment`, wrapped in the kit's documented
// `stillos-evidence-bundle/1` envelope with the `x402_evc` fields taken from the
// same case's payment. Digest-pinned in claims.json like the host adapter.
//
// usage: node stillos-evc-request.cjs <implementer-checkout> <out-path>
const fs = require('fs');
const path = require('path');

const [implDir, outPath] = process.argv.slice(2);
if (!implDir || !outPath) {
  console.error('usage: stillos-evc-request.cjs <implementer-checkout> <out-path>');
  process.exit(2);
}

const CASE_ID = 'auth-01-amount-exactly-at-per-payment';
const corpusPath = path.join(implDir, 'proof', 'corpus', 'adversarial.json');
const corpus = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));
const cases = Array.isArray(corpus) ? corpus : corpus.cases || corpus.vectors;
if (!Array.isArray(cases)) throw new Error(`unrecognised corpus shape at ${corpusPath}`);

const hit = cases.find((c) => c && c.id === CASE_ID);
if (!hit) throw new Error(`corpus case ${CASE_ID} not found at the pinned commit`);
const expected = JSON.stringify(hit.expect || hit.expected || {});
if (!/allow/.test(expected)) {
  throw new Error(`corpus case ${CASE_ID} no longer expects allow (${expected}); pick another case`);
}

const op = (hit.ops || []).find((o) => o && o.op === 'authorize');
if (!op) throw new Error(`corpus case ${CASE_ID} carries no authorize op`);
const { envelope, payment, now_iso: nowIso } = op.args || {};
for (const [k, v] of Object.entries({ envelope, payment, now_iso: nowIso })) {
  if (!v) throw new Error(`corpus case ${CASE_ID} is missing ${k}`);
}

const nowUnix = Math.floor(Date.parse(nowIso) / 1000);
if (!Number.isFinite(nowUnix) || nowUnix <= 0) throw new Error(`unparseable now_iso: ${nowIso}`);

fs.writeFileSync(outPath, JSON.stringify({
  version: 1,
  bundle: JSON.stringify({
    v: 'stillos-evidence-bundle/1',
    chain: [envelope],
    paymentId: payment.paymentId,
  }),
  x402_evc: { amount: payment.amount, asset: payment.asset, payee: payment.recipient },
  now_unix: nowUnix,
}));
