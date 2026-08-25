#!/usr/bin/env node
/**
 * Deterministic generator for the receipt instance-binding conformance corpus
 * (spec/receipt-instance-binding-v1.md §4, "golden corpus / conformance").
 *
 * Every fixture is a signed SignedReceipt (or a .jsonl chain log) produced
 * from FIXED inputs — fixed test key, fixed timestamps, no entropy — so
 * regeneration is byte-stable and MANIFEST.json diffs are meaningful. Any
 * implementation, in any language, can consume these files to prove its
 * instance-binding verifier agrees with the reference:
 *
 *   - signature validity and instance-binding validity are DIFFERENT claims:
 *     `forged-ref.json` carries a VALID signature over a wrong `instance.ref`
 *     and MUST fail the semantic check while passing signature verification.
 *
 * Regenerate:  node spec/fixtures/receipt-conformance/generate.js
 * Requires the reference build:  cd integrations/receipts && npm ci
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');

const receipts = require('../../../integrations/receipts/dist/index.js');
const {
  ReceiptChain,
  computeInstanceRef,
  createAuthReceipt,
  createCommerceReceipt,
  signReceipt,
} = receipts;

const OUT_DIR = __dirname;

// --- fixed inputs: NEVER derive anything from the wall clock ---------------
const SIGNER = {
  issuer: 'conformance-fixture',
  keyId: 'k1',
  // Throwaway test key, fixed forever. NOT a secret.
  privateKey: '0x' + '42'.repeat(32),
};
const ISSUED_AT = 1756100000; // 2026-08-25T05:33:20Z, fixed
const DECISION_AT = '2026-08-25T12:00:00.123Z';

const PREIMAGE = {
  audience: 'api.merchant.example',
  program: 'mpp',
  capabilities: ['mpp:financial:small'],
  amountUsd: '25',
  decisionAt: DECISION_AT,
};

function baseInput(nonce) {
  return {
    rootDid: 'did:bolyra:root:conformance',
    actingDid: 'did:bolyra:agent:conformance',
    credentialCommitment: '12345',
    effectiveCommitment: '12345',
    allowed: true,
    score: 90,
    permissionBitmask: '5',
    chainDepth: 0,
    humanProof: { proof: { fixture: 1 } },
    agentProof: { proof: { fixture: 2 } },
    humanPublicSignals: ['1'],
    agentPublicSignals: ['2'],
    bundleVersion: 1,
    nonce,
  };
}

function commercePayload(nonce, instance) {
  const payload = createCommerceReceipt(
    {
      ...baseInput(nonce),
      commerce: {
        rail: 'mpp',
        amount: 25,
        currency: 'USD',
        merchant: 'api.merchant.example',
        intentHash: 'ab'.repeat(32),
      },
    },
    { issuer: SIGNER.issuer, keyId: SIGNER.keyId },
  );
  const fixed = { ...payload, issuedAt: ISSUED_AT };
  return instance !== undefined ? { ...fixed, instance } : fixed;
}

function authPayload(nonce, instance) {
  const payload = createAuthReceipt(baseInput(nonce), {
    issuer: SIGNER.issuer,
    keyId: SIGNER.keyId,
    issuedAt: ISSUED_AT,
  });
  return instance !== undefined ? { ...payload, instance } : payload;
}

const validInstance = { ref: computeInstanceRef(PREIMAGE), preimage: PREIMAGE };
const forgedInstance = {
  // Signer-issued wrong ref: computed over DIFFERENT facts, signed anyway.
  ref: computeInstanceRef({ ...PREIMAGE, amountUsd: '9999.99' }),
  preimage: PREIMAGE,
};

const fixtures = {
  'valid-instance.json': signReceipt(commercePayload('1001', validInstance), SIGNER),
  'no-instance.json': signReceipt(commercePayload('1002'), SIGNER),
  'forged-ref.json': signReceipt(commercePayload('1003', forgedInstance), SIGNER),
  'out-of-domain-audience.json': signReceipt(
    commercePayload('1004', {
      ref: 'birv1:' + 'ab'.repeat(32),
      preimage: { ...PREIMAGE, audience: 'Acme Corp' },
    }),
    SIGNER,
  ),
  'auth-kind-instance.json': signReceipt(authPayload('1005', validInstance), SIGNER),
  'malformed-block.json': signReceipt(
    { ...commercePayload('1006'), instance: null },
    SIGNER,
  ),
};

// Chained log: 3 receipts on one hash chain; the middle one carries the
// forged ref. Chain integrity and every signature are VALID — only the
// instance claim at index 1 is false.
{
  const chain = new ReceiptChain();
  const rows = [
    chain.sign(commercePayload('2001', validInstance), SIGNER),
    chain.sign(commercePayload('2002', forgedInstance), SIGNER),
    chain.sign(commercePayload('2003', validInstance), SIGNER),
  ];
  fixtures['chained-one-forged.jsonl'] = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
}

// --- write + manifest ------------------------------------------------------
const manifest = { version: 1, spec: 'receipt-instance-binding-v1', files: {} };
for (const name of Object.keys(fixtures).sort()) {
  const value = fixtures[name];
  const body = typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n';
  fs.writeFileSync(path.join(OUT_DIR, name), body);
  manifest.files[name] = createHash('sha256').update(body).digest('hex');
}
fs.writeFileSync(
  path.join(OUT_DIR, 'MANIFEST.json'),
  JSON.stringify(manifest, null, 2) + '\n',
);
console.log(`wrote ${Object.keys(fixtures).length} fixtures + MANIFEST.json to ${OUT_DIR}`);
