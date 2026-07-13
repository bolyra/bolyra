/** Corpus invariants — run after `npm run generate` (the test script does both). */
import { test } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import { verifyReceipt, verifyReceiptChain, computeReceiptHash, type SignedReceipt } from '@bolyra/receipts';

const CORPUS = path.resolve(process.cwd(), 'corpus');

function readJsonl(name: string): SignedReceipt[] {
  return fs
    .readFileSync(path.join(CORPUS, name), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'));

// GOLDEN VALUES — hard-pinned so accidental corpus drift fails the suite even
// though `npm test` regenerates before running (the regenerated output must
// still equal these committed constants, which the README also embeds).
const GOLDEN = {
  a: {
    signer: '0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025',
    count: 8,
    head: '0x8150d2464e2f17dd1bfa921283ae8622d912160bfa7e24ffefd930fc06e31d92',
  },
  b: {
    signer: '0xae72a48c1a36bd18af168541c53037965d26e4a8',
    count: 3,
    head: '0x4f1e6808ba5d49ce6e502ec5aa39cc177a4d3a44747e3366b4c9aba1d68d01d0',
  },
};

test('regenerated corpus matches the committed golden values (no silent drift)', () => {
  assert.deepStrictEqual(manifest.chains['receipts.jsonl'], { ...GOLDEN.a });
  assert.deepStrictEqual(manifest.chains['operator-b.jsonl'], { ...GOLDEN.b });
});

test('chain A verifies end to end with pinned signer, count, and head', () => {
  const receipts = readJsonl('receipts.jsonl');
  const expected = manifest.chains['receipts.jsonl'];
  const result = verifyReceiptChain(receipts, {
    expectedSigner: expected.signer,
    expectedCount: expected.count,
    expectedHeadHash: expected.head,
  });
  assert.deepStrictEqual(result.issues, []);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.chained, expected.count);
  assert.strictEqual(computeReceiptHash(receipts[receipts.length - 1]), expected.head);
});

test('chain B verifies independently under its own signer', () => {
  const receipts = readJsonl('operator-b.jsonl');
  const expected = manifest.chains['operator-b.jsonl'];
  const result = verifyReceiptChain(receipts, {
    expectedSigner: expected.signer,
    expectedCount: expected.count,
    expectedHeadHash: expected.head,
  });
  assert.strictEqual(result.ok, true);
});

test('chains A and B use different signers (multi-operator corpus)', () => {
  assert.notStrictEqual(
    manifest.chains['receipts.jsonl'].signer,
    manifest.chains['operator-b.jsonl'].signer,
  );
});

test('tampered chain FAILS with a signature issue at the edited receipt', () => {
  const receipts = readJsonl('tampered.jsonl');
  const result = verifyReceiptChain(receipts, {
    expectedSigner: manifest.chains['receipts.jsonl'].signer,
  });
  assert.strictEqual(result.ok, false);
  assert.ok(result.issues.some((i) => String(i.code).includes('signature')),
    `expected a signature issue, got: ${JSON.stringify(result.issues)}`);
});

test('single receipts verify standalone against the pinned signer', () => {
  const allow = JSON.parse(fs.readFileSync(path.join(CORPUS, 'allow.json'), 'utf8'));
  const deny = JSON.parse(fs.readFileSync(path.join(CORPUS, 'deny.json'), 'utf8'));
  const signer = manifest.chains['receipts.jsonl'].signer;
  assert.strictEqual(verifyReceipt(allow, signer), true);
  assert.strictEqual(verifyReceipt(deny, signer), true);
  assert.strictEqual(allow.payload.decision.allowed, true);
  assert.strictEqual(deny.payload.decision.allowed, false);
  assert.ok(deny.payload.decision.reasonCode);
});

test('corpus mixes decisions, kinds, and delegation depths (scoring variety)', () => {
  const receipts = readJsonl('receipts.jsonl');
  assert.ok(receipts.some((r) => r.payload.decision.allowed === true));
  assert.ok(receipts.some((r) => r.payload.decision.allowed === false));
  assert.ok(receipts.some((r) => r.payload.kind === 'bolyra.commerce'));
  assert.ok(receipts.some((r) => r.payload.decision.chainDepth > 0));
});

test('emitted corpus content hashes to the golden head (manifest is not self-referential)', () => {
  const receipts = readJsonl('receipts.jsonl');
  assert.strictEqual(computeReceiptHash(receipts[receipts.length - 1]), GOLDEN.a.head);
  const receiptsB = readJsonl('operator-b.jsonl');
  assert.strictEqual(computeReceiptHash(receiptsB[receiptsB.length - 1]), GOLDEN.b.head);
});
