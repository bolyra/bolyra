/** Consumer pipeline against the kit's golden corpus (verify-first, fail closed). */
import { test } from 'node:test';
import * as assert from 'node:assert';
import * as path from 'path';
import { verifyAndScore, extractFeatures } from '../src/score';

const CORPUS = path.resolve(process.cwd(), '..', 'receipt-scoring-kit', 'corpus');
const SIGNERS = path.join(CORPUS, 'bolyra-signers.json');
const GOLDEN_HEAD = '0x8150d2464e2f17dd1bfa921283ae8622d912160bfa7e24ffefd930fc06e31d92';

test('verified corpus produces the expected per-actor features', async () => {
  const features = await verifyAndScore(path.join(CORPUS, 'receipts.jsonl'), {
    signersSource: SIGNERS,
    expectCount: 8,
    expectHead: GOLDEN_HEAD,
  });
  assert.strictEqual(features.length, 1); // one credentialCommitment in chain A
  const f = features[0];
  assert.strictEqual(f.totalActions, 8);
  assert.strictEqual(f.allowed, 5);
  assert.strictEqual(f.denied, 3);
  assert.strictEqual(f.denyRate, 0.375);
  assert.strictEqual(f.maxFinancialTier, 'FINANCIAL_SMALL'); // mask 7 = bits 0-2
  assert.strictEqual(f.maxDelegationDepth, 2);
  assert.deepStrictEqual(f.commerceVolumeAllowed, { USDC: 42.5 });
  assert.strictEqual(f.commerceDenied, 1);
  assert.ok(f.denyReasons['credential_mismatch'] === 1);
  assert.ok(f.denyReasons['credential_expired'] === 1);
  assert.ok(f.denyReasons['request_mismatch'] === 1);
});

test('tampered log scores NOTHING (verification failure aborts)', async () => {
  await assert.rejects(
    verifyAndScore(path.join(CORPUS, 'tampered.jsonl'), {
      signersSource: SIGNERS,
      expectCount: 8,
      expectHead: GOLDEN_HEAD,
    }),
    /failed verification — scoring aborted/,
  );
});

test('missing count/head pins abort scoring (no optional truncation window)', async () => {
  // Deliberately bypass the types: the runtime guard must hold even for JS
  // callers who ignore the required fields.
  await assert.rejects(
    verifyAndScore(path.join(CORPUS, 'receipts.jsonl'), { signersSource: SIGNERS } as never),
    /expectCount and expectHead are required/,
  );
  await assert.rejects(
    verifyAndScore(path.join(CORPUS, 'receipts.jsonl'), {
      signersSource: SIGNERS,
      expectCount: 8,
    } as never),
    /expectCount and expectHead are required/,
  );
});

test('operator-b log is rejected under operator-a discovery doc (unknown signer)', async () => {
  const manifest = JSON.parse(
    require('fs').readFileSync(path.join(CORPUS, 'manifest.json'), 'utf8'),
  );
  const b = manifest.chains['operator-b.jsonl'];
  await assert.rejects(
    verifyAndScore(path.join(CORPUS, 'operator-b.jsonl'), {
      signersSource: SIGNERS,
      expectCount: b.count,
      expectHead: b.head,
    }),
    /not in the discovery document/,
  );
});

test('wrong pinned head aborts scoring (tail-truncation guard)', async () => {
  await assert.rejects(
    verifyAndScore(path.join(CORPUS, 'receipts.jsonl'), {
      signersSource: SIGNERS,
      expectCount: 8,
      expectHead: '0x' + 'ab'.repeat(32),
    }),
    /failed verification/,
  );
});

test('extractFeatures is pure and order-stable', () => {
  assert.deepStrictEqual(extractFeatures([]), []);
});
