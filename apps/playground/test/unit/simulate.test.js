import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyReceipt, verifyReceiptChain, hashPayload, computeReceiptHash } from '@bolyra/receipts';
import { newSession, decide, resetSession, exportJsonl, signerDoc, chainInfo } from '../../src/core/simulate.js';

const KEY = '0x' + '11'.repeat(32);
const fixed = () => newSession({ privateKey: KEY, now: () => 1_760_000_000, nonce: () => '0x' + 'ab'.repeat(16) });

test('tier boundaries follow shipped decimal semantics and never consume a budget', async () => {
  const s = fixed();
  const table = [
    ['small', '25', 'allow'], ['small', '99.99', 'allow'], ['small', '100', 'deny'], ['small', '500', 'deny'],
    ['medium', '9999.99', 'allow'], ['medium', '10000', 'deny'], ['unlimited', '10000', 'allow'],
    ['small', '99', 'allow'], ['small', '99', 'allow'], ['small', '99', 'allow'], ['small', '99', 'allow'], ['small', '99', 'allow'],
  ];
  for (const [tier, amount, want] of table) {
    const r = await decide(s, { tier, amount });
    assert.equal(r.outcome, want, `${tier} ${amount}`);
    assert.ok(r.receipt, 'allow/deny sign a receipt');
    assert.equal(r.receipt.payload.kind, 'bolyra.auth');
    assert.equal(r.receipt.payload.decision.allowed, want === 'allow');
    if (want === 'deny') assert.equal(r.receipt.payload.decision.reasonCode, 'request_mismatch');
    else assert.equal(r.receipt.payload.decision.reasonCode, undefined);
    assert.equal(r.requiredTier !== undefined, true);
  }
  assert.equal(chainInfo(s).seq, table.length);
});

test('invalid amount or unknown tier signs nothing and leaves seq unchanged', async () => {
  const s = fixed();
  await decide(s, { tier: 'small', amount: '5' });
  for (const bad of [['small', '-1'], ['small', ''], ['small', '1e3'], ['small', '1.'], ['small', 'abc'], ['gold', '5'], [undefined, '5']]) {
    const r = await decide(s, { tier: bad[0], amount: bad[1] });
    assert.equal(r.outcome, 'invalid', JSON.stringify(bad));
    assert.equal(r.receipt, undefined);
    assert.ok(typeof r.reason === 'string' && r.reason.length > 0);
  }
  assert.equal(chainInfo(s).seq, 1);
});

test('every signed receipt verifies against the session signer and its derived fields recompute', async () => {
  const s = fixed();
  await decide(s, { tier: 'small', amount: '25' });
  await decide(s, { tier: 'small', amount: '500' });
  const doc = signerDoc(s);
  assert.match(doc.signer, /^0x[0-9a-f]{40}$/);
  assert.equal(doc.ephemeral, true); assert.equal(doc.alg, 'ES256K'); assert.equal(doc.issuer, 'bolyra-playground'); assert.equal(doc.keyId, 'playground-k1');
  for (const receipt of s.receipts) {
    assert.equal(verifyReceipt(receipt, doc.signer), true);
    assert.equal(receipt.signature.signer, doc.signer);
    assert.equal(hashPayload(receipt.payload), receipt.signature.payloadHash);
    assert.equal(computeReceiptHash(receipt), receipt.receiptHash);
    assert.equal(receipt.payload.issuedAt, 1_760_000_000);
    assert.equal(receipt.payload.decision.permissionBitmask, '4');
  }
  assert.equal(s.receipts[0].payload.chain.seq, 0); assert.equal(s.receipts[1].payload.chain.seq, 1);
});

test('export is JSONL that verifies as a chain with the session head and count', async () => {
  const s = fixed();
  for (const amount of ['1', '2', '3']) await decide(s, { tier: 'small', amount });
  const text = exportJsonl(s);
  const lines = text.split('\n').filter(Boolean);
  assert.equal(lines.length, 3); assert.ok(text.endsWith('\n'));
  const receipts = lines.map((l) => JSON.parse(l));
  const info = chainInfo(s);
  const res = verifyReceiptChain(receipts, { expectedSigner: signerDoc(s).signer, expectedCount: info.seq, expectedHeadHash: info.headHash });
  assert.equal(res.ok, true, JSON.stringify(res.issues));
  assert.equal(exportJsonl(newSession({ privateKey: KEY })), '');
});

test('reset starts chain 2 with a fresh key and seq 0; the signer changes', async () => {
  const s = fixed();
  await decide(s, { tier: 'small', amount: '25' });
  const before = signerDoc(s).signer;
  const s2 = resetSession(s);
  assert.equal(s2.chainId, 2); assert.equal(chainInfo(s2).seq, 0); assert.equal(s2.receipts.length, 0);
  assert.notEqual(signerDoc(s2).signer, before);
  await decide(s2, { tier: 'small', amount: '25' });
  assert.equal(s2.receipts[0].payload.chain.seq, 0);
  assert.equal(verifyReceipt(s2.receipts[0], signerDoc(s2).signer), true);
});

test('production defaults: random key, wall clock, random nonce', async () => {
  const a = newSession(); const b = newSession();
  assert.notEqual(signerDoc(a).signer, signerDoc(b).signer);
  const r = await decide(a, { tier: 'medium', amount: '150' });
  assert.equal(r.outcome, 'allow');
  assert.ok(Math.abs(r.receipt.payload.issuedAt - Math.floor(Date.now() / 1000)) < 5);
  assert.match(r.receipt.payload.proof.nonce, /^0x[0-9a-f]{32}$/);
});

test('overlapping decide calls serialize into a consistent chain; reset during a run is refused', async () => {
  const s = fixed();
  const p = Promise.all(['1', '2', '3', '4'].map((amount) => decide(s, { tier: 'small', amount })));
  assert.throws(() => resetSession(s), /in flight|running/);
  const results = await p;
  assert.deepEqual(results.map((r) => r.receipt.payload.chain.seq), [0, 1, 2, 3]);
  const res = verifyReceiptChain(s.receipts, { expectedCount: 4 });
  assert.equal(res.ok, true);
  const s2 = resetSession(s);
  assert.equal(s2.chainId, 2);
});
