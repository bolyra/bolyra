import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { verifyAll, parseInput, validateEnvelope, validateOptions, LIMITS } from '../../src/core/verify.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const corpus = (f) => readFileSync(path.join(ROOT, 'examples/receipt-scoring-kit/corpus', f), 'utf8');
const conf = (f) => readFileSync(path.join(ROOT, 'spec/fixtures/receipt-conformance', f), 'utf8');

const CHAIN = corpus('operator-b.jsonl');
const CHAIN_SIGNER = '0xae72a48c1a36bd18af168541c53037965d26e4a8';
const CHAIN_HEAD = '0x4f1e6808ba5d49ce6e502ec5aa39cc177a4d3a44747e3366b4c9aba1d68d01d0';
const TAMPERED = corpus('tampered.jsonl');
const CONF_SIGNER = '0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025';
const lines = (t) => t.trim().split('\n');

test('sample chain with signer, count and head → overall ok, checkpoint matched', () => {
  const r = verifyAll(CHAIN, { expectedSigner: CHAIN_SIGNER, expectedCount: 3, expectedHeadHash: CHAIN_HEAD });
  assert.equal(r.overall, 'ok'); assert.equal(r.kind, 'chain');
  assert.equal(r.rows.length, 3);
  for (const row of r.rows) { assert.equal(row.envelope.ok, true); assert.equal(row.signature, 'valid'); assert.equal(row.signerMatch, 'matched'); assert.equal(row.instance.code, 'absent'); }
  assert.equal(r.chain.issues.length, 0); assert.equal(r.chain.headHash, CHAIN_HEAD); assert.equal(r.chain.count, 3);
  assert.equal(r.checkpoint.state, 'matched');
});

test('no checkpoint → overall ok but checkpoint missing; no expected signer → not-checked', () => {
  const r = verifyAll(CHAIN, {});
  assert.equal(r.overall, 'ok'); assert.equal(r.checkpoint.state, 'missing');
  for (const row of r.rows) assert.equal(row.signerMatch, 'not-checked');
});

test('partial checkpoint is still compared: count only matched; head only mismatching fails', () => {
  assert.equal(verifyAll(CHAIN, { expectedCount: 3 }).checkpoint.state, 'partial');
  assert.equal(verifyAll(CHAIN, { expectedCount: 3 }).checkpoint.count, 'matched');
  const bad = verifyAll(CHAIN, { expectedCount: 4 });
  assert.equal(bad.overall, 'failed'); assert.equal(bad.checkpoint.state, 'mismatch');
  const badHead = verifyAll(CHAIN, { expectedHeadHash: '0x' + 'ab'.repeat(32) });
  assert.equal(badHead.overall, 'failed'); assert.equal(badHead.checkpoint.state, 'mismatch');
});

test('middle receipt removed, reordered, and tail removed all fail', () => {
  const [a, b, c] = lines(CHAIN);
  const middleGone = verifyAll([a, c].join('\n'), { expectedSigner: CHAIN_SIGNER });
  assert.equal(middleGone.overall, 'failed'); assert.ok(middleGone.chain.issues.some((i) => ['seq-mismatch', 'prev-hash-mismatch'].includes(i.code)));
  const reordered = verifyAll([a, c, b].join('\n'), {});
  assert.equal(reordered.overall, 'failed');
  const tailGone = verifyAll([a, b].join('\n'), { expectedCount: 3, expectedHeadHash: CHAIN_HEAD });
  assert.equal(tailGone.overall, 'failed'); assert.equal(tailGone.checkpoint.state, 'mismatch');
  assert.ok(tailGone.chain.issues.some((i) => i.code === 'count-mismatch' || i.code === 'head-hash-mismatch'));
  // without a checkpoint, tail removal is invisible: ok but completeness not established
  const tailGoneNoCp = verifyAll([a, b].join('\n'), {});
  assert.equal(tailGoneNoCp.overall, 'ok'); assert.equal(tailGoneNoCp.checkpoint.state, 'missing');
});

test('a 1-byte flip in a signed field fails that signature and the whole log', () => {
  const [a, b, c] = lines(CHAIN);
  const obj = JSON.parse(b); obj.payload.decision.score = obj.payload.decision.score === 100 ? 99 : 100;
  const r = verifyAll([a, JSON.stringify(obj), c].join('\n'), { expectedSigner: CHAIN_SIGNER });
  assert.equal(r.overall, 'failed'); assert.equal(r.rows[1].signature, 'invalid'); assert.equal(r.rows[1].signerMatch, 'not-checked');
  assert.equal(r.rows[0].signature, 'valid');
});

test('wrong expected signer → mismatch on every row and overall failed; matched requires a valid signature', () => {
  const r = verifyAll(CHAIN, { expectedSigner: '0x' + '11'.repeat(20) });
  assert.equal(r.overall, 'failed'); for (const row of r.rows) assert.equal(row.signerMatch, 'mismatch');
  const [a] = lines(CHAIN); const obj = JSON.parse(a); obj.signature.value = obj.signature.value.slice(0, -2) + (obj.signature.value.endsWith('1b') ? '1c' : '1b');
  const r2 = verifyAll(JSON.stringify(obj), { expectedSigner: CHAIN_SIGNER });
  assert.equal(r2.rows[0].signature, 'invalid'); assert.notEqual(r2.rows[0].signerMatch, 'matched');
});

test('tampered corpus log reports the three known issues', () => {
  const r = verifyAll(TAMPERED, { expectedSigner: CHAIN_SIGNER === '' ? '' : undefined });
  assert.equal(r.overall, 'failed');
  const codes = r.chain.issues.map((i) => `${i.index}:${i.code}`);
  for (const want of ['2:signature-invalid', '2:receipt-hash-mismatch', '3:prev-hash-mismatch']) assert.ok(codes.includes(want), want + ' in ' + codes.join(','));
});

test('instance binding: forged ref, absent, wrong kind, malformed', () => {
  const forged = verifyAll(conf('forged-ref.json'), { expectedSigner: CONF_SIGNER });
  assert.equal(forged.rows[0].signature, 'valid'); assert.equal(forged.rows[0].signerMatch, 'matched');
  assert.equal(forged.rows[0].instance.code, 'ref_mismatch'); assert.equal(forged.overall, 'failed');
  assert.equal(verifyAll(conf('no-instance.json'), {}).rows[0].instance.code, 'absent');
  assert.equal(verifyAll(conf('valid-instance.json'), {}).rows[0].instance.code, 'ok');
  assert.equal(verifyAll(conf('valid-instance.json'), {}).overall, 'ok');
  assert.equal(verifyAll(conf('auth-kind-instance.json'), {}).rows[0].instance.code, 'wrong_kind');
  const malformed = verifyAll(conf('malformed-block.json'), {});
  assert.notEqual(malformed.overall, 'ok');
});

test('forged instance inside a chain that matches its checkpoint → failed with "values match, but verification failed"', () => {
  const text = conf('chained-one-forged.jsonl');
  const probe = verifyAll(text, {});
  const r = verifyAll(text, { expectedCount: probe.chain.count, expectedHeadHash: probe.chain.headHash });
  assert.equal(r.overall, 'failed'); assert.equal(r.checkpoint.state, 'matched-but-failed');
});

test('single receipts: unchained → checkpoint not-applicable; supplied checkpoint with unchained → options error; chained single → chain checks run', () => {
  const single = verifyAll(conf('valid-instance.json'), {});
  assert.equal(single.kind, 'receipt'); assert.equal(single.checkpoint.state, 'not-applicable');
  const withCp = verifyAll(conf('valid-instance.json'), { expectedCount: 1 });
  assert.equal(withCp.overall, 'invalid'); assert.ok(withCp.problems.some((p) => /unchained/.test(p)));
  const [a] = lines(CHAIN);
  const chainedSingle = verifyAll(a, { expectedSigner: CHAIN_SIGNER });
  assert.equal(chainedSingle.kind, 'receipt'); assert.equal(chainedSingle.chain.count, 1); assert.equal(chainedSingle.overall, 'ok');
  assert.equal(chainedSingle.checkpoint.state, 'missing');
});

test('invalid inputs are never verified: empty, whitespace, non-JSON, array, one bad line, checkpoint-looking line, empty chain', () => {
  for (const bad of ['', '   \n  ', 'not json', '[1,2]', '42', '"x"', 'null']) {
    const r = verifyAll(bad, {}); assert.equal(r.overall, 'invalid', JSON.stringify(bad)); assert.equal(r.rows.length, 0);
  }
  const [a, b] = lines(CHAIN);
  const oneBad = verifyAll([a, 'oops', b].join('\n'), {});
  assert.equal(oneBad.overall, 'invalid'); assert.equal(oneBad.rows.length, 0);
  const cpLine = verifyAll([a, JSON.stringify({ expectedHeadHash: CHAIN_HEAD })].join('\n'), {});
  assert.notEqual(cpLine.overall, 'ok'); assert.equal(cpLine.checkpoint.state, 'missing');
});

test('envelope negatives block signature checks', () => {
  const [a] = lines(CHAIN); const base = JSON.parse(a);
  const cases = [
    (o) => { o.payload.v = 2; }, (o) => { o.signature.alg = 'RS256'; }, (o) => { o.signature.signer = '0x1234'; },
    (o) => { delete o.payload.proof; }, (o) => { o.payload.chain.seq = -1; }, (o) => { o.receiptHash = '0xabc'; },
    (o) => { o.payload.issuedAt = 'now'; }, (o) => { o.payload.proof.bundleVersion = 3; }, (o) => { o.payload.kind = 'bolyra.other'; },
    (o) => { delete o.signature; }, (o) => { o.signature.value = '0x' + 'zz'.repeat(65); },
  ];
  for (const mutate of cases) {
    const o = JSON.parse(JSON.stringify(base)); mutate(o);
    const r = verifyAll(JSON.stringify(o), {});
    assert.notEqual(r.overall, 'ok'); assert.equal(r.rows[0]?.envelope.ok ?? false, false); assert.equal(r.rows[0]?.signature ?? 'not-run', 'not-run');
  }
  assert.equal(validateEnvelope(base).ok, true);
});

test('option negatives block verification with errors, blanks are absent', () => {
  for (const opts of [{ expectedSigner: 'ae72' }, { expectedCount: 0 }, { expectedCount: 1.5 }, { expectedHeadHash: '0x12' }, { allowUnchained: 'yes' }]) {
    const v = validateOptions(opts); assert.equal(v.ok, false, JSON.stringify(opts));
    const r = verifyAll(CHAIN, opts); assert.equal(r.overall, 'invalid');
  }
  const blank = validateOptions({ expectedSigner: '', expectedCount: '', expectedHeadHash: '   ' });
  assert.equal(blank.ok, true); assert.deepEqual(Object.keys(blank.options), []);
  const sigCase = validateOptions({ expectedSigner: CHAIN_SIGNER.toUpperCase().replace('0X', '0x') }); assert.equal(sigCase.ok, true);
});

test('limits: too many bytes, too many lines, too deep', () => {
  assert.equal(verifyAll('x'.repeat(LIMITS.maxBytes + 1), {}).overall, 'invalid');
  assert.equal(verifyAll(Array(LIMITS.maxLines + 1).fill('{}').join('\n'), {}).overall, 'invalid');
  assert.equal(verifyAll('['.repeat(LIMITS.maxDepth + 1) + ']'.repeat(LIMITS.maxDepth + 1), {}).overall, 'invalid');
});

test('allowUnchained: unchained prefix is flagged and ordering caveat set', () => {
  const [a, b] = lines(CHAIN);
  const un = JSON.parse(a); delete un.payload.chain; delete un.receiptHash;
  const r = verifyAll([JSON.stringify(un), b].join('\n'), {});
  assert.equal(r.overall, 'failed'); // unchained receipt's signature no longer valid (payload changed) and missing chain fields
  const r2 = verifyAll([JSON.stringify(un)].join('\n'), { allowUnchained: true });
  assert.equal(r2.chain.unchainedPrefix, true);
});

test('a library exception becomes verifier_error, never ok', () => {
  const [a] = lines(CHAIN); const o = JSON.parse(a);
  Object.defineProperty(o.payload, 'issuedAt', { get() { throw new Error('boom'); }, enumerable: true });
  const r = verifyAll.__withReceipts([o], {});
  assert.equal(r.overall, 'failed'); assert.ok(r.rows[0].problems.some((p) => /verifier_error/.test(p)));
});

test('parseInput classifies', () => {
  assert.equal(parseInput(lines(CHAIN)[0]).kind, 'receipt');
  assert.equal(parseInput(CHAIN).kind, 'chain');
  assert.equal(parseInput('').kind, 'invalid');
});

// --- Codex review round 1 (2026-09-30) ---------------------------------------
test('commerce envelope: required fields typed, intentHash bare 64-hex (CLAUDE.md invariant)', () => {
  const base = JSON.parse(conf('no-instance.json'));
  const withCommerce = (c) => { const o = structuredClone(base); o.payload.commerce = c; return o; };
  assert.equal(verifyAll(JSON.stringify(base), {}).overall, 'ok', 'fixture itself verifies');
  for (const [label, c] of [
    ['empty object', {}],
    ['0x-prefixed intentHash', { ...base.payload.commerce, intentHash: '0x' + base.payload.commerce.intentHash }],
    ['short intentHash', { ...base.payload.commerce, intentHash: 'abab' }],
    ['amount string', { ...base.payload.commerce, amount: '25' }],
    ['missing rail', { ...base.payload.commerce, rail: undefined }],
  ]) {
    const r = verifyAll(JSON.stringify(withCommerce(c)), {});
    assert.equal(r.overall, 'failed', label); assert.equal(r.rows[0].envelope.ok, false, label); assert.equal(r.rows[0].signature, 'not-run', label);
  }
});

test('signature.keyId must equal payload.keyId (outside the signed bytes)', () => {
  const o = JSON.parse(conf('no-instance.json')); o.signature.keyId = 'k2';
  const r = verifyAll(JSON.stringify(o), { expectedSigner: CONF_SIGNER });
  assert.equal(r.overall, 'failed'); assert.equal(r.rows[0].envelope.ok, false); assert.ok(r.rows[0].envelope.problems.some((p) => /keyId/.test(p)));
});

test('chain verifier exception → checkpoint unchecked, never matched', () => {
  const [a] = lines(CHAIN); const o = JSON.parse(a);
  Object.defineProperty(o.payload.chain, 'seq', { get() { return 0; }, enumerable: true });
  let reads = 0;
  Object.defineProperty(o.payload.chain, 'prevReceiptHash', { get() { reads += 1; if (reads > 2) throw new Error('boom'); return '0x' + '00'.repeat(32); }, enumerable: true });
  const r = verifyAll.__withReceipts([o], { expectedCount: 99, expectedHeadHash: '0x' + '11'.repeat(32) });
  assert.equal(r.overall, 'failed');
  assert.equal(r.chain.error, true);
  assert.equal(r.checkpoint.state, 'unchecked');
  assert.notEqual(r.checkpoint.count, 'matched'); assert.notEqual(r.checkpoint.head, 'matched');
});
