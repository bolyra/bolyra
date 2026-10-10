import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { classify } from '../src/report/classify';
import type { Anchors, BundleFiles, Finding, Report, Status } from '../src/report/classify';

const FIX = path.join(__dirname, '..', '..', 'test', 'report-fixtures', 'dry-run');

function files(over: Partial<BundleFiles> = {}): BundleFiles {
  return {
    receiptsJsonl: fs.readFileSync(path.join(FIX, 'receipts.jsonl'), 'utf8'),
    summaryJson: fs.readFileSync(path.join(FIX, 'summary.json'), 'utf8'),
    signerJson: fs.readFileSync(path.join(FIX, 'signer.json'), 'utf8'),
    verifyTxt: fs.readFileSync(path.join(FIX, 'VERIFY.txt'), 'utf8'),
    ...over,
  };
}

const summary = JSON.parse(fs.readFileSync(path.join(FIX, 'summary.json'), 'utf8'));
const signerJson = JSON.parse(fs.readFileSync(path.join(FIX, 'signer.json'), 'utf8'));
const lines = fs.readFileSync(path.join(FIX, 'receipts.jsonl'), 'utf8').trim().split('\n');
const receipts = lines.map((l) => JSON.parse(l));

const ANCHORS: Anchors = {
  signer: signerJson.signer,
  expectCount: summary.receiptCount,
  expectHead: summary.headReceiptHash,
};

function run(f: BundleFiles = files(), a: Anchors = ANCHORS): Report {
  return classify(f, a, { now: new Date('2026-10-10T17:00:00Z'), bundleName: 'dry-run' });
}

/** One finding by claim id, scoped to an attempt or to a receipt line. */
function one(r: Report, claim: string, scope: { attempt?: number; line?: number } = {}): Finding {
  const hits = r.findings.filter(
    (x) =>
      x.claim === claim &&
      (scope.attempt === undefined ? x.attempt === undefined : x.attempt === scope.attempt) &&
      (scope.line === undefined ? true : x.receiptLine === scope.line),
  );
  assert.equal(hits.length, 1, `expected exactly one ${claim} ${JSON.stringify(scope)}, got ${hits.length}`);
  return hits[0];
}
function status(r: Report, claim: string, scope: { attempt?: number; line?: number } = {}): Status {
  return one(r, claim, scope).status;
}
function mutateLine(n: number, fn: (receipt: any) => void): string {
  const copy = receipts.map((x) => JSON.parse(JSON.stringify(x)));
  fn(copy[n - 1]);
  return copy.map((x) => JSON.stringify(x)).join('\n') + '\n';
}
function withSummary(fn: (s: any) => void): string {
  const copy = JSON.parse(JSON.stringify(summary));
  fn(copy);
  return JSON.stringify(copy, null, 2) + '\n';
}

test('1. clean fixture with all anchors: every expected status', () => {
  const r = run();
  for (const line of [1, 2, 3]) {
    assert.equal(status(r, 'B1', { line }), 'DERIVED');
    assert.equal(status(r, 'B1a', { line }), 'DERIVED');
  }
  assert.equal(status(r, 'B2'), 'DERIVED');
  assert.equal(status(r, 'B3a'), 'DERIVED');
  assert.equal(status(r, 'B3b'), 'DERIVED');
  assert.equal(status(r, 'B4'), 'DERIVED');
  assert.equal(status(r, 'B5'), 'ABSENT');
  assert.equal(status(r, 'B6'), 'OBSERVED');
  assert.equal(status(r, 'B7'), 'OBSERVED');

  for (const attempt of [1, 2, 3]) {
    assert.equal(status(r, 'A1', { attempt }), 'DERIVED');
    assert.equal(status(r, 'A2', { attempt }), 'SIGNED');
    assert.equal(status(r, 'A3', { attempt }), 'SIGNED');
    assert.equal(status(r, 'A4a', { attempt }), 'OBSERVED');
    assert.equal(status(r, 'A4b', { attempt }), 'DERIVED');
    assert.equal(status(r, 'A4c', { attempt }), 'DERIVED');
    assert.equal(status(r, 'A5', { attempt }), 'SIGNED');
    assert.equal(status(r, 'A6', { attempt }), 'SIGNED');
    assert.equal(status(r, 'A7a', { attempt }), 'ABSENT');
    assert.equal(status(r, 'A8a', { attempt }), 'SIGNED');
    assert.equal(status(r, 'A9a', { attempt }), 'SIGNED');
    assert.equal(status(r, 'A9b', { attempt }), 'ABSENT');
    assert.equal(status(r, 'A10', { attempt }), 'OBSERVED');
    for (const c of ['A12', 'A13', 'A14', 'A15', 'A16', 'A17']) assert.equal(status(r, c, { attempt }), 'ABSENT');
  }
  // A7b: required mask reported in the denial text, attempt 2 only.
  assert.equal(status(r, 'A7b', { attempt: 2 }), 'DERIVED');
  assert.equal(r.findings.filter((x) => x.claim === 'A7b').length, 1);
  // A8b: replay relation, attempt 3 only.
  assert.equal(status(r, 'A8b', { attempt: 3 }), 'DERIVED');
  assert.equal(r.findings.filter((x) => x.claim === 'A8b').length, 1);
  // A11: observed only where a status was recorded.
  assert.equal(status(r, 'A11', { attempt: 1 }), 'OBSERVED');
  assert.equal(status(r, 'A11', { attempt: 2 }), 'ABSENT');
  assert.equal(status(r, 'A11', { attempt: 3 }), 'ABSENT');
  // A6 attempt 3 carries the failure-default note.
  assert.match(one(r, 'A6', { attempt: 3 }).note ?? '', /failure default/);
  // Evidence names file and path for a signed row.
  const a2 = one(r, 'A2', { attempt: 1 });
  assert.deepEqual(a2.evidence, [{ file: 'receipts.jsonl', line: 1, path: 'payload.decision.allowed' }]);
  assert.equal(r.unattributedLines.length, 0);
  assert.equal(r.anchors.signer, ANCHORS.signer);
});

test('2. signed-payload mutation on line 1: that receipt fails, dependents fail, others unchanged', () => {
  const r = run(files({ receiptsJsonl: mutateLine(1, (x) => { x.payload.decision.allowed = false; }) }));
  const b1 = one(r, 'B1', { line: 1 });
  assert.equal(b1.status, 'FAILED');
  assert.match(b1.note ?? '', /signature-invalid/);
  for (const c of ['A2', 'A3', 'A4b', 'A4c', 'A5', 'A6', 'A8a', 'A9a']) assert.equal(status(r, c, { attempt: 1 }), 'FAILED', c);
  assert.equal(status(r, 'A8b', { attempt: 3 }), 'FAILED');
  assert.equal(status(r, 'B2'), 'FAILED');
  for (const attempt of [2, 3]) {
    assert.equal(status(r, 'A2', { attempt }), 'SIGNED');
    assert.equal(status(r, 'B1', { line: attempt }), 'DERIVED');
  }
  assert.equal(status(r, 'A4a', { attempt: 1 }), 'OBSERVED');
  assert.equal(status(r, 'A10', { attempt: 1 }), 'OBSERVED');
  assert.equal(status(r, 'A11', { attempt: 1 }), 'OBSERVED');
  for (const c of ['A7a', 'A9b', 'A12', 'A13', 'A14', 'A15', 'A16', 'A17']) assert.equal(status(r, c, { attempt: 1 }), 'ABSENT');
  assert.ok(!r.findings.some((x) => x.attempt === 1 && x.status === 'SIGNED'));
});

test('3. id-only mutation on line 2: still verifies, id check fails, attempt 2 unlinked, receipt unattributed', () => {
  const r = run(files({ receiptsJsonl: mutateLine(2, (x) => { x.id = x.id.slice(0, -1) + (x.id.endsWith('0') ? '1' : '0'); }) }));
  assert.equal(status(r, 'B1', { line: 2 }), 'DERIVED');
  assert.equal(status(r, 'B1a', { line: 2 }), 'FAILED');
  assert.equal(status(r, 'A1', { attempt: 2 }), 'FAILED');
  assert.deepEqual(r.unattributedLines, [2]);
  // The receipt's own payload rows survive under the unattributed heading (no attempt).
  assert.equal(status(r, 'A2', { line: 2 }), 'SIGNED');
  // The attempt's receipt-backed rows are FAILED with no value assigned.
  for (const c of ['A2', 'A3', 'A4b', 'A4c', 'A5', 'A6', 'A7b', 'A8a', 'A9a']) {
    const f = one(r, c, { attempt: 2 });
    assert.equal(f.status, 'FAILED', c);
    assert.deepEqual(f.evidence, []);
  }
  assert.equal(status(r, 'B2'), 'DERIVED');
});

test('4. convenience-hash mutation on line 3: chain fails, payload rows stay signed', () => {
  const r = run(files({ receiptsJsonl: mutateLine(3, (x) => { x.receiptHash = '0x' + 'ab'.repeat(32); }) }));
  assert.equal(status(r, 'B1', { line: 3 }), 'DERIVED');
  const b2 = one(r, 'B2');
  assert.equal(b2.status, 'FAILED');
  assert.match(b2.note ?? '', /receipt-hash-mismatch/);
  assert.equal(status(r, 'A2', { attempt: 3 }), 'SIGNED');
});

test('5. tail truncation: each anchor closes its own check', () => {
  const two = lines.slice(0, 2).join('\n') + '\n';
  const both = run(files({ receiptsJsonl: two }));
  assert.equal(status(both, 'B3a'), 'FAILED');
  assert.equal(status(both, 'B3b'), 'FAILED');
  assert.equal(status(both, 'A1', { attempt: 3 }), 'FAILED');
  assert.equal(status(both, 'A2', { attempt: 3 }), 'FAILED');
  assert.equal(status(both, 'A8b', { attempt: 3 }), 'FAILED');

  const countOnly = run(files({ receiptsJsonl: two }), { signer: ANCHORS.signer, expectCount: 3 });
  assert.equal(status(countOnly, 'B3a'), 'FAILED');
  assert.equal(status(countOnly, 'B3b'), 'ABSENT');
  assert.match(one(countOnly, 'B3b').note ?? '', /--expect-head/);

  const headOnly = run(files({ receiptsJsonl: two }), { signer: ANCHORS.signer, expectHead: ANCHORS.expectHead });
  assert.equal(status(headOnly, 'B3a'), 'ABSENT');
  assert.match(one(headOnly, 'B3a').note ?? '', /--expect-count/);
  assert.equal(status(headOnly, 'B3b'), 'FAILED');

  const none = run(files({ receiptsJsonl: two }), { signer: ANCHORS.signer });
  assert.equal(status(none, 'B2'), 'DERIVED');
  assert.equal(status(none, 'B3a'), 'ABSENT');
  assert.equal(status(none, 'B3b'), 'ABSENT');
});

test('6. summary points at a nonexistent id: A1 fails, real receipt unattributed, no positional relink', () => {
  const r = run(files({ summaryJson: withSummary((s) => { s.attempts[0].receiptId = '0x' + '0'.repeat(16); }) }));
  assert.equal(status(r, 'A1', { attempt: 1 }), 'FAILED');
  assert.deepEqual(r.unattributedLines, [1]);
  assert.equal(status(r, 'A2', { line: 1 }), 'SIGNED');
  assert.equal(status(r, 'A2', { attempt: 1 }), 'FAILED');
  assert.deepEqual(one(r, 'A2', { attempt: 1 }).evidence, []);
  assert.equal(status(r, 'A8b', { attempt: 3 }), 'FAILED');
});

test('7. duplicate link: both attempts fail A1', () => {
  const r = run(files({ summaryJson: withSummary((s) => { s.attempts[1].receiptId = s.attempts[0].receiptId; }) }));
  assert.equal(status(r, 'A1', { attempt: 1 }), 'FAILED');
  assert.equal(status(r, 'A1', { attempt: 2 }), 'FAILED');
  assert.deepEqual(r.unattributedLines, [1, 2]);
  for (const attempt of [1, 2]) assert.equal(status(r, 'A2', { attempt }), 'FAILED');
  for (const line of [1, 2]) assert.equal(status(r, 'A2', { line }), 'SIGNED');
});

test('8. signer.json edited: B4 fails, B1 unchanged', () => {
  const r = run(files({ signerJson: JSON.stringify({ ...signerJson, signer: '0x' + '1'.repeat(40) }) }));
  assert.equal(status(r, 'B4'), 'FAILED');
  assert.equal(status(r, 'B1', { line: 1 }), 'DERIVED');
});

test('9. wrong --signer: every B1 fails and nothing is SIGNED', () => {
  const r = run(files(), { ...ANCHORS, signer: '0x' + '2'.repeat(40) });
  for (const line of [1, 2, 3]) assert.equal(status(r, 'B1', { line }), 'FAILED');
  assert.ok(!r.findings.some((x) => x.status === 'SIGNED'));
});

test('10. malformed physical line 2: named FAILED finding, lines 1 and 3 still classified', () => {
  const bad = [lines[0], '{not json', lines[2]].join('\n') + '\n';
  const r = run(files({ receiptsJsonl: bad }));
  const m = r.findings.find((x) => x.claim === 'B0' && x.receiptLine === 2);
  assert.ok(m && m.status === 'FAILED', 'malformed-line finding');
  assert.equal(status(r, 'B1', { line: 1 }), 'DERIVED');
  assert.equal(status(r, 'B1', { line: 3 }), 'DERIVED');
  assert.equal(status(r, 'A2', { attempt: 1 }), 'SIGNED');
  assert.equal(status(r, 'A2', { attempt: 3 }), 'SIGNED');
});

test('every finding has a claim, a status, and evidence or a note', () => {
  const r = run();
  for (const f of r.findings) {
    assert.ok(f.id && f.claim && f.status, JSON.stringify(f));
    assert.ok(f.evidence.length > 0 || (f.note ?? '').length > 0, `${f.id} has neither evidence nor note`);
  }
  const ids = r.findings.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, 'finding ids unique');
});
