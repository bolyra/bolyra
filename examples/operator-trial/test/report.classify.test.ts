import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { BundleInputError, classify } from '../src/report/classify';
import { createGatewayReceiptSigner } from '@bolyra/gateway';
import { buildGatewayConfig } from '../src/gateway-config';
import { createDemoAgent } from '../src/agents';
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

/** The receipt-backed claims every attributed attempt carries. */
const PAYLOAD_CLAIMS = ['A2', 'A3', 'A4b', 'A4c', 'A5', 'A6', 'A8a', 'A9a'];
const CLEAN_BUNDLE: Record<string, Status> = { B2: 'DERIVED', B3a: 'DERIVED', B3b: 'DERIVED', B4: 'DERIVED', B4b: 'OBSERVED', B5: 'ABSENT', B6: 'OBSERVED', B7: 'OBSERVED', B8a: 'OBSERVED', B8b: 'OBSERVED' };
function expectAttempt(r: Report, attempt: number, payload: Status, a1: Status = 'DERIVED') {
  assert.equal(status(r, 'A1', { attempt }), a1, `A1@${attempt}`);
  for (const c of PAYLOAD_CLAIMS) {
    const want = payload === 'SIGNED' && (c === 'A4b' || c === 'A4c') ? 'DERIVED' : payload;
    assert.equal(status(r, c, { attempt }), want, `${c}@${attempt}`);
  }
  assert.equal(status(r, 'A4a', { attempt }), 'OBSERVED');
  assert.equal(status(r, 'A10', { attempt }), 'OBSERVED');
  assert.equal(status(r, 'A11', { attempt }), attempt === 1 ? 'OBSERVED' : 'ABSENT');
  for (const c of ['A7a', 'A9b', 'A12', 'A13', 'A14', 'A15', 'A16', 'A17']) assert.equal(status(r, c, { attempt }), 'ABSENT', `${c}@${attempt}`);
  if (attempt === 2) assert.equal(status(r, 'A7b', { attempt }), payload === 'SIGNED' ? 'DERIVED' : 'FAILED');
}
function expectBundle(r: Report, over: Partial<Record<string, Status>> = {}) {
  for (const [c, st] of Object.entries({ ...CLEAN_BUNDLE, ...over })) assert.equal(status(r, c), st, c);
}

test('1b. clean fixture: complete bundle table incl. the host checkpoints and VERIFY.txt', () => {
  const r = run();
  expectBundle(r);
  for (const attempt of [1, 2, 3]) expectAttempt(r, attempt, 'SIGNED');
  assert.equal(status(r, 'A8b', { attempt: 3 }), 'DERIVED');
});

test('2b. payload mutation on line 1: complete tables', () => {
  const r = run(files({ receiptsJsonl: mutateLine(1, (x) => { x.payload.decision.allowed = false; }) }));
  expectBundle(r, { B2: 'FAILED' });
  expectAttempt(r, 1, 'FAILED');
  expectAttempt(r, 2, 'SIGNED');
  expectAttempt(r, 3, 'SIGNED');
  assert.equal(status(r, 'A8b', { attempt: 3 }), 'FAILED');
  assert.match(one(r, 'A2', { attempt: 1 }).note ?? '', /signature-invalid/);
});

test('4b. convenience-hash mutation on line 3: complete tables', () => {
  const r = run(files({ receiptsJsonl: mutateLine(3, (x) => { x.receiptHash = '0x' + 'ab'.repeat(32); }) }));
  expectBundle(r, { B2: 'FAILED' });
  for (const attempt of [1, 2, 3]) expectAttempt(r, attempt, 'SIGNED');
  assert.equal(status(r, 'A8b', { attempt: 3 }), 'DERIVED');
});

test('5b. tail truncation: attempt 3 propagation under every anchor combination', () => {
  const two = lines.slice(0, 2).join('\n') + '\n';
  for (const a of [ANCHORS, { signer: ANCHORS.signer, expectCount: 3 }, { signer: ANCHORS.signer, expectHead: ANCHORS.expectHead }, { signer: ANCHORS.signer }]) {
    const r = run(files({ receiptsJsonl: two }), a);
    expectAttempt(r, 1, 'SIGNED');
    expectAttempt(r, 2, 'SIGNED');
    for (const c of PAYLOAD_CLAIMS) assert.equal(status(r, c, { attempt: 3 }), 'FAILED', c);
    assert.equal(status(r, 'A1', { attempt: 3 }), 'FAILED');
    assert.equal(status(r, 'A8b', { attempt: 3 }), 'FAILED');
    assert.equal(status(r, 'B2'), 'DERIVED');
    assert.equal(status(r, 'B8a'), 'FAILED');
    assert.equal(status(r, 'B8b'), 'FAILED');
    assert.deepEqual(r.unattributedLines, []);
  }
});

test('6b/7b. unlinked and duplicate links: complete tables', () => {
  const r6 = run(files({ summaryJson: withSummary((s) => { s.attempts[0].receiptId = '0x' + '0'.repeat(16); }) }));
  expectBundle(r6);
  expectAttempt(r6, 1, 'FAILED', 'FAILED');
  expectAttempt(r6, 2, 'SIGNED');
  expectAttempt(r6, 3, 'SIGNED');
  for (const c of PAYLOAD_CLAIMS.filter((c) => c !== 'A4c')) assert.equal(status(r6, c, { line: 1 }), c === 'A4b' ? 'DERIVED' : 'SIGNED', c);
  const r7 = run(files({ summaryJson: withSummary((s) => { s.attempts[1].receiptId = s.attempts[0].receiptId; }) }));
  expectBundle(r7);
  expectAttempt(r7, 1, 'FAILED', 'FAILED');
  expectAttempt(r7, 2, 'FAILED', 'FAILED');
  expectAttempt(r7, 3, 'SIGNED');
  assert.equal(status(r7, 'A8b', { attempt: 3 }), 'FAILED');
});

test('11. host checkpoints and VERIFY.txt that contradict the log are FAILED, and never become anchors', () => {
  const r = run(files({
    summaryJson: withSummary((s) => { s.receiptCount = 99; s.headReceiptHash = '0x' + 'c'.repeat(64); }),
    verifyTxt: `npx @bolyra/cli@0.9.0 receipt verify-chain ./receipts.jsonl --signer 0x${'9'.repeat(40)} --expect-count 3\n`,
  }));
  expectBundle(r, { B8a: 'FAILED', B8b: 'FAILED', B4b: 'FAILED' });
  assert.match(one(r, 'B8a').note ?? '', /contradiction/);
  assert.match(one(r, 'B4b').note ?? '', /0x9{40}/);
  for (const attempt of [1, 2, 3]) expectAttempt(r, attempt, 'SIGNED');
  assert.equal(r.anchors.signer, ANCHORS.signer);
});

test('12. malformed payloads are B0 FAILED without crashing; the other lines are classified', () => {
  for (const strip of ['decision', 'subject', 'proof'] as const) {
    const r = run(files({ receiptsJsonl: mutateLine(2, (x) => { delete x.payload[strip]; }) }));
    const b0 = r.findings.find((f) => f.claim === 'B0' && f.receiptLine === 2);
    assert.ok(b0 && b0.status === 'FAILED' && /payload\./.test(b0.note ?? ''), strip);
    assert.ok(!r.findings.some((f) => f.claim === 'B1' && f.receiptLine === 2));
    expectAttempt(r, 1, 'SIGNED');
    expectAttempt(r, 2, 'FAILED', 'FAILED');
    expectAttempt(r, 3, 'SIGNED');
    assert.equal(status(r, 'B2'), 'FAILED');
  }
  const r = run(files({ receiptsJsonl: mutateLine(1, (x) => { x.payload.decision.allowed = 'yes'; }) }));
  assert.ok(r.findings.some((f) => f.claim === 'B0' && f.receiptLine === 1 && f.status === 'FAILED'));
});

test('13. attempt numbers must match their positions; structural problems are input errors', () => {
  assert.throws(() => run(files({ summaryJson: withSummary((s) => { s.attempts[2].n = 2; }) })), BundleInputError);
  assert.throws(() => run(files({ summaryJson: withSummary((s) => { s.attempts = {}; }) })), BundleInputError);
  assert.throws(() => run(files({ summaryJson: withSummary((s) => { s.attempts = []; }) })), BundleInputError);
  assert.throws(() => run(files({ summaryJson: withSummary((s) => { s.attempts[0] = 'x'; }) })), BundleInputError);
  assert.throws(() => run(files({ summaryJson: '[]' })), BundleInputError);
});

test('14. missing unsigned fields become ABSENT, never OBSERVED placeholders', () => {
  const r = run(files({ summaryJson: withSummary((s) => { delete s.dryRun; delete s.action; delete s.attempts[0].dispatched; delete s.receiptCount; delete s.headReceiptHash; }), verifyTxt: undefined }));
  assert.equal(status(r, 'B7'), 'ABSENT');
  assert.equal(status(r, 'B8a'), 'ABSENT');
  assert.equal(status(r, 'B8b'), 'ABSENT');
  assert.equal(status(r, 'B4b'), 'ABSENT');
  assert.equal(status(r, 'A10', { attempt: 1 }), 'ABSENT');
  for (const attempt of [1, 2, 3]) {
    assert.equal(status(r, 'A4a', { attempt }), 'ABSENT');
    assert.equal(status(r, 'A4c', { attempt }), 'ABSENT');
    assert.equal(status(r, 'A4b', { attempt }), 'DERIVED');
  }
  for (const f of r.findings) assert.ok(!/undefined/.test(f.note ?? ''), f.id);
});

test('15. a dispatched attempt without a status (timeout) is not described as "nothing dispatched"', () => {
  const r = run(files({ summaryJson: withSummary((s) => { s.dryRun = false; s.attempts[0].upstreamStatus = null; s.attempts[0].outcome = 'timeout'; }) }));
  const a11 = one(r, 'A11', { attempt: 1 });
  assert.equal(a11.status, 'ABSENT');
  assert.match(a11.note ?? '', /timeout/);
  assert.doesNotMatch(a11.note ?? '', /nothing was dispatched/);
  assert.equal(status(r, 'A10', { attempt: 1 }), 'OBSERVED');
  assert.match(one(r, 'B7').note ?? '', /false/);
});

test('16. the attempt-3 permission caveat does not depend on the editable stage field', () => {
  const r = run(files({ summaryJson: withSummary((s) => { delete s.attempts[2].stage; }) }));
  assert.match(one(r, 'A6', { attempt: 3 }).note ?? '', /not evidence that permissions were evaluated/);
  assert.equal(status(r, 'A6', { attempt: 3 }), 'SIGNED');
  assert.doesNotMatch(one(r, 'A6', { attempt: 1 }).note ?? '', /failure default/);
});

test('17. upper-case anchors normalize and still verify', () => {
  const r = run(files(), { signer: ANCHORS.signer.toUpperCase().replace('0X', '0x'), expectCount: 3, expectHead: ANCHORS.expectHead!.toUpperCase().replace('0X', '0x') });
  assert.equal(r.anchors.signer, ANCHORS.signer);
  assert.equal(r.anchors.expectHead, ANCHORS.expectHead);
  expectBundle(r);
});

test('18. hostile values in envelope, chain and signer.json produce findings, never exceptions', () => {
  const hostile = { toString: null };
  for (const mut of [
    (x: any) => { x.receiptHash = hostile; },
    (x: any) => { x.payload.chain.seq = hostile; },
    (x: any) => { x.payload.chain.prevReceiptHash = hostile; },
    (x: any) => { x.payload.chain = 'nope'; },
  ]) {
    const r = run(files({ receiptsJsonl: mutateLine(2, mut) }));
    assert.ok(r.findings.some((f) => f.claim === 'B0' && f.receiptLine === 2 && f.status === 'FAILED'));
    assert.equal(status(r, 'B2'), 'FAILED');
    assert.equal(status(r, 'B8a'), 'FAILED');
    expectAttempt(r, 1, 'SIGNED');
    expectAttempt(r, 2, 'FAILED', 'FAILED');
  }
  const r = run(files({ signerJson: JSON.stringify({ signer: hostile, ephemeral: true }) }));
  assert.equal(status(r, 'B4'), 'FAILED');
  assert.match(one(r, 'B4').note ?? '', /toString/);
});

test('19. an appended malformed line makes every whole-log claim FAILED, not a claim about the readable subset', () => {
  const r = run(files({ receiptsJsonl: lines.join('\n') + '\n{}\n' }));
  assert.ok(r.findings.some((f) => f.claim === 'B0' && f.receiptLine === 4 && f.status === 'FAILED'));
  assert.equal(status(r, 'B2'), 'FAILED');
  assert.match(one(r, 'B2').note ?? '', /malformed line\(s\) 4/);
  assert.equal(status(r, 'B3a'), 'FAILED');
  assert.match(one(r, 'B3a').note ?? '', /4 non-blank line\(s\), of which 1 malformed/);
  assert.equal(status(r, 'B3b'), 'DERIVED');
  assert.match(one(r, 'B3b').note ?? '', /last readable chained receipt \(line 3\); malformed line\(s\) 4 are excluded \(see B2\)/);
  assert.deepEqual(one(r, 'B3b').evidence, [{ file: 'receipts.jsonl', line: 3 }]);
  assert.equal(status(r, 'B8a'), 'FAILED');
  assert.equal(status(r, 'B8b'), 'OBSERVED');
  assert.match(one(r, 'B8b').note ?? '', /line 3\); malformed line\(s\) 4 are excluded/);
  for (const attempt of [1, 2, 3]) expectAttempt(r, attempt, 'SIGNED');
});

test('20. a freshly signed receipt without reasonCode: A3 ABSENT (not a SIGNED empty string), A4b ABSENT', () => {
  const cfg = buildGatewayConfig('refund', 2n, createDemoAgent('g', 2n), createDemoAgent('w', 1n));
  const signer = createGatewayReceiptSigner(cfg);
  const receipt = signer.sign({
    rootDid: 'did:bolyra:dev:t', actingDid: 'did:bolyra:dev:t', credentialCommitment: '1', effectiveCommitment: '1',
    allowed: true, score: 100, permissionBitmask: '2', chainDepth: 0,
    humanProof: { proof: {} }, agentProof: { proof: {} }, humanPublicSignals: [], agentPublicSignals: [], bundleVersion: 1, nonce: '7',
  });
  assert.equal(receipt.payload.decision.reasonCode, undefined);
  const sum = { dryRun: true, action: summary.action, attempts: [{ n: 1, credential: 'granted', decision: 'allow', dispatched: true, upstreamStatus: 200, receiptId: receipt.id }], receiptCount: 1, headReceiptHash: receipt.receiptHash };
  const r = classify({ receiptsJsonl: JSON.stringify(receipt) + '\n', summaryJson: JSON.stringify(sum) }, { signer: signer.signer, expectCount: 1, expectHead: receipt.receiptHash! });
  assert.equal(status(r, 'B1', { line: 1 }), 'DERIVED');
  assert.equal(status(r, 'A2', { attempt: 1 }), 'SIGNED');
  assert.equal(status(r, 'A3', { attempt: 1 }), 'ABSENT');
  assert.equal(status(r, 'A4b', { attempt: 1 }), 'ABSENT');
  assert.equal(status(r, 'A4c', { attempt: 1 }), 'ABSENT');
  assert.ok(!r.findings.some((f) => f.status === 'FAILED'), JSON.stringify(r.findings.filter((f) => f.status === 'FAILED').map((f) => f.id)));
});

test('21. a readable but unchained receipt at the tail: B3b/B8b cite the last CHAINED receipt (line 3), B2 fails', () => {
  const extra = JSON.parse(JSON.stringify(receipts[0]));
  delete extra.payload.chain;
  delete extra.receiptHash;
  const r = run(files({ receiptsJsonl: lines.join('\n') + '\n' + JSON.stringify(extra) + '\n' }));
  assert.equal(status(r, 'B2'), 'FAILED');
  assert.match(one(r, 'B2').note ?? '', /unchained-after-chained/);
  assert.equal(status(r, 'B3b'), 'DERIVED');
  assert.deepEqual(one(r, 'B3b').evidence, [{ file: 'receipts.jsonl', line: 3 }]);
  assert.match(one(r, 'B3b').note ?? '', /last readable chained receipt \(line 3\)/);
  assert.doesNotMatch(one(r, 'B3b').note ?? '', /line 4/);
  assert.equal(status(r, 'B8b'), 'OBSERVED');
  assert.ok(one(r, 'B8b').evidence.some((e) => e.line === 3) && !one(r, 'B8b').evidence.some((e) => e.line === 4));
  assert.equal(status(r, 'B3a'), 'FAILED');
  assert.equal(status(r, 'B8a'), 'FAILED');
  assert.equal(status(r, 'B1', { line: 4 }), 'FAILED');
  assert.deepEqual(r.unattributedLines, [4]);
  for (const attempt of [1, 2, 3]) expectAttempt(r, attempt, 'SIGNED');
});
