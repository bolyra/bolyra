/**
 * End-to-end test for the verified-actions demo.
 *
 * Runs the compiled demo once as a child process, then asserts:
 *   1. the allow verdict happened (2 allows: write-scoped refund + read-scoped read)
 *   2. the deny verdicts happened (policy deny + replay deny + forged-bundle deny)
 *   3. the audit log holds one signed receipt per decision
 *   4. every receipt independently verifies (this file imports
 *      @bolyra/receipts directly — no demo code in the verification path)
 *   5. tampered receipts fail verification
 */

import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyReceipt, verifyReceiptChain, GENESIS_PREV_RECEIPT_HASH } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import { pkgRoot } from '../src/paths';

const ROOT = pkgRoot(__dirname);
const AUDIT_DIR = path.join(ROOT, 'audit');
const LOG_PATH = path.join(AUDIT_DIR, 'audit-log.jsonl');

// Run the demo once, up front. `npm test` compiles first, so dist/src exists.
const run = spawnSync(process.execPath, [path.join(ROOT, 'dist', 'src', 'demo.js')], {
  cwd: ROOT,
  encoding: 'utf8',
  env: { ...process.env, NO_COLOR: '1' },
  timeout: 60_000,
});

function readReceipts(): SignedReceipt[] {
  const lines = fs.readFileSync(LOG_PATH, 'utf8').trim().split('\n');
  return lines.map((line) => JSON.parse(line) as SignedReceipt);
}

test('demo exits cleanly', () => {
  assert.equal(run.status, 0, `demo exited ${run.status}\nstderr:\n${run.stderr}\nstdout:\n${run.stdout}`);
});

test('demo narrates allow and deny verdicts', () => {
  const allowCount = (run.stdout.match(/-> ALLOWED/g) ?? []).length;
  const denyCount = (run.stdout.match(/-> DENIED/g) ?? []).length;
  assert.ok(allowCount >= 2, `expected >= 2 ALLOWED verdicts, saw ${allowCount}`);
  assert.ok(denyCount >= 1, `expected >= 1 DENIED verdict, saw ${denyCount}`);
  assert.match(run.stdout, /replay/i, 'expected the replay scene in the narration');
  assert.match(run.stdout, /forged/i, 'expected the forged-bundle scene in the narration');
  assert.match(run.stdout, /tamper/i, 'expected the tamper check in the narration');
});

test('audit log holds one signed receipt per decision (2 allow, 3 deny)', () => {
  const receipts = readReceipts();
  assert.equal(receipts.length, 5, `expected 5 receipts, got ${receipts.length}`);

  const allows = receipts.filter((r) => r.payload.decision.allowed);
  const denies = receipts.filter((r) => !r.payload.decision.allowed);
  assert.equal(allows.length, 2);
  assert.equal(denies.length, 3);

  // The policy deny must name the tool and the missing permission.
  const policyDeny = denies.find((r) => r.payload.decision.reasonCode?.includes('refund_customer'));
  assert.ok(policyDeny, 'expected a deny receipt naming refund_customer');
  assert.match(policyDeny!.payload.decision.reasonCode!, /requires/);

  // The replay deny is an authentication failure with score 0.
  const replayDeny = denies.find((r) => r.payload.decision.reasonCode?.includes('authentication_failed'));
  assert.ok(replayDeny, 'expected a deny receipt for the replayed bundle');
  assert.equal(replayDeny!.payload.decision.score, 0);

  // The forged bundle is caught against the registered credential.
  const forgedDeny = denies.find((r) => r.payload.decision.reasonCode?.includes('credential_mismatch'));
  assert.ok(forgedDeny, 'expected a deny receipt for the forged permission mask');
  assert.match(forgedDeny!.payload.decision.reasonCode!, /claims permissions 11b/);
});

test('every receipt verifies independently against the published signer', () => {
  const signerInfo = JSON.parse(fs.readFileSync(path.join(AUDIT_DIR, 'signer.json'), 'utf8'));
  for (const receipt of readReceipts()) {
    assert.equal(receipt.signature.alg, 'ES256K');
    assert.equal(
      verifyReceipt(receipt, signerInfo.signer),
      true,
      `receipt ${receipt.id} failed verification`,
    );
  }
});

test('receipts are hash-chained: seq 0..n-1 from the genesis sentinel', () => {
  const receipts = readReceipts();
  assert.ok(receipts.length > 0);
  assert.equal(receipts[0].payload.chain?.seq, 0);
  assert.equal(receipts[0].payload.chain?.prevReceiptHash, GENESIS_PREV_RECEIPT_HASH);
  receipts.forEach((r, i) => {
    assert.equal(r.payload.chain?.seq, i, `receipt ${i} has wrong seq`);
    assert.match(r.receiptHash ?? '', /^0x[0-9a-f]{64}$/, `receipt ${i} missing receiptHash`);
  });
  const result = verifyReceiptChain(receipts);
  assert.equal(result.ok, true, `chain verification failed: ${JSON.stringify(result.issues)}`);
  assert.equal(result.chained, receipts.length);
});

test('deleting a line from the audit log breaks chain verification', () => {
  const receipts = readReceipts();
  const deleted = [...receipts.slice(0, 1), ...receipts.slice(2)]; // line 2 deleted
  const result = verifyReceiptChain(deleted);
  assert.equal(result.ok, false, 'a deleted line must break chain verification');
  // Every remaining individual signature is still valid — that is exactly why
  // per-receipt signatures alone cannot catch this.
  for (const r of deleted) assert.equal(verifyReceipt(r), true);
});

test('reordering two lines in the audit log breaks chain verification', () => {
  const receipts = readReceipts();
  const reordered = [...receipts];
  [reordered[1], reordered[2]] = [reordered[2], reordered[1]];
  const result = verifyReceiptChain(reordered);
  assert.equal(result.ok, false, 'reordered lines must break chain verification');
  for (const r of reordered) assert.equal(verifyReceipt(r), true);
});

test('demo narrates the whole-log tamper scenes (delete + reorder)', () => {
  assert.match(run.stdout, /delet/i, 'expected the deleted-line scene in the narration');
  assert.match(run.stdout, /reorder/i, 'expected the reordered-lines scene in the narration');
  assert.match(run.stdout, /chain/i, 'expected chain verification in the narration');
});

test('tampered receipts fail verification', () => {
  const receipts = readReceipts();
  const deny = receipts.find((r) => !r.payload.decision.allowed)!;

  // Flip the verdict: deny -> allow.
  const flipped: SignedReceipt = JSON.parse(JSON.stringify(deny));
  flipped.payload.decision.allowed = true;
  assert.equal(verifyReceipt(flipped), false, 'flipped verdict must not verify');

  // Rewrite the reason.
  const reworded: SignedReceipt = JSON.parse(JSON.stringify(deny));
  reworded.payload.decision.reasonCode = 'nothing to see here';
  assert.equal(verifyReceipt(reworded), false, 'rewritten reason must not verify');

  // Graft another receipt's signature (splice attack).
  const other = receipts.find((r) => r.id !== deny.id)!;
  const spliced: SignedReceipt = JSON.parse(JSON.stringify(deny));
  spliced.signature = JSON.parse(JSON.stringify(other.signature));
  assert.equal(verifyReceipt(spliced), false, 'spliced signature must not verify');
});
