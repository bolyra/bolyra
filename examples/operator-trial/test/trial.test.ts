import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { verifyReceipt, verifyReceiptChain } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import { runTrial } from '../src/trial';
import { validateTrialConfig } from '../src/config';

const ROOT = path.join(__dirname, '..', '..');

function outDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'trial-run-'));
}

function receiptsIn(runDir: string): SignedReceipt[] {
  return fs.readFileSync(path.join(runDir, 'receipts.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
}

test('dry run: allow, policy deny, replay deny; 1/0/0; verifiable bundle (spec tests 1-3)', async () => {
  const lines: string[] = [];
  const summary = await runTrial({ outDir: outDir(), dryRun: true, log: (l) => lines.push(l) });
  assert.equal(summary.ok, true, JSON.stringify(summary, null, 2));
  assert.deepEqual(summary.attempts.map((a) => [a.httpStatus, a.decision, a.stage ?? null]), [
    [200, 'allow', null],
    [403, 'deny', 'policy_denied'],
    [401, 'deny', 'verification_failed'],
  ]);
  assert.match(summary.attempts[2].reason, /Nonce already used/);
  assert.deepEqual(summary.dispatchCounts, [1, 0, 0]);
  assert.equal(summary.echoRequestCount, 1);

  const receipts = receiptsIn(summary.runDir);
  const signer = JSON.parse(fs.readFileSync(path.join(summary.runDir, 'signer.json'), 'utf8')).signer;
  assert.equal(receipts.length, 3);
  for (const r of receipts) assert.ok(verifyReceipt(r, signer));
  const chain = verifyReceiptChain(receipts, { expectedSigner: signer, expectedCount: 3 });
  assert.equal(chain.ok, true);
  const verify = fs.readFileSync(path.join(summary.runDir, 'VERIFY.txt'), 'utf8');
  assert.match(verify, /--expect-count 3/);
  assert.match(verify, new RegExp(`--expect-head ${chain.headHash}`));
  assert.equal(summary.verifyCommand?.trim(), verify.trim());

  const text = lines.join('\n');
  assert.match(text, /Attempt 1 .*ALLOW/);
  assert.match(text, /Attempt 3 .*DENY/);
  assert.match(text, /dispatches to your endpoint: 1 \/ 0 \/ 0/);
  assert.match(text, /hello@bolyra\.ai/);
  assert.match(text, /ZK proof verification is disabled/);
  assert.match(text, /does not stop anyone from calling the endpoint directly/);
});

test('dry run with a 302 endpoint records not_followed (spec test 6)', async () => {
  const summary = await runTrial({ outDir: outDir(), dryRun: true, echo: { status: 302 }, log: () => undefined });
  assert.equal(summary.attempts[0].outcome, 'not_followed');
  assert.equal(summary.attempts[0].upstreamStatus, 302);
  assert.deepEqual(summary.dispatchCounts, [1, 0, 0]);
  assert.equal(summary.ok, true);
});

test('secret exclusion: a header value never reaches the bundle or the log (spec test 8)', async () => {
  const dir = outDir();
  const config = validateTrialConfig(
    { action: 'refund', method: 'POST', url: 'http://127.0.0.1:9/replaced-by-echo', headers: { Authorization: 'Bearer ${T}' }, requiredPermission: 'WRITE_DATA' },
    dir,
    { T: 'sekrit-value-77' },
  );
  const lines: string[] = [];
  // dryRun with a config: the echo URL replaces the configured URL, headers are kept.
  const summary = await runTrial({ config, outDir: dir, dryRun: true, log: (l) => lines.push(l) });
  assert.equal(summary.ok, true);
  for (const name of fs.readdirSync(summary.runDir)) {
    const content = fs.readFileSync(path.join(summary.runDir, name), 'utf8');
    assert.equal(content.includes('sekrit-value-77'), false, `${name} leaks the secret`);
  }
  assert.equal(lines.join('\n').includes('sekrit-value-77'), false, 'log leaks the secret');
  assert.match(lines.join('\n'), /headers sent: Authorization/);
});

test('deny-receipt write failure produces a partial but verifiable bundle (spec test 11)', async () => {
  let calls = 0;
  const summary = await runTrial({
    outDir: outDir(),
    dryRun: true,
    log: () => undefined,
    audit: {
      io: {
        appendFileSync(p, data) {
          calls += 1;
          if (calls === 2) {
            fs.appendFileSync(p, data.slice(0, 20));
            throw new Error('disk full');
          }
          fs.appendFileSync(p, data);
        },
      },
    },
  });
  assert.equal(summary.ok, false);
  assert.equal(summary.attempts[0].receiptId !== null, true);
  assert.match(summary.attempts[1].receiptError ?? '', /disk full/);
  assert.match(summary.attempts[2].receiptError ?? '', /chain broken/);
  assert.equal(receiptsIn(summary.runDir).length, 1);
  assert.match(fs.readFileSync(path.join(summary.runDir, 'VERIFY.txt'), 'utf8'), /--expect-count 1/);
});

test('allow-receipt write failure on attempt 1: 500/403/401, 0/0/0, empty bundle, no VERIFY (spec test 10)', async () => {
  const summary = await runTrial({
    outDir: outDir(),
    dryRun: true,
    log: () => undefined,
    audit: {
      io: {
        appendFileSync() {
          throw new Error('disk full');
        },
      },
    },
  });
  assert.equal(summary.ok, false);
  assert.deepEqual(summary.attempts.map((a) => a.httpStatus), [500, 403, 401]);
  assert.deepEqual(summary.dispatchCounts, [0, 0, 0]);
  assert.equal(summary.echoRequestCount, 0);
  assert.match(summary.attempts[0].receiptError ?? '', /disk full/);
  assert.match(summary.attempts[1].receiptError ?? '', /chain broken/);
  assert.match(summary.attempts[2].receiptError ?? '', /chain broken/);
  assert.equal(fs.readFileSync(path.join(summary.runDir, 'receipts.jsonl'), 'utf8'), '');
  const persisted = JSON.parse(fs.readFileSync(path.join(summary.runDir, 'summary.json'), 'utf8'));
  assert.equal(persisted.ok, false);
  assert.equal(persisted.receiptCount, 0);
  assert.equal(fs.existsSync(path.join(summary.runDir, 'VERIFY.txt')), false);
});

test('cli: --dry-run exits 0; missing --config exits 2; unset ${ENV} exits 2 (spec test 9 at the CLI edge)', () => {
  const cli = path.join(ROOT, 'dist', 'src', 'cli.js');
  const ok = spawnSync(process.execPath, [cli, '--dry-run', '--out-dir', outDir()], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(ok.status, 0, ok.stderr);

  const bad = spawnSync(process.execPath, [cli], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /--config/);

  const unknownFlag = spawnSync(process.execPath, [cli, '--dry-run', '--nope'], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(unknownFlag.status, 2);

  // trial.example.yaml references ${THEIR_TOKEN}. With it unset, config
  // loading must fail before any server starts. (Do not run the example with
  // the variable SET: its url is a real hostname and attempt 1 would dispatch.)
  const env = { ...process.env } as Record<string, string | undefined>;
  delete env.THEIR_TOKEN;
  const unset = spawnSync(process.execPath, [cli, '--config', path.join(ROOT, 'trial.example.yaml'), '--out-dir', outDir()], {
    encoding: 'utf8',
    timeout: 60_000,
    env,
  });
  assert.equal(unset.status, 2, unset.stderr);
  assert.match(unset.stderr, /THEIR_TOKEN/);
});
