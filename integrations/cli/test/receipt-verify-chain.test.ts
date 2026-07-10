/**
 * bolyra receipt verify-chain <file> — whole-log integrity verification.
 *
 * Verifies every ES256K signature AND the hash chain (seq continuity,
 * prevReceiptHash links). Precision matters: deletions, reordering, edits,
 * and head truncation are detectable from the log alone; TAIL truncation is
 * only detectable against an external expectation (--expect-count /
 * --expect-head).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  ReceiptChain,
  createAuthReceipt,
  signReceipt,
  computeReceiptHash,
} from '@bolyra/receipts';
import type { AuthReceiptInput, ReceiptSignerConfig, SignedReceipt } from '@bolyra/receipts';
import { main } from '../src/main';

const TEST_CONFIG: ReceiptSignerConfig = {
  issuer: 'test-gateway',
  keyId: 'k1',
  privateKey: '0x' + '01'.repeat(32),
};

function makeInput(nonce: string): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:dev:root',
    actingDid: 'did:bolyra:dev:agent',
    credentialCommitment: '123',
    effectiveCommitment: '123',
    allowed: true,
    score: 95,
    permissionBitmask: '3',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1] } },
    agentProof: { proof: { pi_a: [2] } },
    humanPublicSignals: ['1'],
    agentPublicSignals: ['2'],
    bundleVersion: 1,
    nonce,
  };
}

function makePayload(nonce: string) {
  return createAuthReceipt(makeInput(nonce), {
    issuer: TEST_CONFIG.issuer,
    keyId: TEST_CONFIG.keyId,
    issuedAt: 1_700_000_000,
  });
}

function makeChainedLog(n: number): SignedReceipt[] {
  const chain = new ReceiptChain();
  const receipts: SignedReceipt[] = [];
  for (let i = 0; i < n; i++) {
    receipts.push(chain.sign(makePayload(String(1000 + i)), TEST_CONFIG));
  }
  return receipts;
}

let tmpDir: string;

function writeLog(receipts: SignedReceipt[], name = 'log.jsonl'): string {
  const file = path.join(tmpDir, name);
  fs.writeFileSync(file, receipts.map((r) => JSON.stringify(r)).join('\n') + (receipts.length ? '\n' : ''));
  return file;
}

function captureConsole() {
  const logs: string[] = [];
  const errors: string[] = [];
  const origLog = console.log;
  const origError = console.error;
  console.log = (...args: unknown[]) => logs.push(args.map(String).join(' '));
  console.error = (...args: unknown[]) => errors.push(args.map(String).join(' '));
  return {
    logs,
    errors,
    all: () => [...logs, ...errors].join('\n'),
    restore() {
      console.log = origLog;
      console.error = origError;
    },
  };
}

async function run(args: string[]): Promise<{ out: string; exitCode: number | string | undefined }> {
  const cap = captureConsole();
  try {
    await main(['receipt', 'verify-chain', ...args]);
    return { out: cap.all(), exitCode: process.exitCode };
  } finally {
    cap.restore();
  }
}

describe('bolyra receipt verify-chain', () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-chain-'));
  });

  afterEach(() => {
    process.exitCode = undefined;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('shows help with --help', async () => {
    const { out, exitCode } = await run(['--help']);
    expect(out).toContain('verify-chain');
    expect(out).toContain('--expect-count');
    expect(exitCode).toBeUndefined();
  });

  it('requires a file argument', async () => {
    const { exitCode } = await run([]);
    expect(exitCode).toBe(2);
  });

  it('errors on a missing file', async () => {
    const { exitCode } = await run([path.join(tmpDir, 'nope.jsonl')]);
    expect(exitCode).toBe(1);
  });

  it('errors on invalid JSON, naming the line', async () => {
    const file = path.join(tmpDir, 'bad.jsonl');
    fs.writeFileSync(file, JSON.stringify(makeChainedLog(1)[0]) + '\n{not json\n');
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/line 2/i);
  });

  it('PASSes a valid chained log and reports the head hash', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog(receipts);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBeUndefined(); // success leaves exit code unset (0)
    expect(out).toContain('PASS');
    expect(out).toContain('4 receipts');
    expect(out).toContain(receipts[3].receiptHash!);
    // Precision: without external anchors, tail truncation is not detectable.
    expect(out).toMatch(/tail/i);
  });

  it('FAILs when a line was deleted', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog([receipts[0], receipts[2], receipts[3]]);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toContain('FAIL');
    expect(out).toMatch(/deleted|reordered/i);
  });

  it('FAILs when two lines were reordered', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog([receipts[0], receipts[2], receipts[1], receipts[3]]);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toContain('FAIL');
  });

  it('FAILs on a seq gap', async () => {
    const chain = new ReceiptChain();
    const first = chain.sign(makePayload('1'), TEST_CONFIG);
    const gapPayload = makePayload('2');
    gapPayload.chain = { seq: 5, prevReceiptHash: first.receiptHash! };
    const gapSigned = signReceipt(gapPayload, TEST_CONFIG);
    const file = writeLog([first, { ...gapSigned, receiptHash: computeReceiptHash(gapSigned) }]);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/seq/i);
  });

  it('FAILs on head truncation (log does not start at genesis)', async () => {
    const receipts = makeChainedLog(3);
    const file = writeLog(receipts.slice(1));
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/genesis|head truncation/i);
  });

  it('FAILs when a receipt payload was edited (signature check)', async () => {
    const receipts = makeChainedLog(2);
    const tampered: SignedReceipt = JSON.parse(JSON.stringify(receipts[1]));
    tampered.payload.decision.allowed = false;
    const file = writeLog([receipts[0], tampered]);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/signature/i);
  });

  it('cannot detect tail truncation without expectations — PASSes with an explicit caveat', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog(receipts.slice(0, 3)); // last line silently dropped
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBeUndefined();
    expect(out).toContain('PASS');
    expect(out).toMatch(/tail/i);
  });

  it('detects tail truncation with --expect-count', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog(receipts.slice(0, 3));
    const { out, exitCode } = await run([file, '--expect-count', '4']);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/expected 4/i);
  });

  it('detects tail truncation with --expect-head', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog(receipts.slice(0, 3));
    const { exitCode } = await run([file, '--expect-head', receipts[3].receiptHash!]);
    expect(exitCode).toBe(1);
  });

  it('PASSes with matching --expect-count and --expect-head', async () => {
    const receipts = makeChainedLog(4);
    const file = writeLog(receipts);
    const { out, exitCode } = await run([
      file,
      '--expect-count', '4',
      '--expect-head', receipts[3].receiptHash!,
    ]);
    expect(exitCode).toBeUndefined();
    expect(out).toContain('PASS');
  });

  it('enforces --signer on every receipt', async () => {
    const receipts = makeChainedLog(2);
    const file = writeLog(receipts);
    const ok = await run([file, '--signer', receipts[0].signature.signer]);
    expect(ok.exitCode).toBeUndefined();
    process.exitCode = undefined;
    const bad = await run([file, '--signer', '0x' + '00'.repeat(20)]);
    expect(bad.exitCode).toBe(1);
    expect(bad.out).toMatch(/signature/i);
  });

  it('FAILs a mixed chain-less + chained log by default', async () => {
    const chainless = signReceipt(makePayload('7'), TEST_CONFIG);
    const file = writeLog([chainless, ...makeChainedLog(2)]);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/chain fields/i);
    expect(out).toContain('--allow-unchained');
  });

  it('--allow-unchained tolerates pre-chaining receipts but states the limitation', async () => {
    const chainless = signReceipt(makePayload('7'), TEST_CONFIG);
    const file = writeLog([chainless, ...makeChainedLog(2)]);
    const { out, exitCode } = await run([file, '--allow-unchained']);
    expect(exitCode).toBeUndefined();
    expect(out).toContain('PASS');
    expect(out).toMatch(/1 unchained/i);
    expect(out).toMatch(/not detectable/i);
  });

  it('--allow-unchained still fails on a tampered chain-less receipt', async () => {
    const chainless: SignedReceipt = JSON.parse(JSON.stringify(signReceipt(makePayload('7'), TEST_CONFIG)));
    chainless.payload.decision.score = 0;
    const file = writeLog([chainless, ...makeChainedLog(2)]);
    const { exitCode } = await run([file, '--allow-unchained']);
    expect(exitCode).toBe(1);
  });

  it('rejects malformed --expect-count values as usage errors', async () => {
    const file = writeLog(makeChainedLog(2));
    for (const bad of ['3abc', '3.9', '0x10', '-1', 'NaN']) {
      const { exitCode } = await run([file, '--expect-count', bad]);
      expect(exitCode).toBe(2);
      process.exitCode = undefined;
    }
  });

  it('--allow-unchained does not hide a chain-less receipt inserted mid-chain', async () => {
    const chained = makeChainedLog(3);
    const inserted = signReceipt(makePayload('666'), TEST_CONFIG);
    const file = writeLog([chained[0], inserted, chained[1], chained[2]]);
    const { out, exitCode } = await run([file, '--allow-unchained']);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/inserted or appended/i);
  });

  it('reports original file line numbers even with blank lines in the log', async () => {
    const receipts = makeChainedLog(3);
    const file = path.join(tmpDir, 'blanks.jsonl');
    // Blank line before the receipts and between them: the deleted receipt's
    // successor sits on FILE line 5, not receipt ordinal 2.
    fs.writeFileSync(
      file,
      '\n' +
        JSON.stringify(receipts[0]) +
        '\n\n' +
        JSON.stringify(receipts[2]) + // receipts[1] deleted
        '\n',
    );
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/line 4/);
    expect(out).not.toMatch(/line 2:/);
  });

  it('flags non-receipt lines (e.g. gateway unsigned fallback records) instead of crashing', async () => {
    const receipts = makeChainedLog(2);
    const file = path.join(tmpDir, 'foreign.jsonl');
    fs.writeFileSync(
      file,
      JSON.stringify(receipts[0]) +
        '\n' +
        JSON.stringify({ unsigned: true, decision: 'deny', toolName: 'x', timestamp: 'now' }) +
        '\n' +
        JSON.stringify(receipts[1]) +
        '\n',
    );
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBe(1);
    expect(out).toMatch(/line 2.*malformed-receipt/);
  });

  it('PASSes an empty log but flags that total deletion is undetectable', async () => {
    const file = writeLog([]);
    const { out, exitCode } = await run([file]);
    expect(exitCode).toBeUndefined();
    expect(out).toMatch(/0 receipts/i);
    expect(out).toMatch(/--expect-count/);
  });
});
