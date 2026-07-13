/**
 * `bolyra receipt verify` against REAL signed receipts (the published-schema
 * shape: signer at signature.signer, timestamp at payload.issuedAt seconds).
 *
 * Regression: the command previously read `receipt.signer` (top level) and
 * `payload.timestamp`, so --signer always failed on real receipts ("Got:
 * unknown") and --max-age never applied. Found by the receipt-scoring-kit.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createAuthReceipt, signReceipt } from '@bolyra/receipts';
import type { AuthReceiptInput, ReceiptSignerConfig } from '@bolyra/receipts';
import { main } from '../src/main';

const SIGNER_CONFIG: ReceiptSignerConfig = {
  issuer: 'cli-test',
  keyId: 'k1',
  privateKey: '0x' + '42'.repeat(32),
};

const INPUT: AuthReceiptInput = {
  rootDid: 'did:bolyra:root:test',
  actingDid: 'did:bolyra:agent:test',
  credentialCommitment: '12345',
  effectiveCommitment: '12345',
  allowed: true,
  score: 90,
  permissionBitmask: '1',
  chainDepth: 0,
  humanProof: { proof: { stub: 1 } },
  agentProof: { proof: { stub: 2 } },
  humanPublicSignals: ['1'],
  agentPublicSignals: ['2'],
  bundleVersion: 1,
  nonce: '77',
};

function writeReceipt(issuedAt: number): { file: string; signer: string } {
  const payload = createAuthReceipt(INPUT, {
    issuer: SIGNER_CONFIG.issuer,
    keyId: SIGNER_CONFIG.keyId,
    issuedAt,
  });
  const receipt = signReceipt(payload, SIGNER_CONFIG);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rcpt-')), 'receipt.json');
  fs.writeFileSync(file, JSON.stringify(receipt));
  return { file, signer: receipt.signature.signer };
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a: unknown[]) => out.push(a.join(' '));
  console.error = (...a: unknown[]) => err.push(a.join(' '));
  return {
    out,
    err,
    restore() {
      console.log = origLog;
      console.error = origErr;
    },
  };
}

describe('receipt verify on real signed receipts', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('PASSES with the correct --signer (reads signature.signer)', async () => {
    const { file, signer } = writeReceipt(Math.floor(Date.now() / 1000));
    const cap = capture();
    try {
      await main(['receipt', 'verify', file, '--signer', signer]);
      expect(process.exitCode ?? 0).toBe(0);
      expect(cap.out.join('\n')).toContain('PASS');
      expect(cap.out.join('\n')).toContain(signer);
    } finally {
      cap.restore();
    }
  });

  it('FAILS with a wrong --signer and reports the actual signer', async () => {
    const { file, signer } = writeReceipt(Math.floor(Date.now() / 1000));
    const cap = capture();
    try {
      await main(['receipt', 'verify', file, '--signer', '0x' + 'ab'.repeat(20)]);
      expect(process.exitCode).toBe(1);
      expect(cap.err.join('\n')).toContain('signer mismatch');
      expect(cap.err.join('\n')).toContain(signer); // real signer, not "unknown"
      expect(cap.err.join('\n')).not.toContain('unknown');
    } finally {
      cap.restore();
    }
  });

  it('FAILS a stale receipt via --max-age (reads payload.issuedAt seconds)', async () => {
    const { file } = writeReceipt(Math.floor(Date.now() / 1000) - 7200); // 2h old
    const cap = capture();
    try {
      await main(['receipt', 'verify', file, '--max-age', '3600']);
      expect(process.exitCode).toBe(1);
      expect(cap.err.join('\n')).toContain('too old');
    } finally {
      cap.restore();
    }
  });

  it('PASSES a fresh receipt within --max-age', async () => {
    const { file } = writeReceipt(Math.floor(Date.now() / 1000) - 60);
    const cap = capture();
    try {
      await main(['receipt', 'verify', file, '--max-age', '3600']);
      expect(process.exitCode ?? 0).toBe(0);
      expect(cap.out.join('\n')).toContain('PASS');
    } finally {
      cap.restore();
    }
  });
});
