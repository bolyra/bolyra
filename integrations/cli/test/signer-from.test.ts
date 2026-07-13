/**
 * --signer-from <url> on `bolyra receipt verify` / `receipt verify-chain`
 * (Receipt Signer Discovery v1, spec/receipt-signer-discovery-v1.md).
 * Fail-closed on transport/schema/unknown-signer; https-only except loopback;
 * with BOTH --signer and --signer-from, both must agree.
 */
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { createAuthReceipt, ReceiptChain, signReceipt } from '@bolyra/receipts';
import type { AuthReceiptInput, ReceiptSignerConfig, SignedReceipt } from '@bolyra/receipts';
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

let tmpDir: string;
let receiptFile: string;
let chainFile: string;
let realSigner: string;

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-from-'));
  const now = Math.floor(Date.now() / 1000);
  const single = signReceipt(
    createAuthReceipt(INPUT, { issuer: 'cli-test', keyId: 'k1', issuedAt: now }),
    SIGNER_CONFIG,
  );
  realSigner = single.signature.signer;
  receiptFile = path.join(tmpDir, 'receipt.json');
  fs.writeFileSync(receiptFile, JSON.stringify(single));

  const chain = new ReceiptChain();
  const receipts: SignedReceipt[] = [];
  for (let i = 0; i < 3; i++) {
    receipts.push(
      chain.sign(
        createAuthReceipt({ ...INPUT, nonce: String(100 + i) }, { issuer: 'cli-test', keyId: 'k1', issuedAt: now }),
        SIGNER_CONFIG,
      ),
    );
  }
  chainFile = path.join(tmpDir, 'chain.jsonl');
  fs.writeFileSync(chainFile, receipts.map((r) => JSON.stringify(r)).join('\n') + '\n');
});

function doc(signer: string) {
  return { v: 1, issuer: 'cli-test', updatedAt: 1783987200, signers: [{ keyId: 'k1', alg: 'ES256K', signer }] };
}

function serve(handler: (res: http.ServerResponse) => void): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => handler(res));
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${port}/.well-known/bolyra-signers.json`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function json(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  const ol = console.log, oe = console.error;
  console.log = (...a: unknown[]) => out.push(a.join(' '));
  console.error = (...a: unknown[]) => err.push(a.join(' '));
  return { out, err, restore() { console.log = ol; console.error = oe; } };
}

describe('receipt verify --signer-from', () => {
  afterEach(() => { process.exitCode = undefined; });

  it('PASSES when the discovery doc lists the real signer (loopback http allowed)', async () => {
    const srv = await serve((res) => json(res, 200, doc(realSigner)));
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', srv.url]);
      expect(process.exitCode ?? 0).toBe(0);
      expect(cap.out.join('\n')).toContain('PASS');
    } finally { cap.restore(); await srv.close(); }
  });

  it('FAILS when the doc does not list the signer', async () => {
    const srv = await serve((res) => json(res, 200, doc('0x' + 'ab'.repeat(20))));
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', srv.url]);
      expect(process.exitCode).toBe(1);
      expect(cap.err.join('\n')).toMatch(/not listed|unknown signer/i);
    } finally { cap.restore(); await srv.close(); }
  });

  it('FAILS closed on malformed discovery documents', async () => {
    const srv = await serve((res) => json(res, 200, { v: 1, signers: [] }));
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', srv.url]);
      expect(process.exitCode).toBe(1);
    } finally { cap.restore(); await srv.close(); }
  });

  it('FAILS closed on non-200', async () => {
    const srv = await serve((res) => json(res, 500, { oops: true }));
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', srv.url]);
      expect(process.exitCode).toBe(1);
    } finally { cap.restore(); await srv.close(); }
  });

  it('FAILS closed on unreachable URL', async () => {
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', 'http://127.0.0.1:1/x.json']);
      expect(process.exitCode).toBe(1);
    } finally { cap.restore(); }
  });

  it('rejects plain http for non-loopback hosts before fetching', async () => {
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', 'http://example.com/signers.json']);
      expect(process.exitCode).toBe(1);
      expect(cap.err.join('\n')).toMatch(/https/i);
    } finally { cap.restore(); }
  });

  it('with BOTH flags: passes when --signer is listed and matches the receipt', async () => {
    const srv = await serve((res) => json(res, 200, doc(realSigner)));
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer', realSigner, '--signer-from', srv.url]);
      expect(process.exitCode ?? 0).toBe(0);
    } finally { cap.restore(); await srv.close(); }
  });

  it('with BOTH flags: fails when --signer is not in the discovery doc', async () => {
    const srv = await serve((res) => json(res, 200, doc('0x' + 'ab'.repeat(20))));
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer', realSigner, '--signer-from', srv.url]);
      expect(process.exitCode).toBe(1);
      expect(cap.err.join('\n')).toMatch(/agree|not listed/i);
    } finally { cap.restore(); await srv.close(); }
  });
});

describe('receipt verify-chain --signer-from', () => {
  afterEach(() => { process.exitCode = undefined; });

  it('PASSES a chain whose signer is listed', async () => {
    const srv = await serve((res) => json(res, 200, doc(realSigner)));
    const cap = capture();
    try {
      await main(['receipt', 'verify-chain', chainFile, '--signer-from', srv.url]);
      expect(process.exitCode ?? 0).toBe(0);
      expect(cap.out.join('\n')).toContain('PASS');
    } finally { cap.restore(); await srv.close(); }
  });

  it('FAILS a chain whose signer is not listed', async () => {
    const srv = await serve((res) => json(res, 200, doc('0x' + 'ab'.repeat(20))));
    const cap = capture();
    try {
      await main(['receipt', 'verify-chain', chainFile, '--signer-from', srv.url]);
      expect(process.exitCode).toBe(1);
    } finally { cap.restore(); await srv.close(); }
  });
});

describe('fail-closed edge cases (Codex round 1)', () => {
  afterEach(() => { process.exitCode = undefined; });

  it('empty --signer-from value fails closed instead of skipping discovery', async () => {
    const cap = capture();
    try {
      await main(['receipt', 'verify', receiptFile, '--signer-from', '']);
      expect(process.exitCode).toBe(1);
    } finally { cap.restore(); }
  });

  it('empty --signer-from value fails closed on verify-chain too', async () => {
    const cap = capture();
    try {
      await main(['receipt', 'verify-chain', chainFile, '--signer-from', '']);
      expect(process.exitCode).toBe(1);
    } finally { cap.restore(); }
  });

  it('verify-chain discovery mode reports (not crashes on) a null JSONL entry', async () => {
    const srv = await serve((res) => json(res, 200, doc(realSigner)));
    const badFile = path.join(tmpDir, 'with-null.jsonl');
    fs.writeFileSync(badFile, fs.readFileSync(chainFile, 'utf8') + 'null\n');
    const cap = capture();
    try {
      await main(['receipt', 'verify-chain', badFile, '--signer-from', srv.url]);
      expect(process.exitCode).toBe(1);
      expect(cap.err.join('\n')).toMatch(/FAIL/);
    } finally { cap.restore(); await srv.close(); }
  });
});
