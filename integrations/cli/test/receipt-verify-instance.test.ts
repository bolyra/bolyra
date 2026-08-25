/**
 * Instance-binding semantics in `bolyra receipt verify` / `verify-chain`
 * (spec/receipt-instance-binding-v1.md §4): the user-facing verifiers MUST
 * additionally call verifyInstanceBinding when the block is present —
 * verifyReceipt() proves only hash+signature, so a signer-issued receipt with
 * a wrong instance.ref passes signature verification and must still FAIL here.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  ReceiptChain,
  computeInstanceRef,
  createCommerceReceipt,
  signReceipt,
} from '@bolyra/receipts';
import type {
  CommerceReceiptInput,
  InstancePreimage,
  ReceiptPayload,
  ReceiptSignerConfig,
  SignedReceipt,
} from '@bolyra/receipts';
import { main } from '../src/main';

const SIGNER_CONFIG: ReceiptSignerConfig = {
  issuer: 'cli-test',
  keyId: 'k1',
  privateKey: '0x' + '42'.repeat(32),
};

const PREIMAGE: InstancePreimage = {
  audience: 'api.merchant.example',
  program: 'mpp',
  capabilities: ['mpp:financial:small'],
  amountUsd: '25',
  decisionAt: '2026-08-25T03:00:00.123Z',
};

function commerceInput(): CommerceReceiptInput {
  return {
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
    commerce: {
      rail: 'mpp',
      amount: 25,
      currency: 'USD',
      merchant: 'api.merchant.example',
      intentHash: 'ab'.repeat(32),
    },
  };
}

function commercePayload(instance?: ReceiptPayload['instance']): ReceiptPayload {
  const payload = createCommerceReceipt(commerceInput(), {
    issuer: SIGNER_CONFIG.issuer,
    keyId: SIGNER_CONFIG.keyId,
  });
  // issuedAt: keep the receipt fresh for the default --max-age window.
  const fresh = { ...payload, issuedAt: Math.floor(Date.now() / 1000) };
  return instance !== undefined ? { ...fresh, instance } : fresh;
}

let tmpDir: string;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rcpt-inst-'));
});

function writeReceipt(receipt: SignedReceipt): string {
  const file = path.join(tmpDir, 'receipt.json');
  fs.writeFileSync(file, JSON.stringify(receipt));
  return file;
}

function writeLog(receipts: SignedReceipt[]): string {
  const file = path.join(tmpDir, 'log.jsonl');
  fs.writeFileSync(file, receipts.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return file;
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a: unknown[]) => out.push(a.map(String).join(' '));
  console.error = (...a: unknown[]) => err.push(a.map(String).join(' '));
  return {
    out,
    err,
    restore() {
      console.log = origLog;
      console.error = origErr;
    },
  };
}

async function runVerify(args: string[]) {
  const cap = capture();
  const prevExit = process.exitCode;
  process.exitCode = undefined;
  try {
    await main(args);
    return { out: cap.out, err: cap.err, exitCode: process.exitCode };
  } finally {
    process.exitCode = prevExit;
    cap.restore();
  }
}

describe('receipt verify — instance binding', () => {
  test('valid instance block: PASS and the ref is reported', async () => {
    const instance = { ref: computeInstanceRef(PREIMAGE), preimage: PREIMAGE };
    const receipt = signReceipt(commercePayload(instance), SIGNER_CONFIG);
    const { out, exitCode } = await runVerify(['receipt', 'verify', writeReceipt(receipt)]);
    expect(exitCode ?? 0).toBe(0);
    expect(out.join('\n')).toContain('PASS');
    expect(out.join('\n')).toContain(instance.ref);
  });

  test('signer-issued WRONG ref: signature valid, command FAILS on instance binding', async () => {
    const wrongRef = computeInstanceRef({ ...PREIMAGE, decisionAt: '2026-08-25T03:00:00.999Z' });
    const receipt = signReceipt(
      commercePayload({ ref: wrongRef, preimage: PREIMAGE }),
      SIGNER_CONFIG,
    );
    const { err, exitCode } = await runVerify(['receipt', 'verify', writeReceipt(receipt)]);
    expect(exitCode).toBe(1);
    expect(err.join('\n')).toMatch(/instance/i);
  });

  test('out-of-domain preimage (display-name audience): FAIL with the domain code', async () => {
    const badPreimage = { ...PREIMAGE, audience: 'Acme Corp' };
    const receipt = signReceipt(
      commercePayload({ ref: 'birv1:' + 'ab'.repeat(32), preimage: badPreimage }),
      SIGNER_CONFIG,
    );
    const { err, exitCode } = await runVerify(['receipt', 'verify', writeReceipt(receipt)]);
    expect(exitCode).toBe(1);
    expect(err.join('\n')).toMatch(/out_of_domain|instance/i);
  });

  test('no instance block: PASS unchanged, no instance line', async () => {
    const receipt = signReceipt(commercePayload(), SIGNER_CONFIG);
    const { out, exitCode } = await runVerify(['receipt', 'verify', writeReceipt(receipt)]);
    expect(exitCode ?? 0).toBe(0);
    expect(out.join('\n')).toContain('PASS');
    expect(out.join('\n')).not.toMatch(/instance/i);
  });
});

describe('receipt verify-chain — instance binding', () => {
  test('a chained log with one wrong-ref receipt FAILS', async () => {
    const chain = new ReceiptChain();
    const good = chain.sign(
      commercePayload({ ref: computeInstanceRef(PREIMAGE), preimage: PREIMAGE }),
      SIGNER_CONFIG,
    );
    const wrongRef = computeInstanceRef({ ...PREIMAGE, amountUsd: '9999.99' });
    const bad = chain.sign(
      commercePayload({ ref: wrongRef, preimage: PREIMAGE }),
      SIGNER_CONFIG,
    );
    const { err, exitCode } = await runVerify([
      'receipt',
      'verify-chain',
      writeLog([good, bad]),
    ]);
    expect(exitCode).toBe(1);
    expect(err.join('\n')).toMatch(/instance/i);
  });

  test('a chained log with valid instance blocks PASSES', async () => {
    const chain = new ReceiptChain();
    const receipts = [
      chain.sign(
        commercePayload({ ref: computeInstanceRef(PREIMAGE), preimage: PREIMAGE }),
        SIGNER_CONFIG,
      ),
      chain.sign(
        commercePayload({ ref: computeInstanceRef(PREIMAGE), preimage: PREIMAGE }),
        SIGNER_CONFIG,
      ),
    ];
    const { exitCode } = await runVerify(['receipt', 'verify-chain', writeLog(receipts)]);
    expect(exitCode ?? 0).toBe(0);
  });
});
