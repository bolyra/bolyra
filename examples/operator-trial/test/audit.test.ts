import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { verifyReceipt, verifyReceiptChain } from '@bolyra/receipts';
import type { AuthReceiptInput } from '@bolyra/receipts';
import { Audit, AuditWriteError } from '../src/audit';
import type { FinalizeInput } from '../src/audit';
import { buildGatewayConfig } from '../src/gateway-config';
import { createDemoAgent } from '../src/agents';

function tmp(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'trial-audit-')), 'run');
}

function gatewayConfig() {
  return buildGatewayConfig('refund', 2n, createDemoAgent('g', 2n), createDemoAgent('w', 1n));
}

function input(reason: string, nonce: string): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:dev:test',
    actingDid: 'did:bolyra:dev:test',
    credentialCommitment: '1',
    effectiveCommitment: '1',
    allowed: true,
    reasonCode: reason,
    score: 100,
    permissionBitmask: '2',
    chainDepth: 0,
    humanProof: { proof: [] },
    agentProof: { proof: [] },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 1,
    nonce,
  };
}

function finalizeInput(overrides: Partial<FinalizeInput> = {}): FinalizeInput {
  return {
    attemptsOk: true,
    attempts: [],
    dispatchCounts: [1, 0, 0],
    dryRun: true,
    action: { name: 'refund', method: 'POST', host: '127.0.0.1:1', path: '/x' },
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    secrets: [],
    ...overrides,
  };
}

test('records a verifiable chain and writes the bundle', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  assert.ok(fs.existsSync(path.join(dir, 'signer.json')));
  const signerJson = JSON.parse(fs.readFileSync(path.join(dir, 'signer.json'), 'utf8'));
  assert.equal(signerJson.ephemeral, true);
  assert.equal(signerJson.signer, audit.signerInfo.signer);

  const r1 = audit.record(input('allowed', '1'));
  const r2 = audit.record(input('denied', '2'));
  assert.ok(verifyReceipt(r1, audit.signerInfo.signer));
  assert.ok(verifyReceipt(r2, audit.signerInfo.signer));

  const fin = audit.finalize(finalizeInput());
  assert.equal(fin.ok, true);
  assert.equal(fin.receiptCount, 2);
  const chain = verifyReceiptChain(audit.readReceipts(), { expectedSigner: audit.signerInfo.signer, expectedCount: 2 });
  assert.equal(chain.ok, true);
  assert.equal(fin.headReceiptHash, chain.headHash);
  const verify = fs.readFileSync(path.join(dir, 'VERIFY.txt'), 'utf8');
  assert.match(verify, /npx @bolyra\/cli@0\.9\.0 receipt verify-chain \.\/receipts\.jsonl/);
  assert.match(verify, new RegExp(`--signer ${audit.signerInfo.signer}`));
  assert.match(verify, /--expect-count 2/);
  assert.match(verify, new RegExp(`--expect-head ${chain.headHash}`));
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.receiptCount, 2);
  assert.equal(summary.note, 'unsigned observations; signer key is ephemeral');
});

test('refuses to start in an existing run directory (EEXIST reservation)', () => {
  const dir = tmp();
  fs.mkdirSync(dir, { recursive: true });
  assert.throws(() => new Audit({ runDir: dir, gatewayConfig: gatewayConfig() }), /already exists/);
});

test('constructor write failure removes the directory it reserved', () => {
  const dir = tmp();
  assert.throws(
    () =>
      new Audit({
        runDir: dir,
        gatewayConfig: gatewayConfig(),
        io: {
          writeFileSync() {
            throw new Error('read-only filesystem');
          },
        },
      }),
    /read-only filesystem/,
  );
  assert.equal(fs.existsSync(dir), false);
});

test('VERIFY.txt write failure leaves no ok:true summary behind', () => {
  const dir = tmp();
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      writeFileSync(p, data) {
        if (p.endsWith('VERIFY.txt')) throw new Error('disk full');
        fs.writeFileSync(p, data);
      },
    },
  });
  audit.record(input('allowed', '1'));
  const fin = audit.finalize(finalizeInput());
  assert.equal(fin.ok, false);
  assert.match(fin.reason ?? '', /disk full/);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
  assert.equal(fs.existsSync(path.join(dir, 'summary.json.tmp')), false);
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8'));
  assert.equal(summary.ok, false);
  assert.match(summary.finalizeError, /disk full/);
});

test('a partially written summary temp file never survives', () => {
  const dir = tmp();
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      writeFileSync(p, data) {
        if (p.endsWith('summary.json.tmp')) {
          fs.writeFileSync(p, data.slice(0, 10));
          throw new Error('disk full');
        }
        fs.writeFileSync(p, data);
      },
    },
  });
  audit.record(input('allowed', '1'));
  const fin = audit.finalize(finalizeInput());
  assert.equal(fin.ok, false);
  assert.equal(fs.existsSync(path.join(dir, 'summary.json')), false);
  assert.equal(fs.existsSync(path.join(dir, 'summary.json.tmp')), false);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
});

test('secret-free corrupted chain: directory retained, no summary, no VERIFY', () => {
  const dir = tmp();
  let calls = 0;
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        calls += 1;
        // Second line: rewrite the reason inside the signed payload so the
        // signature no longer matches and the chain fails verification.
        fs.appendFileSync(p, calls === 2 ? data.replace('"reasonCode":"denied"', '"reasonCode":"edited"') : data);
      },
    },
  });
  audit.record(input('allowed', '1'));
  audit.record(input('denied', '2'));
  const fin = audit.finalize(finalizeInput());
  assert.equal(fin.ok, false);
  assert.match(fin.reason ?? '', /chain failed verification/);
  assert.ok(fs.existsSync(dir));
  assert.equal(fs.existsSync(path.join(dir, 'summary.json')), false);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
});

test('a needle that first appears in summary.json is caught by the second scan', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  audit.record(input('allowed', '1'));
  const startedAt = '2026-09-13T00:00:00.000Z';
  // Not present in any file before finalize; written into summary.json by it.
  const fin = audit.finalize(finalizeInput({ startedAt, secrets: [startedAt] }));
  assert.equal(fin.ok, false);
  assert.match(fin.reason ?? '', /summary\.json/);
  assert.equal(fs.existsSync(dir), false);
});

test('partial append failure rolls back to the committed prefix and breaks the chain (spec test 11)', () => {
  const dir = tmp();
  let calls = 0;
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        calls += 1;
        if (calls === 2) {
          fs.appendFileSync(p, data.slice(0, Math.floor(data.length / 2)));
          throw new Error('disk full');
        }
        fs.appendFileSync(p, data);
      },
    },
  });
  audit.record(input('allowed', '1'));
  assert.throws(() => audit.record(input('denied', '2')), (e: unknown) => e instanceof AuditWriteError && /disk full/.test(e.message));
  assert.equal(audit.fileState, 'broken');
  assert.throws(() => audit.record(input('denied', '3')), /chain broken by earlier write failure/);
  const receipts = audit.readReceipts();
  assert.equal(receipts.length, 1);
  const fin = audit.finalize(finalizeInput({ attemptsOk: false }));
  assert.equal(fin.ok, false);
  assert.equal(fin.receiptCount, 1);
  assert.match(fs.readFileSync(path.join(dir, 'VERIFY.txt'), 'utf8'), /--expect-count 1/);
});

test('readBackLast returns the persisted receipt, not the in-memory one', () => {
  const dir = tmp();
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        // Corrupt the persisted line without throwing.
        fs.appendFileSync(p, data.replace('"allowed":true', '"allowed":false'));
      },
    },
  });
  const inMemory = audit.record(input('allowed', '1'));
  const persisted = audit.readBackLast();
  assert.ok(persisted);
  assert.equal(persisted!.payload.decision.allowed, false);
  assert.equal(inMemory.payload.decision.allowed, true);
  assert.equal(verifyReceipt(persisted!, audit.signerInfo.signer), false);
});

test('abort scans and deletes on a hit, keeps a clean directory', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  audit.record(input('allowed', '1'));
  audit.abort([]);
  assert.ok(fs.existsSync(dir));
  audit.record(input('allowed sekrit-abc', '2'));
  audit.abort(['sekrit-abc']);
  assert.equal(fs.existsSync(dir), false);
});

test('a secret already on disk is caught by the initial scan even when the chain is also broken', () => {
  const dir = tmp();
  let calls = 0;
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        calls += 1;
        // Second line: flip a signature byte so the chain fails verification.
        fs.appendFileSync(p, calls === 2 ? data.replace(/"value":"0x[0-9a-f]{2}/, (m) => m.slice(0, -2) + '00') : data);
      },
    },
  });
  audit.record(input('allowed', '1'));
  audit.record(input('denied sekrit-q', '2'));
  const fin = audit.finalize(finalizeInput({ secrets: ['sekrit-q'] }));
  assert.equal(fin.ok, false);
  assert.equal(fs.existsSync(dir), false);
});

test('failed truncate marks the file unverifiable; finalize does not parse it (spec test 13)', () => {
  const dir = tmp();
  let calls = 0;
  const audit = new Audit({
    runDir: dir,
    gatewayConfig: gatewayConfig(),
    io: {
      appendFileSync(p, data) {
        calls += 1;
        if (calls === 2) {
          fs.appendFileSync(p, data.slice(0, 10));
          throw new Error('disk full');
        }
        fs.appendFileSync(p, data);
      },
      truncateSync() {
        throw new Error('truncate failed');
      },
    },
  });
  audit.record(input('allowed', '1'));
  assert.throws(() => audit.record(input('denied', '2')), AuditWriteError);
  assert.equal(audit.fileState, 'unverifiable');
  const fin = audit.finalize(finalizeInput({ attemptsOk: false }));
  assert.equal(fin.ok, false);
  assert.equal(fin.receiptCount, null);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8'));
  assert.equal(summary.fileState, 'unverifiable');
  assert.equal(summary.ok, false);
  assert.equal(summary.receiptCount, null);
});

test('zero receipts: failure summary, no VERIFY.txt (spec test 10)', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  const fin = audit.finalize(finalizeInput({ attemptsOk: false }));
  assert.equal(fin.ok, false);
  assert.equal(fin.receiptCount, 0);
  assert.equal(fs.existsSync(path.join(dir, 'VERIFY.txt')), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8')).receiptCount, 0);
});

test('secret scan deletes the directory on a hit', () => {
  const dir = tmp();
  const audit = new Audit({ runDir: dir, gatewayConfig: gatewayConfig() });
  audit.record(input('allowed sekrit-xyz', '1'));
  const fin = audit.finalize(finalizeInput({ secrets: ['sekrit-xyz'] }));
  assert.equal(fin.ok, false);
  assert.match(fin.reason ?? '', /receipts\.jsonl/);
  assert.equal(fs.existsSync(dir), false);
});
