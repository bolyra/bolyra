/**
 * Receipt scoring test kit — deterministic corpus generator.
 *
 * Emits a committed corpus of signed, hash-chained Bolyra receipts that a
 * third party (counterparty scoring system, auditor) can fetch and verify
 * WITHOUT talking to the issuer. Everything is deterministic: fixed signing
 * keys, fixed timestamps, fixed nonces — signatures are RFC 6979
 * deterministic, so re-running this script reproduces the corpus byte for
 * byte and the head hashes in manifest.json stay stable.
 *
 * ⚠ The private keys below are TEST KEYS, published on purpose so anyone can
 * regenerate the corpus. Never use them (or this pattern of committing keys)
 * for real receipts — production signers pin `receipts.privateKey` from
 * config and publish only the derived address (signer.json).
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  createAuthReceipt,
  createCommerceReceipt,
  ReceiptChain,
  computeReceiptHash,
  type AuthReceiptInput,
  type CommerceReceiptInput,
  type ReceiptSignerConfig,
  type SignedReceipt,
} from '@bolyra/receipts';

// npm scripts always run with cwd = the package dir, which is stable across
// ts-node (src/) and compiled (dist/src/) execution — unlike __dirname.
const CORPUS_DIR = path.resolve(process.cwd(), 'corpus');

// TEST KEYS — intentionally public (see file header). Do not reuse.
const OPERATOR_A: ReceiptSignerConfig = {
  issuer: 'corpus.bolyra.ai',
  keyId: 'test-kit-a-1',
  privateKey: '0x' + '42'.repeat(32),
};
const OPERATOR_B: ReceiptSignerConfig = {
  issuer: 'operator-b.example',
  keyId: 'test-kit-b-1',
  privateKey: '0x' + '77'.repeat(32),
};

// Fixed epoch for the corpus: 2026-07-13T00:00:00Z, one receipt per minute.
const T0 = Date.UTC(2026, 6, 13) / 1000;

/** Deterministic dummy proof material — hashed by createAuthReceipt. */
function proofStub(tag: string) {
  return {
    humanProof: { proof: { pi_a: [tag, '1'], stub: true } },
    agentProof: { proof: { pi_a: [tag, '2'], stub: true } },
    humanPublicSignals: ['11', '12', '13'],
    agentPublicSignals: ['21', '22', '23', '3'],
  };
}

function authInput(overrides: Partial<AuthReceiptInput> & { nonce: string }): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:root:demo-fleet-operator',
    actingDid: 'did:bolyra:agent:research-assistant',
    credentialCommitment: '18446744073709551617',
    effectiveCommitment: '18446744073709551617',
    allowed: true,
    score: 92,
    permissionBitmask: '1', // READ_DATA
    chainDepth: 0,
    bundleVersion: 1,
    ...proofStub(overrides.nonce),
    ...overrides,
  };
}

function writeJsonl(file: string, receipts: SignedReceipt[]): void {
  fs.writeFileSync(file, receipts.map((r) => JSON.stringify(r)).join('\n') + '\n');
}

function signerAddress(config: ReceiptSignerConfig): string {
  // Probe trick (verified-actions-demo audit.ts): sign a throwaway payload
  // and read back the recovered address.
  const probe = createAuthReceipt(authInput({ nonce: '0' }), {
    issuer: config.issuer,
    keyId: config.keyId,
    issuedAt: T0,
  });
  return new ReceiptChain().sign(probe, config).signature.signer;
}

function main(): void {
  fs.mkdirSync(CORPUS_DIR, { recursive: true });

  // ---- Chain A: 8 receipts, one operator, allow/deny/delegated/commerce ----
  const chainA = new ReceiptChain();
  const a: SignedReceipt[] = [];
  const cfg = { issuer: OPERATOR_A.issuer, keyId: OPERATOR_A.keyId };

  const push = (payload: ReturnType<typeof createAuthReceipt>, minute: number) => {
    payload.issuedAt = T0 + minute * 60; // deterministic (commerce path lacks an issuedAt param)
    a.push(chainA.sign(payload, OPERATOR_A));
  };

  push(createAuthReceipt(authInput({ nonce: '1001' }), { ...cfg, issuedAt: T0 }), 0);
  push(
    createAuthReceipt(
      authInput({ nonce: '1002', permissionBitmask: '3', score: 88 }), // READ+WRITE
      { ...cfg, issuedAt: T0 + 60 },
    ),
    1,
  );
  push(
    createAuthReceipt(
      authInput({
        nonce: '1003',
        allowed: false,
        score: 0,
        reasonCode: 'credential_mismatch: bundle claims permissions 111b but the registered credential grants 1b',
      }),
      { ...cfg, issuedAt: T0 + 120 },
    ),
    2,
  );
  push(
    createAuthReceipt(
      authInput({
        nonce: '1004',
        actingDid: 'did:bolyra:agent:sub-task-runner',
        effectiveCommitment: '9007199254740993',
        permissionBitmask: '7', // READ+WRITE+FINANCIAL_SMALL (cumulative-valid)
        chainDepth: 2,
        bundleVersion: 2,
        delegationChain: [
          { delegateeScope: '7', delegateeCommitment: '9007199254740993', delegateeExpiry: String(T0 + 86400) },
          { delegateeScope: '1', delegateeCommitment: '9007199254740995', delegateeExpiry: String(T0 + 3600) },
        ],
        score: 85,
      }),
      { ...cfg, issuedAt: T0 + 180 },
    ),
    3,
  );
  push(
    createAuthReceipt(
      authInput({
        nonce: '1005',
        allowed: false,
        score: 0,
        reasonCode: 'credential_expired: registered credential expired at 1783900800',
      }),
      { ...cfg, issuedAt: T0 + 240 },
    ),
    4,
  );
  const commerceAllow: CommerceReceiptInput = {
    ...authInput({ nonce: '1006', permissionBitmask: '7', score: 90 }),
    commerce: {
      rail: 'x402',
      amount: 42.5,
      currency: 'USDC',
      merchant: 'api.data-vendor.example',
      intentHash: 'c0ffee0000000000000000000000000000000000000000000000000000000001',
    },
  };
  push(createCommerceReceipt(commerceAllow, cfg), 5);
  const commerceDeny: CommerceReceiptInput = {
    ...authInput({
      nonce: '1007',
      allowed: false,
      score: 0,
      reasonCode: 'request_mismatch: amount 500 USDC exceeds FINANCIAL_SMALL tier of the presented mandate',
    }),
    commerce: {
      rail: 'x402',
      amount: 500,
      currency: 'USDC',
      merchant: 'api.data-vendor.example',
      intentHash: 'c0ffee0000000000000000000000000000000000000000000000000000000002',
    },
  };
  push(createCommerceReceipt(commerceDeny, cfg), 6);
  push(
    createAuthReceipt(authInput({ nonce: '1008', permissionBitmask: '7', score: 94 }), {
      ...cfg,
      issuedAt: T0 + 420,
    }),
    7,
  );

  // ---- Chain B: 3 receipts from an independent operator ----
  const chainB = new ReceiptChain();
  const b: SignedReceipt[] = [];
  const cfgB = { issuer: OPERATOR_B.issuer, keyId: OPERATOR_B.keyId };
  for (let i = 0; i < 3; i++) {
    const payload = createAuthReceipt(
      authInput({
        nonce: String(2001 + i),
        rootDid: 'did:bolyra:root:operator-b-fleet',
        actingDid: 'did:bolyra:agent:crawler',
        allowed: i !== 1,
        score: i === 1 ? 0 : 79,
        reasonCode: i === 1 ? 'nonce_replayed: nonce 2002 already consumed' : undefined,
      }),
      { ...cfgB, issuedAt: T0 + 3600 + i * 60 },
    );
    b.push(chainB.sign(payload, OPERATOR_B));
  }

  // ---- Tampered variant: chain A with receipt #3's decision flipped ----
  // The signature no longer matches the payload → verify-chain must FAIL.
  const tampered: SignedReceipt[] = a.map((r) => JSON.parse(JSON.stringify(r)));
  tampered[2].payload.decision.allowed = true;
  delete tampered[2].payload.decision.reasonCode;

  // ---- Emit ----
  writeJsonl(path.join(CORPUS_DIR, 'receipts.jsonl'), a);
  writeJsonl(path.join(CORPUS_DIR, 'operator-b.jsonl'), b);
  writeJsonl(path.join(CORPUS_DIR, 'tampered.jsonl'), tampered);
  fs.writeFileSync(path.join(CORPUS_DIR, 'allow.json'), JSON.stringify(a[0], null, 2) + '\n');
  fs.writeFileSync(path.join(CORPUS_DIR, 'deny.json'), JSON.stringify(a[2], null, 2) + '\n');

  const signerA = a[0].signature.signer;
  const signerB = b[0].signature.signer;
  fs.writeFileSync(
    path.join(CORPUS_DIR, 'signer.json'),
    JSON.stringify({ issuer: OPERATOR_A.issuer, keyId: OPERATOR_A.keyId, alg: 'ES256K', signer: signerA }, null, 2) + '\n',
  );
  fs.writeFileSync(
    path.join(CORPUS_DIR, 'signer-b.json'),
    JSON.stringify({ issuer: OPERATOR_B.issuer, keyId: OPERATOR_B.keyId, alg: 'ES256K', signer: signerB }, null, 2) + '\n',
  );

  const manifest = {
    generatedBy: 'examples/receipt-scoring-kit/src/generate.ts (deterministic)',
    chains: {
      'receipts.jsonl': { signer: signerA, count: a.length, head: computeReceiptHash(a[a.length - 1]) },
      'operator-b.jsonl': { signer: signerB, count: b.length, head: computeReceiptHash(b[b.length - 1]) },
      'tampered.jsonl': { note: 'INTENTIONALLY INVALID — receipt at line 3 was edited after signing' },
    },
  };
  fs.writeFileSync(path.join(CORPUS_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  console.log(JSON.stringify(manifest.chains, null, 2));
}

main();
