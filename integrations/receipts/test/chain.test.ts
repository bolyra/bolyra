import { signReceipt, verifyReceipt } from '../src/sign';
import { createAuthReceipt } from '../src/receipt';
import {
  GENESIS_PREV_RECEIPT_HASH,
  ReceiptChain,
  computeReceiptHash,
  verifyReceiptChain,
} from '../src/chain';
import type { AuthReceiptInput, ReceiptPayload, ReceiptSignerConfig, SignedReceipt } from '../src/types';

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32);

const TEST_CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: TEST_PRIVATE_KEY,
};

function makeInput(nonce: string): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:root123',
    actingDid: 'did:bolyra:agent456',
    credentialCommitment: '0xabc',
    effectiveCommitment: '0xdef',
    allowed: true,
    score: 95,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1, 2] } },
    agentProof: { proof: { pi_a: [3, 4] } },
    humanPublicSignals: ['111'],
    agentPublicSignals: ['222'],
    bundleVersion: 1,
    nonce,
  };
}

function makePayload(nonce: string): ReceiptPayload {
  return createAuthReceipt(makeInput(nonce), {
    issuer: TEST_CONFIG.issuer,
    keyId: TEST_CONFIG.keyId,
    issuedAt: 1_700_000_000,
  });
}

/** Build a valid chained log of n receipts. */
function makeChain(n: number): SignedReceipt[] {
  const chain = new ReceiptChain();
  const receipts: SignedReceipt[] = [];
  for (let i = 0; i < n; i++) {
    receipts.push(chain.sign(makePayload(String(1000 + i)), TEST_CONFIG));
  }
  return receipts;
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

describe('ReceiptChain', () => {
  it('genesis receipt has seq 0 and the sentinel prevReceiptHash', () => {
    const [genesis] = makeChain(1);
    expect(genesis.payload.chain).toBeDefined();
    expect(genesis.payload.chain!.seq).toBe(0);
    expect(genesis.payload.chain!.prevReceiptHash).toBe(GENESIS_PREV_RECEIPT_HASH);
    expect(GENESIS_PREV_RECEIPT_HASH).toBe('0x' + '0'.repeat(64));
  });

  it('attaches receiptHash matching computeReceiptHash', () => {
    const [genesis] = makeChain(1);
    expect(genesis.receiptHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(genesis.receiptHash).toBe(computeReceiptHash(genesis));
  });

  it('links each receipt to the previous one', () => {
    const receipts = makeChain(3);
    for (let i = 1; i < receipts.length; i++) {
      expect(receipts[i].payload.chain!.seq).toBe(i);
      expect(receipts[i].payload.chain!.prevReceiptHash).toBe(receipts[i - 1].receiptHash);
    }
  });

  it('chain fields are covered by the ES256K signature', () => {
    const receipts = makeChain(2);
    // Chained receipts verify with the plain per-receipt verifier...
    expect(verifyReceipt(receipts[1])).toBe(true);
    // ...and editing the signed chain fields breaks the signature.
    const tampered = clone(receipts[1]);
    tampered.payload.chain!.seq = 7;
    expect(verifyReceipt(tampered)).toBe(false);
  });

  it('computeReceiptHash ignores the receiptHash envelope field itself', () => {
    const [genesis] = makeChain(1);
    const stripped = clone(genesis);
    delete stripped.receiptHash;
    expect(computeReceiptHash(stripped)).toBe(genesis.receiptHash);
  });

  it('chain-less receipts (no chain fields) still sign and verify — back-compat', () => {
    const receipt = signReceipt(makePayload('999'), TEST_CONFIG);
    expect(receipt.payload.chain).toBeUndefined();
    expect(receipt.receiptHash).toBeUndefined();
    expect(verifyReceipt(receipt)).toBe(true);
  });
});

describe('verifyReceiptChain', () => {
  it('accepts a valid chain', () => {
    const receipts = makeChain(4);
    const result = verifyReceiptChain(receipts);
    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.total).toBe(4);
    expect(result.chained).toBe(4);
    expect(result.unchained).toBe(0);
    expect(result.headHash).toBe(receipts[3].receiptHash);
  });

  it('accepts an empty log (trivially consistent)', () => {
    const result = verifyReceiptChain([]);
    expect(result.ok).toBe(true);
    expect(result.total).toBe(0);
    expect(result.headHash).toBeUndefined();
  });

  it('detects a deleted line (middle of the log)', () => {
    const receipts = makeChain(4);
    const truncated = [receipts[0], receipts[2], receipts[3]]; // line 1 deleted
    const result = verifyReceiptChain(truncated);
    expect(result.ok).toBe(false);
    const codes = result.issues.map((i) => i.code);
    expect(codes).toContain('prev-hash-mismatch');
    expect(codes).toContain('seq-mismatch');
    // The break is reported at the receipt that follows the deletion.
    expect(result.issues.find((i) => i.code === 'prev-hash-mismatch')!.index).toBe(1);
  });

  it('detects two reordered lines', () => {
    const receipts = makeChain(4);
    const reordered = [receipts[0], receipts[2], receipts[1], receipts[3]];
    const result = verifyReceiptChain(reordered);
    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.code === 'prev-hash-mismatch' || i.code === 'seq-mismatch')).toBe(true);
  });

  it('detects a seq gap even when prev hashes were re-linked by a buggy writer', () => {
    // Simulate a writer that skips a sequence number but links hashes correctly.
    const chainA = new ReceiptChain();
    const first = chainA.sign(makePayload('1'), TEST_CONFIG);
    const gapPayload = makePayload('2');
    gapPayload.chain = { seq: 5, prevReceiptHash: first.receiptHash! };
    const gapSigned = signReceipt(gapPayload, TEST_CONFIG);
    const gapped: SignedReceipt[] = [first, { ...gapSigned, receiptHash: computeReceiptHash(gapSigned) }];
    const result = verifyReceiptChain(gapped);
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('seq-mismatch');
  });

  it('detects head truncation (log does not start at genesis)', () => {
    const receipts = makeChain(3);
    const result = verifyReceiptChain(receipts.slice(1)); // genesis deleted
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('genesis-mismatch');
  });

  it('flags a mid-log chain restart distinctly', () => {
    const runA = makeChain(2);
    const runB = makeChain(2); // fresh chain, seq starts at 0 again
    const result = verifyReceiptChain([...runA, ...runB]);
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('chain-restart');
  });

  it('cannot detect tail truncation without external expectations', () => {
    const receipts = makeChain(4);
    const truncated = receipts.slice(0, 3); // last line silently dropped
    const result = verifyReceiptChain(truncated);
    expect(result.ok).toBe(true); // documented limitation
  });

  it('detects tail truncation when expectedCount is provided', () => {
    const receipts = makeChain(4);
    const result = verifyReceiptChain(receipts.slice(0, 3), { expectedCount: 4 });
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('count-mismatch');
  });

  it('detects tail truncation when expectedHeadHash is provided', () => {
    const receipts = makeChain(4);
    const result = verifyReceiptChain(receipts.slice(0, 3), {
      expectedHeadHash: receipts[3].receiptHash,
    });
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('head-hash-mismatch');
  });

  it('accepts the full log when expectedCount and expectedHeadHash match', () => {
    const receipts = makeChain(4);
    const result = verifyReceiptChain(receipts, {
      expectedCount: 4,
      expectedHeadHash: receipts[3].receiptHash,
    });
    expect(result.ok).toBe(true);
  });

  it('rejects mixed chain-less + chained logs by default', () => {
    const chainless = signReceipt(makePayload('7'), TEST_CONFIG);
    const receipts = [chainless, ...makeChain(2)];
    const result = verifyReceiptChain(receipts);
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('missing-chain-fields');
    expect(result.unchained).toBe(1);
    expect(result.chained).toBe(2);
  });

  it('allowUnchained tolerates an unchained PREFIX and still checks all signatures', () => {
    const chainless = signReceipt(makePayload('7'), TEST_CONFIG);
    const receipts = [chainless, ...makeChain(2)];
    const result = verifyReceiptChain(receipts, { allowUnchained: true });
    expect(result.ok).toBe(true);
    expect(result.unchained).toBe(1);

    // A tampered chain-less receipt still fails on its signature.
    const tampered = clone(chainless);
    tampered.payload.decision.score = 0;
    const bad = verifyReceiptChain([tampered, ...makeChain(2)], { allowUnchained: true });
    expect(bad.ok).toBe(false);
    expect(bad.issues.map((i) => i.code)).toContain('signature-invalid');
  });

  it('allowUnchained does NOT hide a chain-less receipt inserted mid-chain', () => {
    // Codex round-1 P1: tolerating unchained receipts anywhere would let an
    // attacker splice any validly signed chain-less receipt INTO a chained
    // log (or append one) without detection. Only a pre-chaining PREFIX is
    // tolerable — after the first chained receipt, every line must chain.
    const chained = makeChain(3);
    const inserted = signReceipt(makePayload('666'), TEST_CONFIG);
    const spliced = [chained[0], inserted, chained[1], chained[2]];
    const result = verifyReceiptChain(spliced, { allowUnchained: true });
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('unchained-after-chained');
    expect(result.issues.find((i) => i.code === 'unchained-after-chained')!.index).toBe(1);
  });

  it('allowUnchained does NOT hide a chain-less receipt appended after the chain', () => {
    const chained = makeChain(2);
    const appended = signReceipt(makePayload('667'), TEST_CONFIG);
    const result = verifyReceiptChain([...chained, appended], { allowUnchained: true });
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('unchained-after-chained');
  });

  it('a fully chain-less log fails by default and passes with allowUnchained', () => {
    const receipts = [signReceipt(makePayload('1'), TEST_CONFIG), signReceipt(makePayload('2'), TEST_CONFIG)];
    expect(verifyReceiptChain(receipts).ok).toBe(false);
    const relaxed = verifyReceiptChain(receipts, { allowUnchained: true });
    expect(relaxed.ok).toBe(true);
    expect(relaxed.chained).toBe(0);
  });

  it('detects tampered signed content via the per-receipt signature', () => {
    const receipts = makeChain(2);
    const tampered = clone(receipts);
    tampered[1].payload.decision.allowed = false;
    const result = verifyReceiptChain(tampered);
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('signature-invalid');
  });

  it('detects a mismatched stored receiptHash', () => {
    const receipts = clone(makeChain(2));
    receipts[0].receiptHash = '0x' + 'ab'.repeat(32);
    const result = verifyReceiptChain(receipts);
    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('receipt-hash-mismatch');
  });

  it('chain linking uses the recomputed hash, so a stripped receiptHash field still verifies', () => {
    const receipts = clone(makeChain(3));
    delete receipts[1].receiptHash; // convenience field removed, chain still checkable
    const result = verifyReceiptChain(receipts);
    expect(result.ok).toBe(true);
  });

  it('reports malformed (non-receipt) entries instead of throwing', () => {
    // Codex round-2 P2: a collected gateway log can contain non-receipt lines
    // (e.g. the tagged `unsigned: true` raw fallback records) — the verifier
    // must flag them as malformed, not crash with a TypeError.
    const receipts = makeChain(2);
    const junk = [
      {} as unknown as SignedReceipt,
      null as unknown as SignedReceipt,
      { unsigned: true, decision: 'deny', toolName: 'x' } as unknown as SignedReceipt,
    ];
    for (const bad of junk) {
      const result = verifyReceiptChain([receipts[0], bad, receipts[1]]);
      expect(result.ok).toBe(false);
      const issue = result.issues.find((i) => i.code === 'malformed-receipt');
      expect(issue).toBeDefined();
      expect(issue!.index).toBe(1);
    }
  });

  it('enforces expectedSigner on every receipt', () => {
    const receipts = makeChain(2);
    expect(verifyReceiptChain(receipts, { expectedSigner: receipts[0].signature.signer }).ok).toBe(true);
    const wrong = verifyReceiptChain(receipts, { expectedSigner: '0x' + '00'.repeat(20) });
    expect(wrong.ok).toBe(false);
    expect(wrong.issues.map((i) => i.code)).toContain('signature-invalid');
  });
});
