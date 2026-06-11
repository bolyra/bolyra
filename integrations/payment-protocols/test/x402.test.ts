/**
 * x402 adapter tests — wire-format + verify gate, no live ZK proving.
 *
 * The ZK proving side requires circuit `.wasm` + `.zkey` artifacts which
 * aren't in CI; covered by sdk integration tests separately. These tests
 * exercise:
 *   - PAYMENT-REQUIRED serialize/parse round-trip
 *   - Wire decode rejects malformed / wrong-version credentials
 *   - verifyX402Authorization composes score correctly across gates
 *   - Header constants match the values the landing page advertises
 */

import {
  X402_BOLYRA_CHALLENGE_HEADER,
  X402_BOLYRA_CREDENTIAL_HEADER,
  X402_PAYMENT_REQUIRED_HEADER,
  X402_WIRE_VERSION,
  serializePaymentRequired,
  parsePaymentRequired,
  verifyX402Authorization,
  type X402PaymentRequirements,
} from '../src/x402';

const REQS: X402PaymentRequirements = {
  chain: 'eip155:84532',
  asset: 'USDC',
  amount: 10_000,
  recipient: '0x000000000000000000000000000000000000beef',
};

function toBase64Url(s: string): string {
  return Buffer.from(s, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function makeBundle(overrides: Record<string, unknown> = {}): string {
  const bundle = {
    v: X402_WIRE_VERSION,
    did: 'did:bolyra:base-sepolia:0xdeadbeef',
    sessionNonce: 'deadbeef',
    scopeCommitment: '12345',
    scopeBitmask: '7',
    humanProof: { proof: { pi_a: ['1'], pi_b: [['1']], pi_c: ['1'] }, publicSignals: ['1'] },
    agentProof: { proof: { pi_a: ['1'], pi_b: [['1']], pi_c: ['1'] }, publicSignals: ['1', '2', '3', '12345'] },
    spendPolicy: { maxTransactionAmount: 50_000, currency: 'USD' },
    ...overrides,
  };
  return toBase64Url(JSON.stringify(bundle));
}

describe('x402 header constants', () => {
  test('match the values the landing page advertises', () => {
    expect(X402_PAYMENT_REQUIRED_HEADER).toBe('PAYMENT-REQUIRED');
    expect(X402_BOLYRA_CHALLENGE_HEADER).toBe('Bolyra-Challenge');
    expect(X402_BOLYRA_CREDENTIAL_HEADER).toBe('Bolyra-Credential');
    expect(X402_WIRE_VERSION).toBe(1);
  });
});

describe('PAYMENT-REQUIRED round-trip', () => {
  test('serialize then parse returns equivalent payload', () => {
    const wire = serializePaymentRequired(REQS);
    const back = parsePaymentRequired(wire);
    expect(back).toEqual(REQS);
  });

  test('parse rejects missing required fields', () => {
    expect(() => parsePaymentRequired(JSON.stringify({ chain: 'x' }))).toThrow();
    expect(() => parsePaymentRequired(JSON.stringify({}))).toThrow();
  });
});

describe('verifyX402Authorization', () => {
  const resolveNone = async () => null;
  const resolveSome = async () => ({
    modelHash: 0n,
    operatorPublicKey: { x: 0n, y: 0n },
    permissionBitmask: 7n,
    expiryTimestamp: 0n,
    signature: { R8: { x: 0n, y: 0n }, S: 0n },
    commitment: 0n,
  });

  test('rejects malformed base64url', async () => {
    const r = await verifyX402Authorization('!!!not-valid!!!', REQS, resolveNone);
    expect(r.verified).toBe(false);
    expect(r.grade).toBe('F');
    expect(r.score).toBe(0);
    expect(r.warnings.length).toBeGreaterThan(0);
  });

  test('rejects wrong wire version', async () => {
    const r = await verifyX402Authorization(makeBundle({ v: 99 }), REQS, resolveNone);
    expect(r.verified).toBe(false);
    expect(r.warnings.join(' ')).toMatch(/wire version/);
  });

  test('rejects missing fields', async () => {
    const r = await verifyX402Authorization(
      makeBundle({ humanProof: undefined }),
      REQS,
      resolveNone,
    );
    expect(r.verified).toBe(false);
    expect(r.warnings.join(' ')).toMatch(/missing required/);
  });

  test('decodes sessionNonce + scopeCommitment from a well-formed bundle', async () => {
    const r = await verifyX402Authorization(makeBundle(), REQS, resolveNone);
    // ZK will fail (stub proofs, no real circuit), but the decode side should still surface these.
    expect(r.sessionNonce).toBe(BigInt('0xdeadbeef'));
    expect(r.scopeCommitment).toBe(12345n);
    expect(r.did).toBe('did:bolyra:base-sepolia:0xdeadbeef');
  });

  test('flags over-cap spend even when other gates would pass', async () => {
    const r = await verifyX402Authorization(
      makeBundle({ spendPolicy: { maxTransactionAmount: 100, currency: 'USD' } }),
      REQS, // amount=10_000 > cap=100
      resolveSome,
    );
    expect(r.verified).toBe(false);
    expect(r.warnings.some((w) => /exceeds spend cap/.test(w))).toBe(true);
  });

  test('score composition: stub-ZK fails (no +60), resolver hits (+20), policy fits (+20) → 40', async () => {
    const r = await verifyX402Authorization(makeBundle(), REQS, resolveSome);
    // ZK can't pass with stub proofs / no real circuit setup → ≤ 40.
    expect(r.score).toBeLessThanOrEqual(40);
    expect(r.verified).toBe(false);
  });

  test('unresolved credential → verified false + credentialResolved false', async () => {
    const r = await verifyX402Authorization(
      makeBundle({ spendPolicy: { maxTransactionAmount: 50_000, currency: 'USDC' } }),
      REQS,
      resolveNone,
    );
    expect(r.verified).toBe(false);
    expect(r.credentialResolved).toBe(false);
    expect(r.warnings.some((w) => /unresolved did/.test(w))).toBe(true);
  });

  test('currency mismatch → verified false + warning', async () => {
    const r = await verifyX402Authorization(
      makeBundle({ spendPolicy: { maxTransactionAmount: 50_000, currency: 'DAI' } }),
      REQS, // asset='USDC'
      resolveSome,
    );
    expect(r.verified).toBe(false);
    expect(r.warnings.some((w) => /currency mismatch/.test(w))).toBe(true);
  });

  test('happy path: credentialResolved is true when resolver returns a credential', async () => {
    const r = await verifyX402Authorization(
      makeBundle({ spendPolicy: { maxTransactionAmount: 50_000, currency: 'USDC' } }),
      REQS,
      resolveSome,
    );
    expect(r.credentialResolved).toBe(true);
  });

  test('currency field is populated from the bundle spend policy', async () => {
    const r = await verifyX402Authorization(
      makeBundle({ spendPolicy: { maxTransactionAmount: 50_000, currency: 'USDC' } }),
      REQS,
      resolveSome,
    );
    expect(r.currency).toBe('USDC');
  });

  test('rejection helper returns credentialResolved false and empty currency', async () => {
    const r = await verifyX402Authorization('!!!not-valid!!!', REQS, resolveNone);
    expect(r.credentialResolved).toBe(false);
    expect(r.currency).toBe('');
  });
});
