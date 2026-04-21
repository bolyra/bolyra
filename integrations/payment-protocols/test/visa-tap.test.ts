import { computeTAPScore } from '../src/visa-tap';
import { encodeSpendPolicy } from '../src/spend-policy';
import type { HandshakeResult, AgentCredential } from '@bolyra/sdk';
import type { SpendPolicy, TAPVerificationRequest } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeHandshake(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    humanNullifier: 123n,
    agentNullifier: 456n,
    sessionNonce: BigInt(Math.floor(Date.now())),
    scopeCommitment: 999n,
    verified: true,
    ...overrides,
  };
}

function makeCredential(overrides: Partial<AgentCredential> = {}): AgentCredential {
  return {
    modelHash: 12345n,
    operatorPublicKey: { x: 1n, y: 2n },
    permissionBitmask: 0b00000111n,
    expiryTimestamp: BigInt(Math.floor(Date.now() / 1000) + 86400),
    signature: { R8: { x: 3n, y: 4n }, S: 5n },
    commitment: 67890n,
    ...overrides,
  };
}

function makeSpendPolicy(overrides: Partial<SpendPolicy> = {}): SpendPolicy {
  const now = Math.floor(Date.now() / 1000);
  return {
    maxTransactionAmount: 50_000,  // $500
    maxCumulativeAmount: 100_000,  // $1,000
    currency: 'USD',
    timeWindow: { start: now, end: now + 86400 },
    ...overrides,
  };
}

function makeRequest(overrides: Partial<TAPVerificationRequest> = {}): TAPVerificationRequest {
  return {
    agentDid: 'did:bolyra:base-sepolia:0000000000000000000000000000000000000000000000000000000000010932',
    merchantId: 'visa-merchant-123',
    amount: 5_000, // $50
    currency: 'USD',
    transactionId: 'txn-abc-123',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// computeTAPScore
// ---------------------------------------------------------------------------

describe('computeTAPScore', () => {
  it('returns 100 for a fully valid verification', () => {
    const handshake = makeHandshake();
    const credential = makeCredential();
    const policy = makeSpendPolicy();
    const request = makeRequest();
    const { score, warnings } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBe(100);
    expect(warnings).toHaveLength(0);
  });

  it('deducts 35 pts for invalid proofs', () => {
    const handshake = makeHandshake({ verified: false });
    const credential = makeCredential();
    const policy = makeSpendPolicy();
    const request = makeRequest();
    const { score } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBe(65);
  });

  it('deducts 25 pts when spend policy is insufficient', () => {
    const handshake = makeHandshake();
    const credential = makeCredential();
    // Policy allows $1 max, request is $50
    const policy = makeSpendPolicy({ maxTransactionAmount: 100 });
    const request = makeRequest({ amount: 50_000 });
    const { score, warnings } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBe(75);
    expect(warnings.some(w => w.includes('Spend policy insufficient'))).toBe(true);
  });

  it('deducts 15 pts for expired credential', () => {
    const handshake = makeHandshake();
    const credential = makeCredential({ expiryTimestamp: 0n });
    const policy = makeSpendPolicy();
    const request = makeRequest();
    const { score, warnings } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBe(85);
    expect(warnings.some(w => w.includes('expired'))).toBe(true);
  });

  it('deducts 10 pts for zero scope commitment', () => {
    const handshake = makeHandshake({ scopeCommitment: 0n });
    const credential = makeCredential();
    const policy = makeSpendPolicy();
    const request = makeRequest();
    const { score } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBe(90);
  });

  it('returns 0 when everything fails', () => {
    const handshake = makeHandshake({
      verified: false,
      scopeCommitment: 0n,
      sessionNonce: 0n,
    });
    const credential = makeCredential({
      expiryTimestamp: 0n,
    });
    const policy = makeSpendPolicy({ maxTransactionAmount: 100 });
    const request = makeRequest({ amount: 100_000 });
    const { score, warnings } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBe(0);
    expect(warnings.length).toBeGreaterThanOrEqual(4);
  });

  it('checks MCC when provided in request', () => {
    const handshake = makeHandshake();
    const credential = makeCredential();
    // Policy restricts to grocery only
    const policy = makeSpendPolicy({
      categoryRestriction: { allowedMCCs: ['5411'] },
    });
    // Request is for a restaurant MCC
    const request = makeRequest({ mcc: '5812' });
    const { warnings } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(warnings.some(w => w.includes('Spend policy insufficient'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: encodeSpendPolicy roundtrip through scoring
// ---------------------------------------------------------------------------

describe('TAP + spend policy integration', () => {
  it('encoded policy satisfies verification for matching amounts', () => {
    const policy = makeSpendPolicy({ maxTransactionAmount: 50_000 });
    const bitmask = encodeSpendPolicy(policy);
    expect(bitmask).toBeGreaterThan(0n);

    // The TAP score should pass for a request within the policy
    const handshake = makeHandshake();
    const credential = makeCredential();
    const request = makeRequest({ amount: 10_000 });
    const { score } = computeTAPScore(handshake, credential, policy, request, 120);
    expect(score).toBeGreaterThanOrEqual(70);
  });
});
