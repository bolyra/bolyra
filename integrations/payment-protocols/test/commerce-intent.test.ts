/**
 * Cross-rail commerce authorization tests.
 *
 * 11 tests covering:
 *   - Stripe ACP: allow / deny over cap / deny confirm without SIGN_ON_BEHALF
 *   - x402: allow / deny unverified / deny currency mismatch / deny unresolved credential
 *   - Visa TAP + Google AP2 stub denials
 *   - Uniform decision shape across all 4 rails
 *   - Receipt determinism
 */

import { authorizeCommerceIntent } from '../src/commerce-intent';
import type {
  CommerceAuthorizationInput,
  CommerceAuthorizationDecision,
  CommerceAuthorizationOptions,
  CommerceReceiptEvidence,
  CommerceIntent,
} from '../src/commerce-intent';
import type { ReceiptSignerConfig } from '@bolyra/receipts';
import type {
  StripeACPSpendDecision,
  StripeACPContext,
  TAPVerificationResult,
  AgentPaymentVerification,
} from '../src/types';
import type { X402VerifyDecision } from '../src/x402';

// ---------------------------------------------------------------------------
// Fixed timestamp for deterministic receipts
// ---------------------------------------------------------------------------

const FIXED_TIME = 1_700_000_000;

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeStripeACPContext(
  overrides: Partial<StripeACPContext> = {},
): StripeACPContext {
  return {
    actingAgentDid: 'did:bolyra:base-sepolia:0xabc123',
    rootAgentDid: 'did:bolyra:base-sepolia:0xdef456',
    delegationDepth: 0,
    spendingLimits: {
      maxTransactionAmount: 10_000,
      currency: 'usd',
      financialSmall: true,
      financialMedium: false,
      financialUnlimited: false,
      signOnBehalf: false,
      tier: 'small',
    },
    effectiveScope: '7',
    verified: true,
    score: 95,
    warnings: [],
    ...overrides,
  };
}

function makeStripeSpendDecision(
  overrides: Partial<StripeACPSpendDecision> = {},
): StripeACPSpendDecision {
  return {
    allowed: true,
    capChecked: 10_000,
    tier: 'small',
    ...overrides,
  };
}

function makeX402Decision(
  overrides: Partial<X402VerifyDecision> = {},
): X402VerifyDecision {
  return {
    verified: true,
    score: 100,
    grade: 'A',
    did: 'did:bolyra:base-sepolia:0xdeadbeef',
    scopeCommitment: 12345n,
    sessionNonce: 0xdeadbeefn,
    warnings: [],
    credentialResolved: true,
    currency: 'USDC',
    ...overrides,
  };
}

function makeTAPResult(
  overrides: Partial<TAPVerificationResult> = {},
): TAPVerificationResult {
  return {
    verified: true,
    score: 85,
    grade: 'B',
    did: 'did:bolyra:base-sepolia:0xtap001',
    warnings: [],
    batchMode: false,
    scopeCommitment: 99999n,
    ...overrides,
  };
}

function makeAP2Result(
  overrides: Partial<AgentPaymentVerification> = {},
): AgentPaymentVerification {
  return {
    verified: true,
    score: 80,
    grade: 'B',
    did: 'did:bolyra:base-sepolia:0xap2001',
    warnings: [],
    ...overrides,
  };
}

function intent(rail: CommerceIntent['rail'], currency = 'USD'): CommerceIntent {
  return { rail, amount: 5_000, currency, merchant: 'merchant-001' };
}

// ---------------------------------------------------------------------------
// Stripe ACP
// ---------------------------------------------------------------------------

describe('Stripe ACP rail', () => {
  it('1. allows under cap', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('stripe-acp'), rail: 'stripe-acp' },
      spendDecision: makeStripeSpendDecision({ allowed: true }),
      acpContext: makeStripeACPContext({ score: 95 }),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(true);
    expect(d.did).toBe('did:bolyra:base-sepolia:0xabc123');
    expect(d.score).toBe(95);
    expect(d.grade).toBe('A');
    expect(d.receipt.rail).toBe('stripe-acp');
    expect(d.receipt.allowed).toBe(true);
  });

  it('2. denies over cap', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('stripe-acp'), rail: 'stripe-acp' },
      spendDecision: makeStripeSpendDecision({
        allowed: false,
        reason: 'exceeds small-tier cap',
      }),
      acpContext: makeStripeACPContext(),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('exceeds');
  });

  it('3. denies confirm without SIGN_ON_BEHALF', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('stripe-acp'), rail: 'stripe-acp' },
      spendDecision: makeStripeSpendDecision({
        allowed: false,
        reason: 'confirm requires SIGN_ON_BEHALF (bit 5)',
      }),
      acpContext: makeStripeACPContext(),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('SIGN_ON_BEHALF');
  });
});

// ---------------------------------------------------------------------------
// x402
// ---------------------------------------------------------------------------

describe('x402 rail', () => {
  it('4. allows verified + amount fits', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision({
        verified: true,
        credentialResolved: true,
        currency: 'USDC',
      }),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(true);
    expect(d.did).toBe('did:bolyra:base-sepolia:0xdeadbeef');
    expect(d.score).toBe(100);
  });

  it('5. denies unverified', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision({
        verified: false,
        score: 20,
        grade: 'F',
        warnings: ['zk handshake verify returned false'],
      }),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toBeDefined();
  });

  it('6. denies currency mismatch', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USD'), rail: 'x402' },
      adapterResult: makeX402Decision({
        verified: true,
        credentialResolved: true,
        currency: 'ETH',
      }),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('currency mismatch');
  });

  it('7. denies unresolved credential', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision({
        verified: true,
        credentialResolved: false,
        warnings: ['unresolved did: did:bolyra:base-sepolia:0xdeadbeef'],
      }),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('credential not resolved');
  });
});

// ---------------------------------------------------------------------------
// Stub rails
// ---------------------------------------------------------------------------

describe('stub rails', () => {
  it('8. Visa TAP stub — allowed=false + reason contains "not fully wired"', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('visa-tap'), rail: 'visa-tap' },
      adapterResult: makeTAPResult(),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('not fully wired');
    expect(d.did).toBe('did:bolyra:base-sepolia:0xtap001');
    expect(d.score).toBe(85);
  });

  it('9. Google AP2 stub — allowed=false', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('google-ap2'), rail: 'google-ap2' },
      adapterResult: makeAP2Result(),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('not fully wired');
  });
});

// ---------------------------------------------------------------------------
// Cross-rail properties
// ---------------------------------------------------------------------------

describe('cross-rail properties', () => {
  const EXPECTED_KEYS: (keyof CommerceAuthorizationDecision)[] = [
    'allowed',
    'did',
    'score',
    'grade',
    'warnings',
    'receipt',
  ];

  it('10. uniform shape — all 4 rails return objects with the same keys', () => {
    const stripeInput: CommerceAuthorizationInput = {
      intent: { ...intent('stripe-acp'), rail: 'stripe-acp' },
      spendDecision: makeStripeSpendDecision(),
      acpContext: makeStripeACPContext(),
    };
    const x402Input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision(),
    };
    const tapInput: CommerceAuthorizationInput = {
      intent: { ...intent('visa-tap'), rail: 'visa-tap' },
      adapterResult: makeTAPResult(),
    };
    const ap2Input: CommerceAuthorizationInput = {
      intent: { ...intent('google-ap2'), rail: 'google-ap2' },
      adapterResult: makeAP2Result(),
    };

    const decisions = [stripeInput, x402Input, tapInput, ap2Input].map((i) =>
      authorizeCommerceIntent(i, { issuedAt: FIXED_TIME }),
    );

    for (const d of decisions) {
      for (const key of EXPECTED_KEYS) {
        expect(d).toHaveProperty(key);
      }
      // Receipt must have a deterministic shape
      expect(typeof d.receipt.id).toBe('string');
      expect(d.receipt.id.length).toBe(16);
      expect(typeof d.receipt.intentHash).toBe('string');
      expect(d.receipt.v).toBe(1);
    }
  });

  it('11. receipt determinism — same input + fixed issuedAt → same receipt.id', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision(),
    };

    const d1 = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });
    const d2 = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });

    expect(d1.receipt.id).toBe(d2.receipt.id);
    expect(d1.receipt.intentHash).toBe(d2.receipt.intentHash);

    // Different timestamp → different receipt ID
    const d3 = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME + 1 });
    expect(d3.receipt.id).not.toBe(d1.receipt.id);
  });
});

// ---------------------------------------------------------------------------
// Signed commerce receipts
// ---------------------------------------------------------------------------

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32);

const TEST_SIGNER: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: TEST_PRIVATE_KEY,
};

const TEST_EVIDENCE: CommerceReceiptEvidence = {
  rootDid: 'did:bolyra:root123',
  credentialCommitment: '0xabc',
  effectiveCommitment: '0xdef',
  permissionBitmask: '255',
  chainDepth: 0,
  humanProof: { proof: { pi_a: [1, 2], pi_b: [[3, 4], [5, 6]], pi_c: [7, 8] } },
  agentProof: { proof: { pi_a: [9, 10], pi_b: [[11, 12], [13, 14]], pi_c: [15, 16] } },
  humanPublicSignals: ['111', '222'],
  agentPublicSignals: ['333', '444'],
  bundleVersion: 1,
  nonce: '12345',
};

describe('signed commerce receipts', () => {
  it('12. authorizeCommerceIntent with receiptSigner + receiptEvidence produces signedReceipt', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision(),
    };
    const options: CommerceAuthorizationOptions = {
      issuedAt: FIXED_TIME,
      receiptSigner: TEST_SIGNER,
      receiptEvidence: TEST_EVIDENCE,
    };
    const d = authorizeCommerceIntent(input, options);

    expect(d.signedReceipt).toBeDefined();
    expect(d.signedReceipt!.payload.kind).toBe('bolyra.commerce');
    expect(d.signedReceipt!.payload.commerce).toBeDefined();
    expect(d.signedReceipt!.payload.commerce!.rail).toBe('x402');
    expect(d.signedReceipt!.payload.commerce!.amount).toBe(5_000);
    expect(d.signedReceipt!.payload.commerce!.currency).toBe('USDC');
    expect(d.signedReceipt!.payload.commerce!.merchant).toBe('merchant-001');
    expect(d.signedReceipt!.signature.alg).toBe('ES256K');
  });

  it('13. authorizeCommerceIntent without signer produces no signedReceipt', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('x402', 'USDC'), rail: 'x402' },
      adapterResult: makeX402Decision(),
    };
    const d = authorizeCommerceIntent(input, { issuedAt: FIXED_TIME });

    expect(d.signedReceipt).toBeUndefined();
  });

  it('14. signedReceipt has correct commerce fields matching intent', () => {
    const input: CommerceAuthorizationInput = {
      intent: { ...intent('stripe-acp'), rail: 'stripe-acp' },
      spendDecision: makeStripeSpendDecision(),
      acpContext: makeStripeACPContext(),
    };
    const options: CommerceAuthorizationOptions = {
      issuedAt: FIXED_TIME,
      receiptSigner: TEST_SIGNER,
      receiptEvidence: TEST_EVIDENCE,
    };
    const d = authorizeCommerceIntent(input, options);

    expect(d.signedReceipt).toBeDefined();
    expect(d.signedReceipt!.payload.kind).toBe('bolyra.commerce');
    expect(d.signedReceipt!.payload.commerce!.rail).toBe('stripe-acp');
    expect(d.signedReceipt!.payload.commerce!.merchant).toBe('merchant-001');
    expect(d.signedReceipt!.payload.commerce!.intentHash).toBe(d.receipt.intentHash);
  });
});
