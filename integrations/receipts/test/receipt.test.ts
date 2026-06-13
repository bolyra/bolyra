import { createAuthReceipt, createCommerceReceipt } from '../src/receipt';
import { signReceipt, verifyReceipt } from '../src/sign';
import type { AuthReceiptInput, CommerceReceiptInput, ReceiptSignerConfig } from '../src/types';

function makeInput(overrides: Partial<AuthReceiptInput> = {}): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:root123',
    actingDid: 'did:bolyra:agent456',
    credentialCommitment: '0xabc',
    effectiveCommitment: '0xdef',
    allowed: true,
    score: 95,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1, 2], pi_b: [[3, 4], [5, 6]], pi_c: [7, 8] } },
    agentProof: { proof: { pi_a: [9, 10], pi_b: [[11, 12], [13, 14]], pi_c: [15, 16] } },
    humanPublicSignals: ['111', '222'],
    agentPublicSignals: ['333', '444'],
    bundleVersion: 1,
    nonce: '12345',
    ...overrides,
  };
}

describe('createAuthReceipt', () => {
  const config = { issuer: 'test-server', keyId: 'key-1' };

  it('creates auth receipt with all fields', () => {
    const payload = createAuthReceipt(makeInput(), config);

    expect(payload.v).toBe(1);
    expect(payload.kind).toBe('bolyra.auth');
    expect(payload.issuer).toBe('test-server');
    expect(payload.keyId).toBe('key-1');
    expect(payload.subject.rootDid).toBe('did:bolyra:root123');
    expect(payload.subject.actingDid).toBe('did:bolyra:agent456');
    expect(payload.decision.allowed).toBe(true);
    expect(payload.decision.score).toBe(95);
    expect(payload.proof.bundleVersion).toBe(1);
    expect(payload.proof.nonce).toBe('12345');
  });

  it('produces SHA-256 hex strings for proof hashes', () => {
    const payload = createAuthReceipt(makeInput(), config);

    // SHA-256 hex strings are 64 chars
    expect(payload.proof.humanProofHash).toMatch(/^[0-9a-f]{64}$/);
    expect(payload.proof.agentProofHash).toMatch(/^[0-9a-f]{64}$/);
    expect(payload.proof.publicSignalsHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('includes delegationChainHash for v=2 with delegation chain', () => {
    const input = makeInput({
      bundleVersion: 2,
      delegationChain: [{ from: 'root', to: 'agent', scope: '0xff' }],
    });
    const payload = createAuthReceipt(input, config);

    expect(payload.proof.delegationChainHash).toBeDefined();
    expect(payload.proof.delegationChainHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('omits delegationChainHash when no delegation chain', () => {
    const payload = createAuthReceipt(makeInput(), config);

    expect(payload.proof.delegationChainHash).toBeUndefined();
  });

  it('includes reasonCode when provided', () => {
    const input = makeInput({ reasonCode: 'PERMISSION_DENIED' });
    const payload = createAuthReceipt(input, config);

    expect(payload.decision.reasonCode).toBe('PERMISSION_DENIED');
  });
});

// ---------------------------------------------------------------------------
// createCommerceReceipt
// ---------------------------------------------------------------------------

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32);
const TEST_SIGNER_CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: TEST_PRIVATE_KEY,
};

function makeCommerceInput(
  overrides: Partial<CommerceReceiptInput> = {},
): CommerceReceiptInput {
  return {
    ...makeInput(),
    commerce: {
      rail: 'x402',
      amount: 5000,
      currency: 'USDC',
      merchant: 'merchant-001',
      intentHash: 'a'.repeat(64),
    },
    ...overrides,
  };
}

describe('createCommerceReceipt', () => {
  const config = { issuer: 'test-server', keyId: 'key-1' };

  it('returns payload with kind=bolyra.commerce', () => {
    const payload = createCommerceReceipt(makeCommerceInput(), config);

    expect(payload.kind).toBe('bolyra.commerce');
    expect(payload.v).toBe(1);
    expect(payload.issuer).toBe('test-server');
  });

  it('includes commerce fields in payload', () => {
    const payload = createCommerceReceipt(makeCommerceInput(), config);

    expect(payload.commerce).toBeDefined();
    expect(payload.commerce!.rail).toBe('x402');
    expect(payload.commerce!.amount).toBe(5000);
    expect(payload.commerce!.currency).toBe('USDC');
    expect(payload.commerce!.merchant).toBe('merchant-001');
    expect(payload.commerce!.intentHash).toBe('a'.repeat(64));
  });

  it('sign + verify round-trip works for commerce receipts', () => {
    const payload = createCommerceReceipt(makeCommerceInput(), config);
    const receipt = signReceipt(payload, TEST_SIGNER_CONFIG);

    expect(receipt.payload.kind).toBe('bolyra.commerce');
    expect(receipt.payload.commerce).toBeDefined();
    expect(verifyReceipt(receipt)).toBe(true);
    expect(verifyReceipt(receipt, receipt.signature.signer)).toBe(true);
  });
});
