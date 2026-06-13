import { signReceipt, verifyReceipt, hashPayload } from '../src/sign';
import { createAuthReceipt } from '../src/receipt';
import type { AuthReceiptInput, ReceiptPayload, ReceiptSignerConfig } from '../src/types';

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32); // 0x0101...01

const TEST_CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: TEST_PRIVATE_KEY,
};

function makeInput(): AuthReceiptInput {
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
  };
}

function makePayload(): ReceiptPayload {
  return createAuthReceipt(makeInput(), { issuer: TEST_CONFIG.issuer, keyId: TEST_CONFIG.keyId });
}

describe('signReceipt + verifyReceipt', () => {
  it('sign + verify round-trip passes', () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, TEST_CONFIG);

    expect(receipt.id).toBeDefined();
    expect(receipt.signature.alg).toBe('ES256K');
    expect(receipt.signature.signer).toMatch(/^0x[0-9a-f]{40}$/);
    expect(receipt.signature.payloadHash).toMatch(/^0x[0-9a-f]{64}$/);
    // 65 bytes = 130 hex chars + 0x prefix
    expect(receipt.signature.value).toMatch(/^0x[0-9a-f]{130}$/);

    expect(verifyReceipt(receipt)).toBe(true);
    expect(verifyReceipt(receipt, receipt.signature.signer)).toBe(true);
  });

  it('verify with wrong expectedSigner returns false', () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, TEST_CONFIG);
    const wrongSigner = '0x' + '00'.repeat(20);

    expect(verifyReceipt(receipt, wrongSigner)).toBe(false);
  });

  it('verify with tampered payload returns false', () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, TEST_CONFIG);

    // Tamper with the payload
    receipt.payload.decision.score = 0;

    expect(verifyReceipt(receipt)).toBe(false);
  });

  it('receipt ID is first 16 hex chars of payload hash', () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, TEST_CONFIG);

    // id = '0x' + payloadHash.slice(2, 18)
    expect(receipt.id).toBe('0x' + receipt.signature.payloadHash.slice(2, 18));
    // 0x + 16 hex chars = 18 chars total
    expect(receipt.id).toHaveLength(18);
  });

  it('receipt ID is deterministic (same input -> same ID)', () => {
    const payload = makePayload();
    const receipt1 = signReceipt(payload, TEST_CONFIG);
    const receipt2 = signReceipt(payload, TEST_CONFIG);

    expect(receipt1.id).toBe(receipt2.id);
    expect(receipt1.signature.payloadHash).toBe(receipt2.signature.payloadHash);
  });
});

describe('hashPayload', () => {
  it('returns keccak256 hex of canonical JSON payload', () => {
    const payload = makePayload();
    const hash = hashPayload(payload);

    expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('matches payloadHash from signReceipt', () => {
    const payload = makePayload();
    const hash = hashPayload(payload);
    const receipt = signReceipt(payload, TEST_CONFIG);

    expect(hash).toBe(receipt.signature.payloadHash);
  });
});
