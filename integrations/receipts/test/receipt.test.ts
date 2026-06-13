import { createAuthReceipt } from '../src/receipt';
import type { AuthReceiptInput } from '../src/types';

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
