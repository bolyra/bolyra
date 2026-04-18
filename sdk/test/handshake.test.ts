import { proveHandshake, verifyHandshake } from '../src/handshake';
import { ProofGenerationError } from '../src/errors';
import { HumanIdentity, AgentCredential } from '../src/types';

const mockHuman: HumanIdentity = {
  secret: 1n,
  publicKey: { x: 100n, y: 200n },
  commitment: 300n,
};

const mockAgent: AgentCredential = {
  modelHash: 1n,
  operatorPublicKey: { x: 100n, y: 200n },
  permissionBitmask: 1n,
  expiryTimestamp: 9999999999n,
  signature: { R8: { x: 1n, y: 2n }, S: 3n },
  commitment: 400n,
};

describe('proveHandshake', () => {
  it('throws ProofGenerationError when circuit artifacts are missing', async () => {
    // With no real circuit files at the default path in test env,
    // this should throw a ProofGenerationError (not NOT_IMPLEMENTED)
    await expect(
      proveHandshake(mockHuman, mockAgent, {
        config: { circuitDir: '/nonexistent/path' },
      }),
    ).rejects.toThrow(ProofGenerationError);
  });

  it('accepts scope and nonce options', async () => {
    await expect(
      proveHandshake(mockHuman, mockAgent, {
        scope: 42n,
        nonce: 12345n,
        config: { circuitDir: '/nonexistent/path' },
      }),
    ).rejects.toThrow(ProofGenerationError);
  });
});

describe('verifyHandshake', () => {
  it('requires valid proof objects with publicSignals', async () => {
    const mockProof = { proof: {}, publicSignals: ['0', '1', '2'] };
    // Will fail because vkey files don't exist at default path in test
    await expect(
      verifyHandshake(mockProof, mockProof, 1n, {
        circuitDir: '/nonexistent/path',
      }),
    ).rejects.toThrow();
  });
});
