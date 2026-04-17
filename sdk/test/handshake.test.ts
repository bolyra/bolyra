import { proveHandshake, verifyHandshake } from '../src/handshake';
import { BolyraError } from '../src/errors';
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
  it('throws NOT_IMPLEMENTED', async () => {
    await expect(proveHandshake(mockHuman, mockAgent)).rejects.toThrow(
      BolyraError,
    );
    await expect(proveHandshake(mockHuman, mockAgent)).rejects.toMatchObject({
      code: 'NOT_IMPLEMENTED',
    });
  });
});

describe('verifyHandshake', () => {
  it('throws NOT_IMPLEMENTED', async () => {
    const mockProof = { proof: {}, publicSignals: [] };
    await expect(
      verifyHandshake(mockProof, mockProof, 1n),
    ).rejects.toMatchObject({
      code: 'NOT_IMPLEMENTED',
    });
  });
});
