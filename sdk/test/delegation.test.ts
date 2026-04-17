import { delegate, verifyDelegation } from '../src/delegation';
import { BolyraError } from '../src/errors';
import { AgentCredential } from '../src/types';

const mockAgent: AgentCredential = {
  modelHash: 1n,
  operatorPublicKey: { x: 100n, y: 200n },
  permissionBitmask: 1n,
  expiryTimestamp: 9999999999n,
  signature: { R8: { x: 1n, y: 2n }, S: 3n },
  commitment: 400n,
};

describe('delegate', () => {
  it('throws NOT_IMPLEMENTED', async () => {
    await expect(delegate(mockAgent, mockAgent, 1n, 0)).rejects.toThrow(
      BolyraError,
    );
    await expect(
      delegate(mockAgent, mockAgent, 1n, 0),
    ).rejects.toMatchObject({
      code: 'NOT_IMPLEMENTED',
    });
  });
});

describe('verifyDelegation', () => {
  it('throws NOT_IMPLEMENTED', async () => {
    const mockProof = { proof: {}, publicSignals: [] };
    await expect(verifyDelegation(mockProof, 1n)).rejects.toMatchObject({
      code: 'NOT_IMPLEMENTED',
    });
  });
});
