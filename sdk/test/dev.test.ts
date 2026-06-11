// Mock circomlibjs and utils before importing anything that uses them
jest.mock('../src/utils', () => ({
  poseidon2: jest.fn().mockResolvedValue(99999n),
  poseidon5: jest.fn().mockResolvedValue(77777n),
  poseidon3: jest.fn().mockResolvedValue(55555n),
  poseidon4: jest.fn().mockResolvedValue(44444n),
  derivePublicKey: jest.fn().mockResolvedValue({ x: 111n, y: 222n }),
  derivePublicKeyScalar: jest.fn().mockResolvedValue({ x: 333n, y: 444n }),
  eddsaSign: jest.fn().mockResolvedValue({
    R8: { x: 500n, y: 600n },
    S: 700n,
  }),
}));

import { createDevIdentities } from '../src/dev';

describe('createDevIdentities', () => {
  it('returns structurally valid human identity', async () => {
    const { human } = await createDevIdentities();
    expect(typeof human.secret).toBe('bigint');
    expect(human.secret).toBeGreaterThan(0n);
    expect(human.publicKey.x).toBeGreaterThan(0n);
    expect(human.publicKey.y).toBeGreaterThan(0n);
    expect(human.commitment).toBeGreaterThan(0n);
  });

  it('returns structurally valid agent credential', async () => {
    const { agent } = await createDevIdentities();
    expect(typeof agent.modelHash).toBe('bigint');
    expect(agent.operatorPublicKey.x).toBeGreaterThan(0n);
    expect(agent.permissionBitmask).toBe(0b11111111n);
    expect(agent.expiryTimestamp).toBeGreaterThan(0n);
    expect(agent.signature.R8.x).toBeGreaterThan(0n);
    expect(agent.commitment).toBeGreaterThan(0n);
  });

  it('returns operatorKey as Buffer', async () => {
    const { operatorKey } = await createDevIdentities();
    expect(Buffer.isBuffer(operatorKey)).toBe(true);
    expect(operatorKey.length).toBe(32);
  });

  it('is deterministic: calling twice gives same commitments', async () => {
    const first = await createDevIdentities();
    const second = await createDevIdentities();
    expect(first.human.commitment).toBe(second.human.commitment);
    expect(first.agent.commitment).toBe(second.agent.commitment);
  });

  it('accepts permissionBitmask override', async () => {
    const { agent } = await createDevIdentities({ permissionBitmask: 0b01n });
    // permissionBitmask on the result reflects the override
    expect(agent.permissionBitmask).toBe(0b01n);
  });

  it('accepts expiryTimestamp override', async () => {
    const customExpiry = BigInt(Math.floor(Date.now() / 1000) + 9999999);
    const { agent } = await createDevIdentities({ expiryTimestamp: customExpiry });
    expect(agent.expiryTimestamp).toBe(customExpiry);
  });
});
