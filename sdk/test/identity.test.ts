import {
  permissionsToBitmask,
  validateCumulativeBitEncoding,
} from '../src/identity';
import { Permission } from '../src/types';
import { InvalidPermissionError } from '../src/errors';

// Mock circomlibjs so tests don't need the actual crypto libraries
jest.mock('circomlibjs', () => ({
  buildPoseidon: jest.fn().mockResolvedValue({
    F: {
      toObject: (x: any) => BigInt(x ?? 42),
    },
    // Mock poseidon: just return sum of inputs for determinism
    __esModule: true,
  }),
  buildEddsa: jest.fn().mockResolvedValue({
    signPoseidon: jest.fn().mockReturnValue({
      R8: [1n, 2n],
      S: 3n,
    }),
  }),
  buildBabyjub: jest.fn().mockResolvedValue({
    Base8: [1n, 2n],
    mulPointEscalar: jest.fn().mockReturnValue([100n, 200n]),
  }),
}));

// We need to re-mock the utils module since it uses circomlibjs internally
jest.mock('../src/utils', () => ({
  poseidon2: jest.fn().mockResolvedValue(12345n),
  poseidon5: jest.fn().mockResolvedValue(67890n),
  derivePublicKey: jest.fn().mockResolvedValue({ x: 100n, y: 200n }),
  eddsaSign: jest.fn().mockResolvedValue({
    R8: { x: 1n, y: 2n },
    S: 3n,
  }),
}));

import { createHumanIdentity, createAgentCredential } from '../src/identity';

describe('createHumanIdentity', () => {
  it('returns correct shape with secret, publicKey, and commitment', async () => {
    const identity = await createHumanIdentity(42n);

    expect(identity).toEqual({
      secret: 42n,
      publicKey: { x: 100n, y: 200n },
      commitment: 12345n,
    });
  });

  it('preserves the original secret', async () => {
    const secret = 9999999999999n;
    const identity = await createHumanIdentity(secret);
    expect(identity.secret).toBe(secret);
  });
});

describe('createAgentCredential', () => {
  it('returns correct shape with all fields', async () => {
    const credential = await createAgentCredential(
      111n,
      42n,
      [Permission.READ_DATA, Permission.WRITE_DATA],
      1700000000n,
    );

    expect(credential.modelHash).toBe(111n);
    expect(credential.operatorPublicKey).toEqual({ x: 100n, y: 200n });
    expect(credential.permissionBitmask).toBe(3n); // bits 0 + 1
    expect(credential.expiryTimestamp).toBe(1700000000n);
    expect(credential.signature).toEqual({ R8: { x: 1n, y: 2n }, S: 3n });
    expect(credential.commitment).toBe(67890n);
  });

  it('throws on invalid cumulative permissions (MEDIUM without SMALL)', async () => {
    await expect(
      createAgentCredential(
        111n,
        42n,
        [Permission.FINANCIAL_MEDIUM], // bit 3 without bit 2
        1700000000n,
      ),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('throws on invalid cumulative permissions (UNLIMITED without MEDIUM)', async () => {
    await expect(
      createAgentCredential(
        111n,
        42n,
        [Permission.FINANCIAL_SMALL, Permission.FINANCIAL_UNLIMITED], // bit 4 without bit 3
        1700000000n,
      ),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('accepts valid cumulative permissions', async () => {
    const credential = await createAgentCredential(
      111n,
      42n,
      [
        Permission.FINANCIAL_SMALL,
        Permission.FINANCIAL_MEDIUM,
        Permission.FINANCIAL_UNLIMITED,
      ],
      1700000000n,
    );
    // bits 2 + 3 + 4 = 4 + 8 + 16 = 28
    expect(credential.permissionBitmask).toBe(28n);
  });
});

describe('permissionsToBitmask', () => {
  it('returns 0n for empty permissions', () => {
    expect(permissionsToBitmask([])).toBe(0n);
  });

  it('sets correct bits for individual permissions', () => {
    expect(permissionsToBitmask([Permission.READ_DATA])).toBe(1n); // bit 0
    expect(permissionsToBitmask([Permission.WRITE_DATA])).toBe(2n); // bit 1
    expect(permissionsToBitmask([Permission.ACCESS_PII])).toBe(128n); // bit 7
  });

  it('combines multiple permissions', () => {
    const bitmask = permissionsToBitmask([
      Permission.READ_DATA,
      Permission.WRITE_DATA,
      Permission.FINANCIAL_SMALL,
    ]);
    expect(bitmask).toBe(7n); // 1 + 2 + 4
  });

  it('handles duplicate permissions idempotently', () => {
    const bitmask = permissionsToBitmask([
      Permission.READ_DATA,
      Permission.READ_DATA,
    ]);
    expect(bitmask).toBe(1n);
  });
});

describe('validateCumulativeBitEncoding', () => {
  it('passes for valid cumulative encoding', () => {
    expect(() => validateCumulativeBitEncoding(0n)).not.toThrow();
    expect(() => validateCumulativeBitEncoding(7n)).not.toThrow(); // bits 0,1,2
    expect(() => validateCumulativeBitEncoding(28n)).not.toThrow(); // bits 2,3,4
  });

  it('throws when FINANCIAL_MEDIUM set without FINANCIAL_SMALL', () => {
    expect(() => validateCumulativeBitEncoding(8n)).toThrow(
      InvalidPermissionError,
    ); // bit 3 only
  });

  it('throws when FINANCIAL_UNLIMITED set without FINANCIAL_MEDIUM', () => {
    expect(() => validateCumulativeBitEncoding(20n)).toThrow(
      InvalidPermissionError,
    ); // bits 2,4 but not 3
  });

  it('throws when FINANCIAL_UNLIMITED set without FINANCIAL_SMALL', () => {
    expect(() => validateCumulativeBitEncoding(24n)).toThrow(
      InvalidPermissionError,
    ); // bits 3,4 but not 2
  });
});
