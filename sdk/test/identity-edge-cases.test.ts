import {
  permissionsToBitmask,
  validateCumulativeBitEncoding,
} from '../src/identity';
import { Permission } from '../src/types';
import { InvalidPermissionError, InvalidSecretError } from '../src/errors';

// Mock circomlibjs so tests don't need the actual crypto libraries
jest.mock('circomlibjs', () => ({
  buildPoseidon: jest.fn().mockResolvedValue({
    F: {
      toObject: (x: any) => BigInt(x ?? 42),
    },
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

jest.mock('../src/utils', () => ({
  poseidon2: jest.fn().mockResolvedValue(12345n),
  poseidon5: jest.fn().mockResolvedValue(67890n),
  derivePublicKey: jest.fn().mockResolvedValue({ x: 100n, y: 200n }),
  derivePublicKeyScalar: jest.fn().mockResolvedValue({ x: 100n, y: 200n }),
  eddsaSign: jest.fn().mockResolvedValue({
    R8: { x: 1n, y: 2n },
    S: 3n,
  }),
}));

import { createHumanIdentity, createAgentCredential } from '../src/identity';

/** Helper: returns a future timestamp (+1 day) */
const futureTimestamp = () => BigInt(Math.floor(Date.now() / 1000) + 86400);

describe('createHumanIdentity — edge cases', () => {
  it('rejects zero secret with InvalidSecretError', async () => {
    await expect(createHumanIdentity(0n)).rejects.toThrow(InvalidSecretError);
  });

  it('zero secret error has correct code', async () => {
    await expect(createHumanIdentity(0n)).rejects.toMatchObject({
      code: 'INVALID_SECRET',
    });
  });

  it('rejects negative secret', async () => {
    await expect(createHumanIdentity(-1n)).rejects.toThrow(InvalidSecretError);
    await expect(createHumanIdentity(-1n)).rejects.toMatchObject({
      code: 'INVALID_SECRET',
    });
  });

  it('rejects secret at BN254 field order boundary', async () => {
    const fieldOrder =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    await expect(createHumanIdentity(fieldOrder)).rejects.toThrow(
      InvalidSecretError,
    );
  });

  it('rejects secret exceeding BN254 field order', async () => {
    const overField = 2n ** 256n - 1n;
    await expect(createHumanIdentity(overField)).rejects.toThrow(
      InvalidSecretError,
    );
  });

  it('accepts secret just below BN254 field order', async () => {
    const maxValid =
      21888242871839275222246405745257275088548364400416034343698204186575808495616n;
    const identity = await createHumanIdentity(maxValid);
    expect(identity.secret).toBe(maxValid);
    expect(identity.publicKey).toEqual({ x: 100n, y: 200n });
    expect(identity.commitment).toBe(12345n);
  });

  it('accepts secret value of 1n (minimum valid)', async () => {
    const identity = await createHumanIdentity(1n);
    expect(identity.secret).toBe(1n);
    expect(identity.commitment).toBe(12345n);
  });

  it('accepts typical random secret', async () => {
    const secret = 123456789012345678901234567890n;
    const identity = await createHumanIdentity(secret);
    expect(identity.secret).toBe(secret);
    expect(identity.publicKey).toEqual({ x: 100n, y: 200n });
    expect(identity.commitment).toBe(12345n);
  });
});

describe('createAgentCredential — edge cases', () => {
  it('handles zero modelHash', async () => {
    const credential = await createAgentCredential(
      0n,
      42n,
      [Permission.READ_DATA],
      futureTimestamp(),
    );
    expect(credential.modelHash).toBe(0n);
    expect(credential.commitment).toBe(67890n);
  });

  it('handles max modelHash value', async () => {
    const maxHash = 2n ** 254n - 1n;
    const credential = await createAgentCredential(
      maxHash,
      42n,
      [Permission.READ_DATA],
      futureTimestamp(),
    );
    expect(credential.modelHash).toBe(maxHash);
  });

  it('rejects expiryTimestamp of 0 (already expired)', async () => {
    await expect(
      createAgentCredential(111n, 42n, [Permission.READ_DATA], 0n),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('rejects past expiryTimestamp', async () => {
    const pastTs = BigInt(Math.floor(Date.now() / 1000) - 86400);
    await expect(
      createAgentCredential(111n, 42n, [Permission.READ_DATA], pastTs),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('accepts far-future expiryTimestamp', async () => {
    const farFuture = BigInt(Math.floor(Date.now() / 1000) + 86400 * 365 * 100);
    const credential = await createAgentCredential(
      111n,
      42n,
      [Permission.READ_DATA],
      farFuture,
    );
    expect(credential.expiryTimestamp).toBe(farFuture);
  });

  it('handles Buffer operatorPrivateKey', async () => {
    const buf = Buffer.from(
      '000000000000000000000000000000000000000000000000000000000000002a',
      'hex',
    );
    const credential = await createAgentCredential(
      111n,
      buf,
      [Permission.READ_DATA],
      futureTimestamp(),
    );
    expect(credential.operatorPublicKey).toEqual({ x: 100n, y: 200n });
  });

  it('accepts all permissions when cumulative constraint satisfied', async () => {
    const credential = await createAgentCredential(
      111n,
      42n,
      [
        Permission.READ_DATA,
        Permission.WRITE_DATA,
        Permission.FINANCIAL_SMALL,
        Permission.FINANCIAL_MEDIUM,
        Permission.FINANCIAL_UNLIMITED,
        Permission.SIGN_ON_BEHALF,
        Permission.SUB_DELEGATE,
        Permission.ACCESS_PII,
      ],
      futureTimestamp(),
    );
    // bits 0-7 all set = 255
    expect(credential.permissionBitmask).toBe(255n);
  });

  it('accepts single READ_DATA permission', async () => {
    const credential = await createAgentCredential(
      111n,
      42n,
      [Permission.READ_DATA],
      futureTimestamp(),
    );
    expect(credential.permissionBitmask).toBe(1n);
  });
});

describe('permissionsToBitmask — extended', () => {
  it('handles all Permission values individually', () => {
    expect(permissionsToBitmask([Permission.READ_DATA])).toBe(1n);
    expect(permissionsToBitmask([Permission.WRITE_DATA])).toBe(2n);
    expect(permissionsToBitmask([Permission.FINANCIAL_SMALL])).toBe(4n);
    expect(permissionsToBitmask([Permission.FINANCIAL_MEDIUM])).toBe(8n);
    expect(permissionsToBitmask([Permission.FINANCIAL_UNLIMITED])).toBe(16n);
    expect(permissionsToBitmask([Permission.SIGN_ON_BEHALF])).toBe(32n);
    expect(permissionsToBitmask([Permission.SUB_DELEGATE])).toBe(64n);
    expect(permissionsToBitmask([Permission.ACCESS_PII])).toBe(128n);
  });

  it('is commutative (order does not matter)', () => {
    const a = permissionsToBitmask([Permission.READ_DATA, Permission.ACCESS_PII]);
    const b = permissionsToBitmask([Permission.ACCESS_PII, Permission.READ_DATA]);
    expect(a).toBe(b);
  });

  it('is idempotent with repeated values', () => {
    const single = permissionsToBitmask([Permission.SIGN_ON_BEHALF]);
    const repeated = permissionsToBitmask([
      Permission.SIGN_ON_BEHALF,
      Permission.SIGN_ON_BEHALF,
      Permission.SIGN_ON_BEHALF,
    ]);
    expect(single).toBe(repeated);
  });
});

describe('validateCumulativeBitEncoding — exhaustive', () => {
  // All valid combinations involving financial permissions (bits 2, 3, 4)
  const validBitmasks = [
    0n,   // no financial bits
    4n,   // bit 2 only (SMALL)
    12n,  // bits 2 + 3 (SMALL + MEDIUM)
    28n,  // bits 2 + 3 + 4 (SMALL + MEDIUM + UNLIMITED)
  ];

  const invalidBitmasks = [
    8n,   // bit 3 only (MEDIUM without SMALL)
    16n,  // bit 4 only (UNLIMITED without SMALL or MEDIUM)
    24n,  // bits 3 + 4 (MEDIUM + UNLIMITED without SMALL)
    20n,  // bits 2 + 4 (SMALL + UNLIMITED without MEDIUM)
  ];

  it.each(validBitmasks)('accepts valid bitmask %p', (bitmask) => {
    expect(() => validateCumulativeBitEncoding(bitmask)).not.toThrow();
  });

  it.each(invalidBitmasks)('rejects invalid bitmask %p', (bitmask) => {
    expect(() => validateCumulativeBitEncoding(bitmask)).toThrow(
      InvalidPermissionError,
    );
  });

  it('allows non-financial bits regardless of financial state', () => {
    // bits 0,1,5,6,7 without any financial bits
    expect(() => validateCumulativeBitEncoding(0b11100011n)).not.toThrow();
  });

  it('allows non-financial bits combined with valid financial chain', () => {
    // bits 0,1,2,3,4,5,6,7 all set
    expect(() => validateCumulativeBitEncoding(255n)).not.toThrow();
  });

  it('rejects UNLIMITED even with extra non-financial bits if MEDIUM missing', () => {
    // bits 0,1,2,4,5 (missing bit 3)
    expect(() => validateCumulativeBitEncoding(0b00110111n)).toThrow(
      InvalidPermissionError,
    );
  });
});
