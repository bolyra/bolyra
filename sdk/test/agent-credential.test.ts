import { Permission } from '../src/types';
import {
  InvalidPermissionError,
  ExpiredCredentialError,
  InvalidSecretError,
} from '../src/errors';

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

import { createAgentCredential } from '../src/identity';

/** Helper: returns a future timestamp (+1 day) */
const futureTimestamp = () => BigInt(Math.floor(Date.now() / 1000) + 86400);

describe('Agent credential — expired timestamp detection', () => {
  it('rejects past timestamp with InvalidPermissionError', async () => {
    const pastTimestamp = BigInt(Math.floor(Date.now() / 1000) - 86400);
    await expect(
      createAgentCredential(111n, 42n, [Permission.READ_DATA], pastTimestamp),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('rejects current timestamp (not strictly in the future)', async () => {
    // Use a timestamp that's definitely in the past by the time it's evaluated
    const pastTimestamp = BigInt(Math.floor(Date.now() / 1000) - 1);
    await expect(
      createAgentCredential(111n, 42n, [Permission.READ_DATA], pastTimestamp),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('rejects zero timestamp', async () => {
    await expect(
      createAgentCredential(111n, 42n, [Permission.READ_DATA], 0n),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('ExpiredCredentialError is throwable with expired timestamp', () => {
    const pastTimestamp = BigInt(Math.floor(Date.now() / 1000) - 86400);
    const err = new ExpiredCredentialError(pastTimestamp);
    expect(err.code).toBe('CREDENTIAL_EXPIRED');
    expect(err.message).toContain(pastTimestamp.toString());
  });

  it('accepts future timestamp', async () => {
    const ts = futureTimestamp();
    const credential = await createAgentCredential(
      111n,
      42n,
      [Permission.READ_DATA],
      ts,
    );
    expect(credential.expiryTimestamp).toBe(ts);
  });
});

describe('Agent credential — zero modelHash', () => {
  it('accepts zero modelHash without error', async () => {
    const credential = await createAgentCredential(
      0n,
      42n,
      [Permission.READ_DATA],
      futureTimestamp(),
    );
    expect(credential.modelHash).toBe(0n);
    expect(credential.commitment).toBe(67890n);
  });

  it('zero modelHash still produces valid credential structure', async () => {
    const credential = await createAgentCredential(
      0n,
      42n,
      [Permission.READ_DATA, Permission.WRITE_DATA],
      futureTimestamp(),
    );
    expect(credential.operatorPublicKey).toEqual({ x: 100n, y: 200n });
    expect(credential.signature).toEqual({ R8: { x: 1n, y: 2n }, S: 3n });
    expect(credential.permissionBitmask).toBe(3n);
  });
});

describe('Agent credential — permission combinations', () => {
  it('rejects FINANCIAL_UNLIMITED alone', async () => {
    await expect(
      createAgentCredential(
        1n,
        42n,
        [Permission.FINANCIAL_UNLIMITED],
        futureTimestamp(),
      ),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('rejects FINANCIAL_MEDIUM alone', async () => {
    await expect(
      createAgentCredential(
        1n,
        42n,
        [Permission.FINANCIAL_MEDIUM],
        futureTimestamp(),
      ),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('rejects FINANCIAL_MEDIUM + FINANCIAL_UNLIMITED without SMALL', async () => {
    await expect(
      createAgentCredential(
        1n,
        42n,
        [Permission.FINANCIAL_MEDIUM, Permission.FINANCIAL_UNLIMITED],
        futureTimestamp(),
      ),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('rejects FINANCIAL_SMALL + FINANCIAL_UNLIMITED without MEDIUM', async () => {
    await expect(
      createAgentCredential(
        1n,
        42n,
        [Permission.FINANCIAL_SMALL, Permission.FINANCIAL_UNLIMITED],
        futureTimestamp(),
      ),
    ).rejects.toThrow(InvalidPermissionError);
  });

  it('accepts FINANCIAL_SMALL alone', async () => {
    const credential = await createAgentCredential(
      1n,
      42n,
      [Permission.FINANCIAL_SMALL],
      futureTimestamp(),
    );
    expect(credential.permissionBitmask).toBe(4n);
  });

  it('accepts FINANCIAL_SMALL + FINANCIAL_MEDIUM', async () => {
    const credential = await createAgentCredential(
      1n,
      42n,
      [Permission.FINANCIAL_SMALL, Permission.FINANCIAL_MEDIUM],
      futureTimestamp(),
    );
    expect(credential.permissionBitmask).toBe(12n);
  });

  it('accepts full financial chain', async () => {
    const credential = await createAgentCredential(
      1n,
      42n,
      [
        Permission.FINANCIAL_SMALL,
        Permission.FINANCIAL_MEDIUM,
        Permission.FINANCIAL_UNLIMITED,
      ],
      futureTimestamp(),
    );
    expect(credential.permissionBitmask).toBe(28n);
  });

  it('accepts non-financial permissions without any financial permissions', async () => {
    const credential = await createAgentCredential(
      1n,
      42n,
      [
        Permission.READ_DATA,
        Permission.WRITE_DATA,
        Permission.SIGN_ON_BEHALF,
        Permission.SUB_DELEGATE,
        Permission.ACCESS_PII,
      ],
      futureTimestamp(),
    );
    // bits 0,1,5,6,7 = 1+2+32+64+128 = 227
    expect(credential.permissionBitmask).toBe(227n);
  });

  it('accepts SIGN_ON_BEHALF without requiring any financial permissions', async () => {
    const credential = await createAgentCredential(
      1n,
      42n,
      [Permission.SIGN_ON_BEHALF],
      futureTimestamp(),
    );
    expect(credential.permissionBitmask).toBe(32n);
  });

  it('accepts empty permission array (bitmask 0)', async () => {
    const credential = await createAgentCredential(
      1n,
      42n,
      [],
      futureTimestamp(),
    );
    expect(credential.permissionBitmask).toBe(0n);
  });
});
