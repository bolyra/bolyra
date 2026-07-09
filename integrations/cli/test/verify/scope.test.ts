/**
 * Task 7 owns the STRICT-expiry-equality edge and the F1/F2 scope-inflation
 * edges. These tests independently recompute the expected scopeCommitment via
 * the same SDK Poseidon primitives, so the anchor cannot be "verified" against
 * itself.
 */

import { poseidon5, poseidon3 } from '@bolyra/sdk';
import {
  recomputeScopeCommitment,
  assertScopeAnchored,
  subsetOK,
  assertSubset,
  expiryLive,
  assertNotExpired,
  type CredentialPreimage,
} from '../../src/verify/scope';
import { VerifyDenial } from '../../src/verify/verdict';

/** A well-formed credential preimage (bitmask 0b111 = READ|WRITE|FIN_SMALL). */
const CRED: CredentialPreimage = {
  modelHash: 12345678901234567890n,
  opX: 111111111111111111n,
  opY: 222222222222222222n,
  bitmask: 0b111n,
  expiry: 2000000000n,
};

/** Independently derive the expected scopeCommitment (no reuse of scope.ts). */
async function expectedScopeCommitment(
  cred: CredentialPreimage,
): Promise<bigint> {
  const credentialCommitment = await poseidon5(
    cred.modelHash,
    cred.opX,
    cred.opY,
    cred.bitmask,
    cred.expiry,
  );
  return poseidon3(cred.bitmask, credentialCommitment, cred.expiry);
}

describe('expiryLive / assertNotExpired — STRICT', () => {
  const t = 1_700_000_000n;

  it('equality is EXPIRED (strict LessThan)', () => {
    expect(expiryLive(t, t)).toBe(false);
  });

  it('one second before expiry is live', () => {
    expect(expiryLive(t - 1n, t)).toBe(true);
  });

  it('assertNotExpired throws `expired` on equality', () => {
    expect(() => assertNotExpired(t, t)).toThrow(VerifyDenial);
    try {
      assertNotExpired(t, t);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('expired');
    }
  });

  it('assertNotExpired does not throw one second before expiry', () => {
    expect(() => assertNotExpired(t - 1n, t)).not.toThrow();
  });
});

describe('recomputeScopeCommitment / assertScopeAnchored', () => {
  it('recompute matches an independent Poseidon derivation', async () => {
    const expected = await expectedScopeCommitment(CRED);
    const actual = await recomputeScopeCommitment(CRED);
    expect(actual).toBe(expected);
  });

  it('passes for the matching scopeCommitment signal', async () => {
    const signal = await expectedScopeCommitment(CRED);
    await expect(assertScopeAnchored(CRED, signal)).resolves.toBeUndefined();
  });

  it('throws `invalid_proof` for a mismatched signal', async () => {
    const signal = await expectedScopeCommitment(CRED);
    await expect(assertScopeAnchored(CRED, signal + 1n)).rejects.toMatchObject({
      code: 'invalid_proof',
    });
    await expect(assertScopeAnchored(CRED, signal + 1n)).rejects.toBeInstanceOf(
      VerifyDenial,
    );
  });

  it('F2 inflation: inflated bitmask against the honest signal is rejected', async () => {
    // Honest proof signal for the real credential.
    const honestSignal = await expectedScopeCommitment(CRED);
    // Attacker keeps the proof signal but claims an inflated bitmask (255n).
    const inflated: CredentialPreimage = { ...CRED, bitmask: 255n };
    await expect(
      assertScopeAnchored(inflated, honestSignal),
    ).rejects.toMatchObject({ code: 'invalid_proof' });
  });
});

describe('subsetOK / assertSubset', () => {
  it('subsetOK: required ⊆ effective', () => {
    expect(subsetOK(0b1n, 0b11n)).toBe(true);
  });

  it('subsetOK: required ⊄ effective', () => {
    expect(subsetOK(0b10n, 0b01n)).toBe(false);
  });

  it('assertSubset does not throw when required ⊆ effective', () => {
    expect(() => assertSubset(0b1n, 0b11n)).not.toThrow();
  });

  it('assertSubset throws `scope_exceeded` when required ⊄ effective', () => {
    expect(() => assertSubset(0b10n, 0b01n)).toThrow(VerifyDenial);
    try {
      assertSubset(0b10n, 0b01n);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('scope_exceeded');
    }
  });
});
