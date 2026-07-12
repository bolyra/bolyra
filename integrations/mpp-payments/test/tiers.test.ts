/**
 * Amount → financial-tier mapping (cumulative Permission bits from
 * @bolyra/sdk): FINANCIAL_SMALL < $100, FINANCIAL_MEDIUM < $10,000,
 * FINANCIAL_UNLIMITED otherwise. Boundaries are strict (`<`), matching the
 * tier definitions, and comparison is exact-decimal — no float rounding.
 */

import {
  requiredTierForUsdAmount,
  tierCapability,
  MPP_CAPABILITY_MAP,
  requiredPermissionBits,
} from '../src/tiers';
import { Permission } from '@bolyra/sdk';

describe('requiredTierForUsdAmount', () => {
  test('amounts under $100 require FINANCIAL_SMALL', () => {
    expect(requiredTierForUsdAmount('0')).toBe('small');
    expect(requiredTierForUsdAmount('0.01')).toBe('small');
    expect(requiredTierForUsdAmount('25')).toBe('small');
    expect(requiredTierForUsdAmount('99.99')).toBe('small');
    expect(requiredTierForUsdAmount(99)).toBe('small');
  });

  test('amounts in [$100, $10,000) require FINANCIAL_MEDIUM', () => {
    expect(requiredTierForUsdAmount('100')).toBe('medium');
    expect(requiredTierForUsdAmount('100.00')).toBe('medium');
    expect(requiredTierForUsdAmount('500')).toBe('medium');
    expect(requiredTierForUsdAmount('9999.99')).toBe('medium');
  });

  test('amounts >= $10,000 require FINANCIAL_UNLIMITED', () => {
    expect(requiredTierForUsdAmount('10000')).toBe('unlimited');
    expect(requiredTierForUsdAmount('10000.01')).toBe('unlimited');
    expect(requiredTierForUsdAmount('123456789.42')).toBe('unlimited');
  });

  test('boundary comparison is exact-decimal, not float', () => {
    // 99.99999999999999999999 would round to 100 as a float; as an exact
    // decimal it is < 100 and stays in the small tier.
    expect(requiredTierForUsdAmount('99.99999999999999999999')).toBe('small');
    expect(requiredTierForUsdAmount('9999.99999999999999999999')).toBe('medium');
    // Leading zeros must not confuse the integer-part comparison.
    expect(requiredTierForUsdAmount('0099.50')).toBe('small');
    expect(requiredTierForUsdAmount('000100')).toBe('medium');
  });

  test('malformed and negative amounts throw (fail closed upstream)', () => {
    for (const bad of ['', '-1', '+5', '1e3', 'abc', '1.', '.5', '1.2.3', 'NaN', 'Infinity']) {
      expect(() => requiredTierForUsdAmount(bad)).toThrow();
    }
    expect(() => requiredTierForUsdAmount(-1)).toThrow();
    expect(() => requiredTierForUsdAmount(Number.NaN)).toThrow();
    expect(() => requiredTierForUsdAmount(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => requiredTierForUsdAmount(undefined as unknown as string)).toThrow();
  });
});

describe('tier capabilities', () => {
  test('each tier maps to a namespaced capability token', () => {
    expect(tierCapability('small')).toBe('mpp:financial:small');
    expect(tierCapability('medium')).toBe('mpp:financial:medium');
    expect(tierCapability('unlimited')).toBe('mpp:financial:unlimited');
  });

  test('the built-in capability map covers exactly the three tiers', () => {
    expect(Object.keys(MPP_CAPABILITY_MAP).sort()).toEqual([
      'mpp:financial:medium',
      'mpp:financial:small',
      'mpp:financial:unlimited',
    ]);
  });

  test('requiredPermissionBits resolves capabilities to CUMULATIVE Permission masks', () => {
    const small = 1n << BigInt(Permission.FINANCIAL_SMALL);
    const medium = small | (1n << BigInt(Permission.FINANCIAL_MEDIUM));
    const unlimited = medium | (1n << BigInt(Permission.FINANCIAL_UNLIMITED));
    expect(requiredPermissionBits(['mpp:financial:small'])).toBe(small);
    expect(requiredPermissionBits(['mpp:financial:medium'])).toBe(medium);
    expect(requiredPermissionBits(['mpp:financial:unlimited'])).toBe(unlimited);
  });

  test('unknown capabilities fail closed with unknown_capability', () => {
    expect(() => requiredPermissionBits(['mpp:financial:tiny'])).toThrow(
      expect.objectContaining({ code: 'unknown_capability' }),
    );
  });
});
