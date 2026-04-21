import {
  encodeSpendPolicy,
  verifySpendPolicyProof,
  decodePermissionTier,
  decodeAmountTier,
  decodeCumulativeTier,
  decodeTimeTier,
  decodeCategoryMask,
  getAmountTiers,
  getTimeWindowTiers,
} from '../src/spend-policy';
import type { SpendPolicy } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePolicy(overrides: Partial<SpendPolicy> = {}): SpendPolicy {
  const now = Math.floor(Date.now() / 1000);
  return {
    maxTransactionAmount: 10_000, // $100
    maxCumulativeAmount: 50_000,  // $500
    currency: 'USD',
    timeWindow: { start: now, end: now + 86400 },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// encodeSpendPolicy
// ---------------------------------------------------------------------------

describe('encodeSpendPolicy', () => {
  it('encodes a basic spend policy into a bigint', () => {
    const policy = makePolicy();
    const bitmask = encodeSpendPolicy(policy);
    expect(typeof bitmask).toBe('bigint');
    expect(bitmask).toBeGreaterThan(0n);
  });

  it('produces different bitmasks for different amounts', () => {
    const small = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 100 }));
    const large = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 1_000_000 }));
    expect(small).not.toBe(large);
  });

  it('encodes permission tier correctly for small amounts', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 500 }));
    expect(decodePermissionTier(bitmask)).toBe(2); // FINANCIAL_SMALL
  });

  it('encodes permission tier correctly for medium amounts', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 50_000 }));
    expect(decodePermissionTier(bitmask)).toBe(3); // FINANCIAL_MEDIUM
  });

  it('encodes permission tier correctly for unlimited amounts', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 1_000_000 }));
    expect(decodePermissionTier(bitmask)).toBe(4); // FINANCIAL_UNLIMITED
  });

  it('encodes zero amount as READ_DATA tier', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 0 }));
    expect(decodePermissionTier(bitmask)).toBe(0);
  });

  it('encodes time window tier', () => {
    const now = Math.floor(Date.now() / 1000);
    // 1-week window
    const bitmask = encodeSpendPolicy(makePolicy({
      timeWindow: { start: now, end: now + 604800 },
    }));
    const timeTier = decodeTimeTier(bitmask);
    expect(timeTier).toBeGreaterThanOrEqual(6); // 604800s = 1 week tier
  });

  it('encodes category restrictions', () => {
    const bitmask = encodeSpendPolicy(makePolicy({
      categoryRestriction: { allowedMCCs: ['5411', '5812'] }, // grocery + restaurants
    }));
    const catMask = decodeCategoryMask(bitmask);
    // Bit 0 (grocery) and bit 1 (restaurants) should be set
    expect(catMask & 0x01).toBe(1); // grocery
    expect(catMask & 0x02).toBe(2); // restaurants
  });

  it('sets all category bits when no restriction', () => {
    const bitmask = encodeSpendPolicy(makePolicy());
    const catMask = decodeCategoryMask(bitmask);
    expect(catMask).toBe(0xFF);
  });

  it('fits within 63 bits (BN254 safe)', () => {
    const bitmask = encodeSpendPolicy(makePolicy({
      maxTransactionAmount: Number.MAX_SAFE_INTEGER,
      maxCumulativeAmount: Number.MAX_SAFE_INTEGER,
      categoryRestriction: { allowedMCCs: ['5411'] },
      vendorRestriction: { merchants: ['merchant-1', 'merchant-2'], mode: 'allow' },
    }));
    expect(bitmask).toBeLessThan(1n << 63n);
  });
});

// ---------------------------------------------------------------------------
// verifySpendPolicyProof
// ---------------------------------------------------------------------------

describe('verifySpendPolicyProof', () => {
  it('satisfies when proven policy exceeds required policy', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 50_000 }));
    const result = verifySpendPolicyProof(bitmask, {
      minTransactionAmount: 10_000,
    });
    expect(result.satisfied).toBe(true);
    expect(result.reasons).toHaveLength(0);
  });

  it('fails when proven amount tier is too low', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 100 }));
    const result = verifySpendPolicyProof(bitmask, {
      minTransactionAmount: 100_000,
    });
    expect(result.satisfied).toBe(false);
    expect(result.reasons.some(r => r.includes('Amount tier'))).toBe(true);
  });

  it('fails when proven permission tier is too low', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxTransactionAmount: 500 }));
    const result = verifySpendPolicyProof(bitmask, {
      minTransactionAmount: 50_000,
    });
    expect(result.satisfied).toBe(false);
    expect(result.reasons.some(r => r.includes('Permission tier'))).toBe(true);
  });

  it('checks cumulative tier', () => {
    const bitmask = encodeSpendPolicy(makePolicy({ maxCumulativeAmount: 1_000 }));
    const result = verifySpendPolicyProof(bitmask, {
      minCumulativeAmount: 500_000,
    });
    expect(result.satisfied).toBe(false);
    expect(result.reasons.some(r => r.includes('Cumulative tier'))).toBe(true);
  });

  it('checks time window tier', () => {
    const now = Math.floor(Date.now() / 1000);
    const bitmask = encodeSpendPolicy(makePolicy({
      timeWindow: { start: now, end: now + 3600 },
    }));
    const result = verifySpendPolicyProof(bitmask, {
      minDurationSeconds: 604800, // 1 week
    });
    expect(result.satisfied).toBe(false);
    expect(result.reasons.some(r => r.includes('Time tier'))).toBe(true);
  });

  it('checks category mask', () => {
    const bitmask = encodeSpendPolicy(makePolicy({
      categoryRestriction: { allowedMCCs: ['5411'] }, // grocery only
    }));
    const result = verifySpendPolicyProof(bitmask, {
      requiredMCCs: ['5812'], // restaurant required
    });
    expect(result.satisfied).toBe(false);
    expect(result.reasons.some(r => r.includes('Category mask'))).toBe(true);
  });

  it('passes with no requirements', () => {
    const bitmask = encodeSpendPolicy(makePolicy());
    const result = verifySpendPolicyProof(bitmask, {});
    expect(result.satisfied).toBe(true);
    expect(result.reasons).toHaveLength(0);
  });

  it('accumulates multiple failure reasons', () => {
    const bitmask = encodeSpendPolicy(makePolicy({
      maxTransactionAmount: 100,
      maxCumulativeAmount: 100,
    }));
    const result = verifySpendPolicyProof(bitmask, {
      minTransactionAmount: 100_000,
      minCumulativeAmount: 500_000,
    });
    expect(result.satisfied).toBe(false);
    expect(result.reasons.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Tier accessors
// ---------------------------------------------------------------------------

describe('tier accessors', () => {
  it('getAmountTiers returns 16 tiers', () => {
    expect(getAmountTiers()).toHaveLength(16);
  });

  it('getTimeWindowTiers returns 16 tiers', () => {
    expect(getTimeWindowTiers()).toHaveLength(16);
  });

  it('amount tiers are monotonically non-decreasing', () => {
    const tiers = getAmountTiers();
    for (let i = 1; i < tiers.length; i++) {
      expect(tiers[i]).toBeGreaterThanOrEqual(tiers[i - 1]);
    }
  });
});
