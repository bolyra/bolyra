/**
 * Spend Policy Encoding & Verification
 *
 * Encodes human-readable spend policies into Bolyra's permission bitmask format
 * for ZKP circuit consumption. The encoded policy becomes a private input to the
 * AgentPolicy circuit — the verifier learns only that the policy is satisfied,
 * never the actual limits.
 *
 * Encoding scheme (fits in a single 253-bit BN254 scalar):
 *   Bits  0-2:   Base permission tier (from Bolyra Permission enum)
 *   Bits  3-6:   Amount tier (log-scale encoding of maxTransactionAmount)
 *   Bits  7-10:  Cumulative tier (log-scale encoding of maxCumulativeAmount)
 *   Bits 11-14:  Time window tier (duration bucket)
 *   Bits 15-22:  Category mask (top-8 MCC groups)
 *   Bits 23-30:  Vendor hash prefix (first 8 bits of Poseidon hash of vendor list)
 *   Bits 31-62:  Reserved for future extensions
 */

import type { SpendPolicy, CategoryRestriction, VendorRestriction, TimeWindow } from './types';

// ---------------------------------------------------------------------------
// Amount Tier Encoding (log-scale, 4 bits = 16 tiers)
// ---------------------------------------------------------------------------

/** Amount tiers in minor units (cents). Each tier is roughly 3x the previous. */
const AMOUNT_TIERS = [
  0,          // 0: zero
  100,        // 1: $1
  500,        // 2: $5
  1_000,      // 3: $10
  2_500,      // 4: $25
  5_000,      // 5: $50
  10_000,     // 6: $100
  25_000,     // 7: $250
  50_000,     // 8: $500
  100_000,    // 9: $1,000
  250_000,    // 10: $2,500
  500_000,    // 11: $5,000
  1_000_000,  // 12: $10,000
  2_500_000,  // 13: $25,000
  5_000_000,  // 14: $50,000
  Number.MAX_SAFE_INTEGER, // 15: unlimited
];

/** Time window tiers (seconds) */
const TIME_WINDOW_TIERS = [
  0,          // 0: instant (single transaction)
  3600,       // 1: 1 hour
  14400,      // 2: 4 hours
  43200,      // 3: 12 hours
  86400,      // 4: 1 day
  259200,     // 5: 3 days
  604800,     // 6: 1 week
  1209600,    // 7: 2 weeks
  2592000,    // 8: 30 days
  7776000,    // 9: 90 days
  15552000,   // 10: 180 days
  31536000,   // 11: 1 year
  63072000,   // 12: 2 years
  Number.MAX_SAFE_INTEGER, // 13-15: unlimited
  Number.MAX_SAFE_INTEGER,
  Number.MAX_SAFE_INTEGER,
];

/**
 * Top-8 MCC groups for the category bitmask.
 * Each bit represents a broad merchant category group.
 */
const MCC_GROUPS: Record<string, number> = {
  // Bit 0: Grocery & food
  '5411': 0, '5422': 0, '5441': 0, '5451': 0, '5462': 0,
  // Bit 1: Restaurants & dining
  '5812': 1, '5813': 1, '5814': 1,
  // Bit 2: Travel & transportation
  '3000': 2, '3001': 2, '4111': 2, '4112': 2, '4121': 2, '4131': 2, '7011': 2,
  // Bit 3: Gas & automotive
  '5541': 3, '5542': 3, '5571': 3, '7531': 3,
  // Bit 4: Retail & shopping
  '5200': 4, '5311': 4, '5691': 4, '5699': 4,
  // Bit 5: Digital services & subscriptions
  '5815': 5, '5816': 5, '5817': 5, '5818': 5,
  // Bit 6: Healthcare & pharmacy
  '5912': 6, '8011': 6, '8021': 6, '8031': 6, '8041': 6,
  // Bit 7: Utilities & telecom
  '4812': 7, '4813': 7, '4814': 7, '4899': 7,
};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/**
 * Find the tier index for a given amount.
 * Returns the highest tier whose threshold is <= the amount.
 */
function amountToTier(amount: number, tiers: number[]): number {
  let tier = 0;
  for (let i = 0; i < tiers.length; i++) {
    if (amount >= tiers[i]) {
      tier = i;
    } else {
      break;
    }
  }
  return tier;
}

/**
 * Derive the base permission tier from the max transaction amount.
 * Maps to Bolyra's Permission enum financial tiers.
 */
function derivePermissionTier(maxTransactionAmount: number): number {
  if (maxTransactionAmount >= 1_000_000) return 4; // FINANCIAL_UNLIMITED
  if (maxTransactionAmount >= 10_000) return 3;    // FINANCIAL_MEDIUM
  if (maxTransactionAmount > 0) return 2;          // FINANCIAL_SMALL
  return 0;                                        // READ_DATA only
}

/**
 * Encode an MCC category restriction into an 8-bit mask.
 */
function encodeCategoryMask(restriction?: CategoryRestriction): number {
  if (!restriction || restriction.allowedMCCs.length === 0) {
    return 0xFF; // all categories allowed
  }
  let mask = 0;
  for (const mcc of restriction.allowedMCCs) {
    const group = MCC_GROUPS[mcc];
    if (group !== undefined) {
      mask |= (1 << group);
    }
  }
  return mask & 0xFF;
}

/**
 * Encode a vendor restriction into an 8-bit hash prefix.
 * Uses a simple hash of the sorted merchant IDs.
 */
function encodeVendorHash(restriction?: VendorRestriction): number {
  if (!restriction || restriction.merchants.length === 0) {
    return 0xFF; // no vendor restriction
  }
  const sorted = [...restriction.merchants].sort();
  let hash = 0;
  for (const merchant of sorted) {
    for (let i = 0; i < merchant.length; i++) {
      hash = ((hash << 5) - hash + merchant.charCodeAt(i)) & 0xFFFFFFFF;
    }
  }
  // Take first 8 bits
  return (hash >>> 24) & 0xFF;
}

/**
 * Encode a spend policy into Bolyra's permission bitmask format.
 *
 * The resulting bigint can be used as the `permissionBitmask` field in an
 * AgentCredential, or as a private input to the AgentPolicy circuit.
 *
 * @param policy - The spend policy to encode
 * @returns The encoded permission bitmask (fits in 63 bits)
 */
export function encodeSpendPolicy(policy: SpendPolicy): bigint {
  const permissionTier = derivePermissionTier(policy.maxTransactionAmount);
  const amountTier = amountToTier(policy.maxTransactionAmount, AMOUNT_TIERS);
  const cumulativeTier = amountToTier(policy.maxCumulativeAmount, AMOUNT_TIERS);
  const duration = policy.timeWindow.end - policy.timeWindow.start;
  const timeTier = amountToTier(duration, TIME_WINDOW_TIERS);
  const categoryMask = encodeCategoryMask(policy.categoryRestriction);
  const vendorHash = encodeVendorHash(policy.vendorRestriction);

  let bitmask = 0n;
  bitmask |= BigInt(permissionTier) & 0x7n;           // bits 0-2
  bitmask |= (BigInt(amountTier) & 0xFn) << 3n;       // bits 3-6
  bitmask |= (BigInt(cumulativeTier) & 0xFn) << 7n;   // bits 7-10
  bitmask |= (BigInt(timeTier) & 0xFn) << 11n;        // bits 11-14
  bitmask |= (BigInt(categoryMask) & 0xFFn) << 15n;   // bits 15-22
  bitmask |= (BigInt(vendorHash) & 0xFFn) << 23n;     // bits 23-30

  return bitmask;
}

/**
 * Decode the permission tier from an encoded bitmask.
 */
export function decodePermissionTier(bitmask: bigint): number {
  return Number(bitmask & 0x7n);
}

/**
 * Decode the amount tier from an encoded bitmask.
 */
export function decodeAmountTier(bitmask: bigint): number {
  return Number((bitmask >> 3n) & 0xFn);
}

/**
 * Decode the cumulative tier from an encoded bitmask.
 */
export function decodeCumulativeTier(bitmask: bigint): number {
  return Number((bitmask >> 7n) & 0xFn);
}

/**
 * Decode the time window tier from an encoded bitmask.
 */
export function decodeTimeTier(bitmask: bigint): number {
  return Number((bitmask >> 11n) & 0xFn);
}

/**
 * Decode the category mask from an encoded bitmask.
 */
export function decodeCategoryMask(bitmask: bigint): number {
  return Number((bitmask >> 15n) & 0xFFn);
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Verify that a ZKP-proven spend policy meets a required policy.
 *
 * This is the merchant-side check: given the encoded bitmask from the agent's
 * ZKP proof (public signal), verify it satisfies the merchant's requirements.
 * The merchant never learns the actual policy — only that it is sufficient.
 *
 * @param provenBitmask - The permission bitmask from the ZKP public signals
 * @param requiredPolicy - The merchant's minimum required policy
 * @returns Object with `satisfied` boolean and human-readable `reasons` for failures
 */
export function verifySpendPolicyProof(
  provenBitmask: bigint,
  requiredPolicy: {
    minTransactionAmount?: number;
    minCumulativeAmount?: number;
    minDurationSeconds?: number;
    requiredMCCs?: string[];
  },
): { satisfied: boolean; reasons: string[] } {
  const reasons: string[] = [];

  // Check permission tier
  const provenPermTier = decodePermissionTier(provenBitmask);
  if (requiredPolicy.minTransactionAmount !== undefined) {
    const requiredPermTier = derivePermissionTier(requiredPolicy.minTransactionAmount);
    if (provenPermTier < requiredPermTier) {
      reasons.push(
        `Permission tier ${provenPermTier} < required ${requiredPermTier}`
      );
    }
  }

  // Check amount tier
  if (requiredPolicy.minTransactionAmount !== undefined) {
    const provenAmountTier = decodeAmountTier(provenBitmask);
    const requiredAmountTier = amountToTier(requiredPolicy.minTransactionAmount, AMOUNT_TIERS);
    if (provenAmountTier < requiredAmountTier) {
      reasons.push(
        `Amount tier ${provenAmountTier} < required ${requiredAmountTier}`
      );
    }
  }

  // Check cumulative tier
  if (requiredPolicy.minCumulativeAmount !== undefined) {
    const provenCumTier = decodeCumulativeTier(provenBitmask);
    const requiredCumTier = amountToTier(requiredPolicy.minCumulativeAmount, AMOUNT_TIERS);
    if (provenCumTier < requiredCumTier) {
      reasons.push(
        `Cumulative tier ${provenCumTier} < required ${requiredCumTier}`
      );
    }
  }

  // Check time window tier
  if (requiredPolicy.minDurationSeconds !== undefined) {
    const provenTimeTier = decodeTimeTier(provenBitmask);
    const requiredTimeTier = amountToTier(requiredPolicy.minDurationSeconds, TIME_WINDOW_TIERS);
    if (provenTimeTier < requiredTimeTier) {
      reasons.push(
        `Time tier ${provenTimeTier} < required ${requiredTimeTier}`
      );
    }
  }

  // Check category mask
  if (requiredPolicy.requiredMCCs && requiredPolicy.requiredMCCs.length > 0) {
    const provenCatMask = decodeCategoryMask(provenBitmask);
    const requiredCatMask = encodeCategoryMask({ allowedMCCs: requiredPolicy.requiredMCCs });
    // All required bits must be set in the proven mask
    if ((provenCatMask & requiredCatMask) !== requiredCatMask) {
      reasons.push(
        `Category mask 0x${provenCatMask.toString(16)} missing required bits 0x${requiredCatMask.toString(16)}`
      );
    }
  }

  return {
    satisfied: reasons.length === 0,
    reasons,
  };
}

/**
 * Get the amount tier thresholds (useful for UI display).
 */
export function getAmountTiers(): readonly number[] {
  return AMOUNT_TIERS;
}

/**
 * Get the time window tier thresholds (useful for UI display).
 */
export function getTimeWindowTiers(): readonly number[] {
  return TIME_WINDOW_TIERS;
}
