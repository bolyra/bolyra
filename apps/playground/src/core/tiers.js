/**
 * Spend-tier calculation for the playground's simulated policy.
 *
 * `compareDecimalToInt`, `requiredTierForUsdAmount`, `tierCeilingUsd` and
 * `describeTierAuthorization` are copied from
 * `integrations/mpp-payments/src/tiers.ts` as published in @bolyra/mpp@0.7.0
 * (the package itself pulls @bolyra/sdk and the ZK toolchain, so it is not
 * bundled into the page). `test/unit/tiers.test.js` runs a differential test
 * against the published package so this copy cannot drift silently.
 *
 * Differences from the source, on purpose: only STRING amounts are accepted
 * (the page never has a number to pass), and unknown tiers are rejected
 * explicitly. No denial machinery, no HTTP status, no RFC 9457 body: the
 * playground reports a local allow / deny / invalid, nothing more.
 */

export const TIER_ORDER = Object.freeze(['small', 'medium', 'unlimited']);

/** Cumulative Permission bits (sdk): FINANCIAL_SMALL=2, MEDIUM=3, UNLIMITED=4. */
const TIER_BITS = Object.freeze({ small: [2], medium: [2, 3], unlimited: [2, 3, 4] });

export function isTier(value) {
  return typeof value === 'string' && TIER_ORDER.includes(value);
}

function assertTier(tier) {
  if (!isTier(tier)) throw new TypeError(`unknown tier: ${JSON.stringify(tier)}`);
}

/**
 * Compare a non-negative decimal string against a non-negative integer,
 * exactly. Returns -1 / 0 / 1. (copied)
 */
function compareDecimalToInt(decimal, n) {
  const [rawInt, frac = ''] = decimal.split('.');
  const intPart = rawInt.replace(/^0+(?=\d)/, '');
  const nStr = String(n);
  if (intPart.length !== nStr.length) {
    return intPart.length < nStr.length ? -1 : 1;
  }
  if (intPart !== nStr) {
    return intPart < nStr ? -1 : 1;
  }
  return /[1-9]/.test(frac) ? 1 : 0;
}

/**
 * Map a decimal USD amount string to the financial tier required to spend it.
 * Throws `TypeError` on anything that is not a plain non-negative decimal
 * (no sign, no exponent, no bare `.`); callers treat that as invalid input.
 * (copied; number inputs deliberately rejected here)
 */
export function requiredTierForUsdAmount(amount) {
  if (typeof amount !== 'string') {
    throw new TypeError(`amount must be a string, got ${typeof amount}`);
  }
  const text = amount.trim();
  if (!/^\d+(\.\d+)?$/.test(text)) {
    throw new TypeError(`amount must be a plain non-negative decimal string, got ${JSON.stringify(text)}`);
  }
  if (compareDecimalToInt(text, 100) < 0) return 'small';
  if (compareDecimalToInt(text, 10_000) < 0) return 'medium';
  return 'unlimited';
}

/** EXCLUSIVE upper bound a tier authorizes in whole USD, or null for unlimited. (copied) */
export function tierCeilingUsd(tier) {
  assertTier(tier);
  switch (tier) {
    case 'small':
      return 100;
    case 'medium':
      return 10_000;
    default:
      return null;
  }
}

/** Human-readable authorized range for a tier. (copied) */
export function describeTierAuthorization(tier) {
  const ceiling = tierCeilingUsd(tier);
  return ceiling === null
    ? 'any amount (no ceiling)'
    : `any amount under $${ceiling.toLocaleString('en-US')}`;
}

/** Decimal permission bitmask string for a tier's cumulative bits. */
export function tierBitmask(tier) {
  assertTier(tier);
  let mask = 0;
  for (const bit of TIER_BITS[tier]) mask |= 1 << bit;
  return String(mask);
}

/** Does a mandate for `tier` cover a request of `amount`? (required tier ≤ tier) */
export function tierCovers(tier, amount) {
  assertTier(tier);
  const required = requiredTierForUsdAmount(amount);
  return TIER_ORDER.indexOf(required) <= TIER_ORDER.indexOf(tier);
}
