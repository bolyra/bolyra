/**
 * Amount → financial-tier mapping over @bolyra/sdk's cumulative Permission
 * bits, and the MPP capability vocabulary this gate speaks to verifiers.
 *
 * Tier semantics (sdk `Permission`, cumulative encoding — higher tiers imply
 * lower):
 *   FINANCIAL_SMALL      amount <  $100
 *   FINANCIAL_MEDIUM     amount <  $10,000 (implies SMALL)
 *   FINANCIAL_UNLIMITED  any amount        (implies MEDIUM + SMALL)
 *
 * Comparison is EXACT-DECIMAL over the amount string — never float. A float
 * would round `99.99999999999999999999` up to `100` and demand a higher tier
 * than delegated; exact comparison keeps the mapping deterministic. (Rounding
 * UP is the safe direction, but deterministic beats accidentally-safe.)
 */

import { Permission } from '@bolyra/sdk';
import type { FinancialTier } from './types';
import { VerifyDenial } from './types';

/** The MPP capability token for each financial tier. */
const CAPABILITY_FOR_TIER: Record<FinancialTier, string> = {
  small: 'mpp:financial:small',
  medium: 'mpp:financial:medium',
  unlimited: 'mpp:financial:unlimited',
};

/**
 * Built-in capability → Permission-name map for the MPP vocabulary — the same
 * shape the `bolyra verify` `--capability-map` file uses, so an external
 * verifier can be configured with exactly this mapping. Each entry lists the
 * IMPLIED lower tiers explicitly so the resulting mask is a valid cumulative
 * encoding (higher financial tiers imply lower ones):
 *
 * ```json
 * { "mpp:financial:small": ["FINANCIAL_SMALL"],
 *   "mpp:financial:medium": ["FINANCIAL_SMALL", "FINANCIAL_MEDIUM"],
 *   "mpp:financial:unlimited": ["FINANCIAL_SMALL", "FINANCIAL_MEDIUM", "FINANCIAL_UNLIMITED"] }
 * ```
 */
export const MPP_CAPABILITY_MAP: Record<string, ReadonlyArray<keyof typeof Permission>> = {
  'mpp:financial:small': ['FINANCIAL_SMALL'],
  'mpp:financial:medium': ['FINANCIAL_SMALL', 'FINANCIAL_MEDIUM'],
  'mpp:financial:unlimited': ['FINANCIAL_SMALL', 'FINANCIAL_MEDIUM', 'FINANCIAL_UNLIMITED'],
};

/** The capability token the gate requests for a tier. */
export function tierCapability(tier: FinancialTier): string {
  return CAPABILITY_FOR_TIER[tier];
}

/**
 * Compare a non-negative decimal string against a non-negative integer,
 * exactly. Returns -1 / 0 / 1.
 */
function compareDecimalToInt(decimal: string, n: number): -1 | 0 | 1 {
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
 * Map a decimal USD amount to the financial tier required to spend it.
 * Throws `TypeError` on anything that is not a plain non-negative decimal
 * (no sign, no exponent, no bare `.`); callers fail closed on that throw.
 */
export function requiredTierForUsdAmount(amount: string | number): FinancialTier {
  let text: string;
  if (typeof amount === 'number') {
    if (!Number.isFinite(amount) || amount < 0) {
      throw new TypeError(`amount must be a finite non-negative number, got ${amount}`);
    }
    // Number.prototype.toString may use exponent notation for extremes; those
    // extremes are all >= $10,000 anyway, but keep the parse strict.
    text = String(amount);
  } else if (typeof amount === 'string') {
    text = amount.trim();
  } else {
    throw new TypeError(`amount must be a string or number, got ${typeof amount}`);
  }

  if (!/^\d+(\.\d+)?$/.test(text)) {
    throw new TypeError(`amount must be a plain non-negative decimal string, got ${JSON.stringify(text)}`);
  }

  if (compareDecimalToInt(text, 100) < 0) return 'small';
  if (compareDecimalToInt(text, 10_000) < 0) return 'medium';
  return 'unlimited';
}

/**
 * Resolve capability tokens to the Permission bits they require, using the
 * built-in MPP map. Unknown capabilities fail CLOSED with
 * `unknown_capability` (spec §9), mirroring the reference verifier.
 */
export function requiredPermissionBits(capabilities: string[]): bigint {
  let required = 0n;
  for (const capability of capabilities) {
    const names = MPP_CAPABILITY_MAP[capability];
    if (names === undefined) {
      throw new VerifyDenial('unknown_capability', `capability "${capability}" has no mapping`, {
        capability,
      });
    }
    for (const name of names) {
      required |= 1n << BigInt(Permission[name]);
    }
  }
  return required;
}
