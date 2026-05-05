// 8-bit cumulative permission encoding.
// Mirrors the Bolyra circuits/Delegation.circom semantics so receipts issued
// here can later be upgraded to ZKP-backed delegation without changing the
// permission shape. Higher tiers imply lower; validateCumulativeBitEncoding
// rejects bit combinations that violate the implication rules.

export const PERM = {
  READ_DATA: 1 << 0,            // bit 0
  WRITE_DATA: 1 << 1,           // bit 1
  FINANCIAL_SMALL: 1 << 2,      // bit 2 — < $100
  FINANCIAL_MEDIUM: 1 << 3,     // bit 3 — < $10K, implies FINANCIAL_SMALL
  FINANCIAL_UNLIMITED: 1 << 4,  // bit 4 — implies FINANCIAL_SMALL + FINANCIAL_MEDIUM
  SIGN_ON_BEHALF: 1 << 5,       // bit 5
  SUB_DELEGATE: 1 << 6,         // bit 6
  ACCESS_PII: 1 << 7,           // bit 7
} as const;

export type Permission = number;

export function hasPermission(granted: Permission, required: Permission): boolean {
  return (granted & required) === required;
}

/**
 * Enforces the cumulative implication rules from circuits/Delegation.circom.
 * Returns null if valid, or a string describing the first violation.
 */
export function validateCumulativeBitEncoding(perm: Permission): string | null {
  if (perm < 0 || perm > 0xff || !Number.isInteger(perm)) {
    return `permission must be an 8-bit integer (0-255), got ${perm}`;
  }
  if ((perm & PERM.FINANCIAL_MEDIUM) && !(perm & PERM.FINANCIAL_SMALL)) {
    return "FINANCIAL_MEDIUM (bit 3) requires FINANCIAL_SMALL (bit 2)";
  }
  if (perm & PERM.FINANCIAL_UNLIMITED) {
    if (!(perm & PERM.FINANCIAL_SMALL)) {
      return "FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_SMALL (bit 2)";
    }
    if (!(perm & PERM.FINANCIAL_MEDIUM)) {
      return "FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)";
    }
  }
  return null;
}

/**
 * Narrowing check used at delegation time. Returns true iff `narrower` is a
 * non-strict subset of `wider` (every bit in narrower is also in wider).
 * Mirrors the one-way scope narrowing the Delegation circuit enforces on-chain.
 */
export function narrows(wider: Permission, narrower: Permission): boolean {
  return (wider & narrower) === narrower;
}
