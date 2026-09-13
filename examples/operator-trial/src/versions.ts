/**
 * Pinned versions of the published packages this trial runs against. They
 * are recorded in every bundle's summary.json. test/versions.test.ts asserts
 * they match package.json so the two cannot drift.
 */
export const PACKAGES = {
  gateway: '0.6.0',
  mcp: '0.6.5',
  receipts: '0.11.0',
} as const;

/** The verifier CLI named in VERIFY.txt. */
export const CLI_VERSION = '0.9.0';

export const TRIAL_VERSION = '0.1.0';
