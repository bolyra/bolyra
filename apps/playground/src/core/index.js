/** Public surface of the bundle: `globalThis.BolyraPlayground`. No DOM here. */
import { verifyAll, parseInput, validateEnvelope, validateOptions, LIMITS } from './verify.js';
import { newSession, decide, resetSession, exportJsonl, signerDoc, chainInfo, ISSUER, KEY_ID, DENY_REASON } from './simulate.js';
import { TIER_ORDER, isTier, requiredTierForUsdAmount, tierCeilingUsd, describeTierAuthorization, tierBitmask, tierCovers } from './tiers.js';

// Filled by build.mjs via esbuild `define`.
export const VERSION = __PLAYGROUND_VERSION__;
export const RECEIPTS_VERSION = __RECEIPTS_VERSION__;
export const CLI_VERSION = __CLI_VERSION__;
export const SAMPLES = __SAMPLES__;

export const PLAYGROUND = Object.freeze({
  VERSION, RECEIPTS_VERSION, CLI_VERSION, SAMPLES, LIMITS,
  verifyAll, parseInput, validateEnvelope, validateOptions,
  newSession, decide, resetSession, exportJsonl, signerDoc, chainInfo, ISSUER, KEY_ID, DENY_REASON,
  TIER_ORDER, isTier, requiredTierForUsdAmount, tierCeilingUsd, describeTierAuthorization, tierBitmask, tierCovers,
});
globalThis.BolyraPlayground = PLAYGROUND;
