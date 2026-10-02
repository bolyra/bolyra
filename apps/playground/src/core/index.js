/** Public surface of the bundle: `globalThis.BolyraPlayground`. No DOM here. */
import { verifyAll, parseInput, validateEnvelope, validateOptions, LIMITS } from './verify.js';
import { newSession, decide, resetSession, exportJsonl, signerDoc, chainInfo, ISSUER, KEY_ID, DENY_REASON } from './simulate.js';
import { TIER_ORDER, isTier, requiredTierForUsdAmount, tierCeilingUsd, describeTierAuthorization, tierBitmask, tierCovers } from './tiers.js';
import { parseChallenge, selectLeg, classifyLeg, defaultPayeeMatch, peekJwsHeader, inspectJwsPayload, tokenSha256, isUnixSeconds, PLACEHOLDER_URN, LIMITS as X402_LIMITS } from './x402.js';
import { EVC_SHAPES, shapeById } from './evc-shapes.js';
import { track, EVENTS as USAGE_EVENTS } from './usage.js';

// Filled by build.mjs via esbuild `define`.
export const VERSION = __PLAYGROUND_VERSION__;
export const RECEIPTS_VERSION = __RECEIPTS_VERSION__;
export const CLI_VERSION = __CLI_VERSION__;
export const PAYMENT_PROTOCOLS_VERSION = __PAYMENT_PROTOCOLS_VERSION__;
export const X402_SAMPLES = __X402_SAMPLES__;
export const SAMPLES = __SAMPLES__;

export const PLAYGROUND = Object.freeze({
  VERSION, RECEIPTS_VERSION, CLI_VERSION, PAYMENT_PROTOCOLS_VERSION, SAMPLES, X402_SAMPLES, LIMITS, X402_LIMITS,
  parseChallenge, selectLeg, classifyLeg, defaultPayeeMatch, peekJwsHeader, inspectJwsPayload, tokenSha256, isUnixSeconds, PLACEHOLDER_URN,
  EVC_SHAPES, shapeById,
  track, USAGE_EVENTS,
  verifyAll, parseInput, validateEnvelope, validateOptions,
  newSession, decide, resetSession, exportJsonl, signerDoc, chainInfo, ISSUER, KEY_ID, DENY_REASON,
  TIER_ORDER, isTier, requiredTierForUsdAmount, tierCeilingUsd, describeTierAuthorization, tierBitmask, tierCovers,
});
globalThis.BolyraPlayground = PLAYGROUND;
