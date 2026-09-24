/**
 * @bolyra/mpp — verify an agent's delegated spend mandate before accepting an
 * MPP payment credential.
 *
 * See README.md for the honest scope of what is and isn't checked, and
 * docs/mpp-authorization-companion.md for how Bolyra composes with the MPP
 * flow without modifying it.
 */

export {
  bolyraGate,
  BOLYRA_AUTHORIZATION_HEADER,
  type MppxServerMethodLike,
  type BolyraAuthorizationReceiptField,
} from './gate';

export {
  requiredTierForUsdAmount,
  tierCapability,
  MPP_CAPABILITY_MAP,
  requiredPermissionBits,
} from './tiers';

export { verifyClassical, bindingDigest, hashModel } from './classical';

export { issueMandate, MandateIssueError } from './issue';
export type { IssueMandateInput, IssuedMandate, MandateEncoding } from './issue';
export { parseBundle, peekBundle } from './bundle';
export type {
  BindingClaim,
  BundlePeek,
  BundleSignature,
  ParsedBundle,
  PointDec,
  RevealedCredential,
} from './bundle';

export {
  denyProblem,
  denyResponse,
  DENY_STATUS,
  type DenyProblem,
  type DenyProblemInput,
} from './deny';
export {
  runCommandVerifier,
  callUrlVerifier,
  callUrlVerifierWithEvidence,
  normalizeVerifierUrl,
  validateVerdict,
  type UrlVerifierConfig,
  type UrlVerifierEvidence,
} from './evc';
export {
  NonceStore,
  NonceStoreCapacityError,
  NonceRetentionTooLongError,
  MAX_NONCE_RETENTION_SECONDS,
  DEFAULT_MAX_ENTRIES,
  type NonceStoreOptions,
} from './nonces';
export {
  createGateReceiptSigner,
  buildDecisionReceiptInput,
  buildDecisionInstance,
  instanceFactsFrom,
} from './receipts';
export type {
  DecisionFacts,
  DecisionReceiptFacts,
  DecisionInstanceFacts,
} from './receipts';
export type { GateReceiptSigner } from './receipts';

export {
  allow,
  deny,
  AUDIENCE_IDENTIFIER_PATTERN,
  VerifyDenial,
  isVerifyDenial,
  type AllowVerdict,
  type BolyraGateOptions,
  type ConsumeNonce,
  type AllowDecision,
  type Decision,
  type DenyDecision,
  type DenyCode,
  type DenyVerdict,
  type EvcDenyCode,
  type FinancialTier,
  type GateDecision,
  type GateReceiptConfig,
  type NonceStoreLike,
  type OperatorKey,
  type Verdict,
  type VerifierConfig,
  type VerifierRequest,
  type VerifierRequestContext,
} from './types';

export {
  BolyraDeniedError,
  BolyraGateConfigError,
  isBolyraDeniedError,
  isBolyraGateConfigError,
} from './errors';
export { handleDenials, sendDenial, type DenialResponseWriter } from './handle-denials';
