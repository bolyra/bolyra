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

export { denyProblem, denyResponse, DENY_STATUS, type DenyProblem } from './deny';
export { runCommandVerifier, callUrlVerifier, validateVerdict } from './evc';
export { NonceStore } from './nonces';
export { createGateReceiptSigner, buildDecisionReceiptInput } from './receipts';
export type { GateReceiptSigner, DecisionFacts } from './receipts';

export {
  allow,
  deny,
  VerifyDenial,
  isVerifyDenial,
  type AllowVerdict,
  type BolyraGateOptions,
  type ConsumeNonce,
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
