// Bolyra Payment Protocol Adapters — ZKP privacy layer for agentic commerce
// Visa TAP + Google AP2 integration

// Visa TAP
export {
  createVisaTAPVerification,
  createCachedTAPVerifier,
  computeTAPScore,
} from './visa-tap';

// Google AP2
export {
  createAP2AgentCredential,
  verifyAP2AgentCredential,
  delegateAP2Capabilities,
  capabilitiesToSpendPolicy,
  bitmaskToCapabilities,
} from './google-ap2';

// Spend Policy
export {
  encodeSpendPolicy,
  verifySpendPolicyProof,
  decodePermissionTier,
  decodeAmountTier,
  decodeCumulativeTier,
  decodeTimeTier,
  decodeCategoryMask,
  getAmountTiers,
  getTimeWindowTiers,
} from './spend-policy';

// Stripe Agent Commerce Protocol (ACP)
export {
  bitmaskToStripeSpendingLimits,
  authContextToStripeACPContext,
  verifyStripeACPSpend,
} from './stripe-acp';
export type { StripeACPOperation } from './stripe-acp';

// Coinbase x402
export {
  createX402Authorization,
  verifyX402Authorization,
  serializePaymentRequired,
  parsePaymentRequired,
  X402_BOLYRA_CREDENTIAL_HEADER,
  X402_BOLYRA_CHALLENGE_HEADER,
  X402_PAYMENT_REQUIRED_HEADER,
  X402_WIRE_VERSION,
} from './x402';
export type {
  X402PaymentRequirements,
  X402AuthorizationResult,
  X402VerifyDecision,
  X402CredentialResolver,
  X402Config,
} from './x402';

// Commerce Authorization Layer
export { authorizeCommerceIntent } from './commerce-intent';
export type {
  CommerceRail,
  CommerceIntent,
  CommerceAuthorizationInput,
  CommerceAuthorizationDecision,
  CommerceAuthorizationReceipt,
  CommerceAuthorizationOptions,
  CommerceReceiptEvidence,
} from './commerce-intent';

// Types
export type {
  SpendPolicy,
  VendorRestriction,
  CategoryRestriction,
  TimeWindow,
  PaymentTrustGrade,
  AgentPaymentVerification,
  TAPVerificationRequest,
  TAPVerificationResult,
  AP2MandateType,
  AP2AgentCapability,
  AP2AgentCredential,
  AP2DelegationRecord,
  PaymentVerificationConfig,
  StripeACPSpendingTier,
  StripeACPSpendingLimits,
  BolyraVerifiedContext,
  StripeACPContext,
  StripeACPSpendDecision,
} from './types';
