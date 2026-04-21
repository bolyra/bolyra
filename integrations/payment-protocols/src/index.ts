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
} from './types';
