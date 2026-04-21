/**
 * Shared types for Bolyra payment protocol adapters.
 *
 * These types bridge Bolyra's ZKP identity primitives with the trust/authorization
 * models used by Visa's Trusted Agent Protocol (TAP) and Google's Agent Payments
 * Protocol (AP2). The core idea: an agent proves it has payment authorization from
 * a human without revealing the full policy graph to the merchant or payment network.
 */

import type { BolyraConfig } from '@bolyra/sdk';

// ---------------------------------------------------------------------------
// Spend Policy
// ---------------------------------------------------------------------------

/** Vendor restriction — allowlist or blocklist of merchant identifiers */
export interface VendorRestriction {
  /** Merchant identifiers (Visa merchant IDs, AP2 seller URIs, etc.) */
  merchants: string[];
  /** Whether the list is an allowlist or blocklist */
  mode: 'allow' | 'block';
}

/** Merchant Category Code restriction (ISO 18245) */
export interface CategoryRestriction {
  /** Allowed MCC codes (e.g., ["5411", "5812"] for grocery + restaurants) */
  allowedMCCs: string[];
}

/** Time-bounded spending window */
export interface TimeWindow {
  /** Window start (Unix timestamp, seconds) */
  start: number;
  /** Window end (Unix timestamp, seconds) */
  end: number;
}

/**
 * Spend policy — the human's constraints on what an agent may purchase.
 *
 * Encoded into Bolyra's permission bitmask for ZKP-based verification.
 * The merchant sees only that the policy is satisfied, never the policy itself.
 */
export interface SpendPolicy {
  /** Maximum spend per transaction (minor units, e.g., cents) */
  maxTransactionAmount: number;
  /** Maximum cumulative spend within the time window (minor units) */
  maxCumulativeAmount: number;
  /** Currency code (ISO 4217, e.g., "USD") */
  currency: string;
  /** Optional vendor restrictions */
  vendorRestriction?: VendorRestriction;
  /** Optional category restrictions */
  categoryRestriction?: CategoryRestriction;
  /** Time window for cumulative limits */
  timeWindow: TimeWindow;
}

// ---------------------------------------------------------------------------
// Verification Results
// ---------------------------------------------------------------------------

/** Trust grade aligned with both TAP's trust tiers and AP2's mandate confidence */
export type PaymentTrustGrade = 'A' | 'B' | 'C' | 'D' | 'F';

/**
 * Result of verifying an agent's payment authorization via ZKP.
 *
 * This is the unified output that both the Visa TAP adapter and Google AP2
 * adapter produce. The merchant/payment network receives this without learning
 * the underlying spend policy details.
 */
export interface AgentPaymentVerification {
  /** Whether the agent passed ZKP verification for the requested action */
  verified: boolean;
  /** Trust score (0-100) — composite of proof validity, policy match, freshness */
  score: number;
  /** Letter grade */
  grade: PaymentTrustGrade;
  /** Bolyra DID for the verified agent */
  did: string;
  /** Protocol-specific verification token (TAP signed message or AP2 mandate hash) */
  protocolToken?: string;
  /** Warnings or notes about the verification */
  warnings?: string[];
}

// ---------------------------------------------------------------------------
// Visa TAP Types
// ---------------------------------------------------------------------------

/**
 * Visa TAP trust verification request.
 *
 * Maps to TAP's HTTP Message Signature flow: the agent proves identity and
 * authorization to the merchant, who verifies against Visa's registry.
 * Bolyra replaces the centralized registry lookup with a ZKP proof.
 */
export interface TAPVerificationRequest {
  /** Agent's Bolyra DID */
  agentDid: string;
  /** Merchant identifier (Visa merchant ID) */
  merchantId: string;
  /** Transaction amount (minor units) */
  amount: number;
  /** Currency code */
  currency: string;
  /** Merchant Category Code */
  mcc?: string;
  /** Idempotency key for the transaction */
  transactionId: string;
}

/**
 * Visa TAP verification result with TAP-specific fields.
 * Extends the base AgentPaymentVerification with TAP signal data.
 */
export interface TAPVerificationResult extends AgentPaymentVerification {
  /** TAP payment signal — opaque token for Visa's Payment Signals API */
  paymentSignal?: string;
  /** Whether the verification used batch (off-chain) mode */
  batchMode: boolean;
  /** Scope commitment used (for delegation chain tracking) */
  scopeCommitment: bigint;
}

// ---------------------------------------------------------------------------
// Google AP2 Types
// ---------------------------------------------------------------------------

/** AP2 mandate type — mirrors the AP2 spec's mandate lifecycle */
export type AP2MandateType = 'intent' | 'cart' | 'payment';

/**
 * AP2 agent capability — what the agent is authorized to do in the AP2 flow.
 * Maps to Bolyra's permission bitmask.
 */
export interface AP2AgentCapability {
  /** Capability name (e.g., "purchase", "price_compare", "subscribe") */
  name: string;
  /** Maximum amount for this capability (minor units, 0 = unlimited) */
  maxAmount: number;
  /** Currency code */
  currency: string;
}

/**
 * AP2-compatible agent credential wrapping a Bolyra identity.
 *
 * In AP2, agents carry cryptographically signed mandates from users.
 * Bolyra replaces the plain-text mandate with a ZKP proof: the merchant
 * learns the agent is authorized without seeing the user's full instructions.
 */
export interface AP2AgentCredential {
  /** Agent's Bolyra DID */
  agentDid: string;
  /** AP2 mandate type */
  mandateType: AP2MandateType;
  /** Capabilities the agent can exercise */
  capabilities: AP2AgentCapability[];
  /** ZKP proof of mandate validity (serialized) */
  mandateProof: string;
  /** Scope commitment (for delegation chain) */
  scopeCommitment: bigint;
  /** Expiry (Unix timestamp, seconds) */
  expiresAt: number;
}

/**
 * AP2 delegation record — tracks agent-to-agent capability delegation.
 * Maps to Bolyra's delegation chain with hop tracking.
 */
export interface AP2DelegationRecord {
  /** Source agent DID */
  fromAgent: string;
  /** Target agent DID */
  toAgent: string;
  /** Delegated capabilities (must be subset of source's capabilities) */
  capabilities: AP2AgentCapability[];
  /** Hop index in the delegation chain */
  hopIndex: number;
  /** Delegation nullifier (for double-delegation prevention) */
  delegationNullifier: bigint;
  /** New scope commitment after delegation */
  newScopeCommitment: bigint;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Configuration for the payment protocol adapters.
 */
export interface PaymentVerificationConfig {
  /** Network identifier for DID construction (default: "base-sepolia") */
  network?: string;
  /** Address of the IdentityRegistry contract */
  registryAddress?: string;
  /** Minimum trust score to pass verification (default: 70) */
  minScore?: number;
  /** Maximum proof age in seconds (default: 120 for payments) */
  maxProofAge?: number;
  /** Use off-chain (batch) verification by default (default: true) */
  offchainByDefault?: boolean;
  /** Bolyra SDK configuration passthrough */
  sdkConfig?: BolyraConfig;
}
