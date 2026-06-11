/**
 * Commerce Authorization Layer
 *
 * Unified API that normalizes authorization decisions across Stripe ACP,
 * Coinbase x402, Visa TAP, and Google AP2. Stripe + x402 are fully wired;
 * TAP + AP2 return fail-closed stubs in v0.5.0.
 *
 * Every decision carries an unsigned deterministic receipt for logging/audit.
 */

import { createHash } from 'crypto';
import type {
  PaymentTrustGrade,
  StripeACPSpendDecision,
  StripeACPContext,
  AgentPaymentVerification,
  TAPVerificationResult,
} from './types';
import type { X402VerifyDecision } from './x402';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Payment rail identifier. */
export type CommerceRail = 'stripe-acp' | 'x402' | 'visa-tap' | 'google-ap2';

/** What the agent wants to buy. */
export interface CommerceIntent {
  /** Which rail to use. */
  rail: CommerceRail;
  /** Amount in minor units (cents, wei, etc.). */
  amount: number;
  /** ISO 4217 or asset symbol (e.g. "USD", "USDC"). */
  currency: string;
  /** Merchant / recipient identifier (opaque to the commerce layer). */
  merchant: string;
  /** Optional human-readable description. */
  description?: string;
}

/** Discriminated union of per-rail adapter results. */
export type CommerceAuthorizationInput =
  | {
      intent: CommerceIntent & { rail: 'stripe-acp' };
      spendDecision: StripeACPSpendDecision;
      acpContext: StripeACPContext;
    }
  | {
      intent: CommerceIntent & { rail: 'x402' };
      adapterResult: X402VerifyDecision;
    }
  | {
      intent: CommerceIntent & { rail: 'visa-tap' };
      adapterResult: TAPVerificationResult;
    }
  | {
      intent: CommerceIntent & { rail: 'google-ap2' };
      adapterResult: AgentPaymentVerification;
    };

/** Normalized authorization decision — same shape for every rail. */
export interface CommerceAuthorizationDecision {
  /** Whether the commerce intent is authorized. */
  allowed: boolean;
  /** Human-readable denial reason (only when allowed=false). */
  reason?: string;
  /** Acting agent DID. */
  did: string;
  /** Trust score (0-100). */
  score: number;
  /** Letter grade. */
  grade: PaymentTrustGrade;
  /** Warnings from the adapter / commerce layer. */
  warnings: string[];
  /** Deterministic receipt for logging. */
  receipt: CommerceAuthorizationReceipt;
}

/** Unsigned deterministic receipt for audit logging. */
export interface CommerceAuthorizationReceipt {
  /** Schema version. */
  v: 1;
  /** Deterministic receipt ID (first 16 hex chars of a SHA-256). */
  id: string;
  /** Rail that produced this receipt. */
  rail: CommerceRail;
  /** SHA-256 of the serialized intent. */
  intentHash: string;
  /** Acting agent DID. */
  did: string;
  /** Whether the intent was authorized. */
  allowed: boolean;
  /** Unix timestamp (seconds) when the decision was issued. */
  issuedAt: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function gradeFromScore(score: number): PaymentTrustGrade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function generateReceipt(
  intent: CommerceIntent,
  did: string,
  allowed: boolean,
  issuedAt: number,
): CommerceAuthorizationReceipt {
  const intentHash = createHash('sha256')
    .update(JSON.stringify(intent))
    .digest('hex');
  const id = createHash('sha256')
    .update(JSON.stringify({ intentHash, did, issuedAt, rail: intent.rail }))
    .digest('hex')
    .slice(0, 16);
  return { v: 1, id, rail: intent.rail, intentHash, did, allowed, issuedAt };
}

// ---------------------------------------------------------------------------
// Per-rail authorization
// ---------------------------------------------------------------------------

function authorizeStripe(
  input: Extract<CommerceAuthorizationInput, { intent: { rail: 'stripe-acp' } }>,
  issuedAt: number,
): CommerceAuthorizationDecision {
  const { intent, spendDecision, acpContext } = input;
  const did = acpContext.actingAgentDid;
  const score = acpContext.score;
  const grade = gradeFromScore(score);
  const warnings = acpContext.warnings ?? [];
  const allowed = spendDecision.allowed;
  const reason = spendDecision.reason;
  const receipt = generateReceipt(intent, did, allowed, issuedAt);

  return {
    allowed,
    ...(reason !== undefined ? { reason } : {}),
    did,
    score,
    grade,
    warnings,
    receipt,
  };
}

function authorizeX402(
  input: Extract<CommerceAuthorizationInput, { intent: { rail: 'x402' } }>,
  issuedAt: number,
): CommerceAuthorizationDecision {
  const { intent, adapterResult } = input;
  const { did, score, grade: adapterGrade, warnings: adapterWarnings } = adapterResult;
  const warnings = [...adapterWarnings];

  // Commerce-layer gates on top of the adapter's own checks
  let allowed = adapterResult.verified;
  let reason: string | undefined;

  if (!adapterResult.credentialResolved) {
    allowed = false;
    reason = 'credential not resolved';
    if (!warnings.some((w) => /credential/i.test(w))) {
      warnings.push('commerce-layer: credential not resolved');
    }
  }

  if (
    allowed &&
    intent.currency.toLowerCase() !== adapterResult.currency.toLowerCase()
  ) {
    allowed = false;
    reason = `currency mismatch: intent=${intent.currency}, adapter=${adapterResult.currency}`;
    warnings.push(`commerce-layer: ${reason}`);
  }

  if (!allowed && reason === undefined) {
    reason = 'x402 adapter verification failed';
  }

  const grade = gradeFromScore(score);
  const receipt = generateReceipt(intent, did, allowed, issuedAt);

  return {
    allowed,
    ...(reason !== undefined ? { reason } : {}),
    did,
    score,
    grade,
    warnings,
    receipt,
  };
}

function stubDenial(
  input: CommerceAuthorizationInput,
  issuedAt: number,
): CommerceAuthorizationDecision {
  const { intent } = input;
  const rail = intent.rail;

  // Extract did/score/grade/warnings from whichever adapter result shape we have
  let did: string;
  let score: number;
  let warnings: string[];

  if ('adapterResult' in input) {
    did = input.adapterResult.did;
    score = input.adapterResult.score;
    warnings = input.adapterResult.warnings ? [...input.adapterResult.warnings] : [];
  } else {
    did = input.acpContext.actingAgentDid;
    score = input.acpContext.score;
    warnings = [...input.acpContext.warnings];
  }

  const grade = gradeFromScore(score);
  const reason = `${rail} commerce authorization is not fully wired in v0.5.0`;
  const receipt = generateReceipt(intent, did, false, issuedAt);

  return { allowed: false, reason, did, score, grade, warnings, receipt };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Authorize a commerce intent against a pre-computed adapter result.
 *
 * Stripe ACP and x402 are fully wired. Visa TAP and Google AP2 return
 * fail-closed stub denials in v0.5.0.
 */
export function authorizeCommerceIntent(
  input: CommerceAuthorizationInput,
  options?: { issuedAt?: number },
): CommerceAuthorizationDecision {
  const issuedAt = options?.issuedAt ?? Math.floor(Date.now() / 1000);

  switch (input.intent.rail) {
    case 'stripe-acp':
      return authorizeStripe(
        input as Extract<CommerceAuthorizationInput, { intent: { rail: 'stripe-acp' } }>,
        issuedAt,
      );
    case 'x402':
      return authorizeX402(
        input as Extract<CommerceAuthorizationInput, { intent: { rail: 'x402' } }>,
        issuedAt,
      );
    case 'visa-tap':
      return stubDenial(input, issuedAt);
    case 'google-ap2':
      return stubDenial(input, issuedAt);
  }
}
