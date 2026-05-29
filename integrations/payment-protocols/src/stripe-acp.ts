/**
 * Stripe Agent Commerce Protocol (ACP) Adapter
 *
 * Maps a verified Bolyra v=2 proof bundle into a Stripe ACP context. The
 * narrowing story:
 *
 *   human  ──handshake──>  root agent (bit 4: FINANCIAL_UNLIMITED)
 *                              │
 *                              ▼ delegation hop 1
 *                          agent A (bit 3: FINANCIAL_MEDIUM)
 *                              │
 *                              ▼ delegation hop 2
 *                          agent B (bit 2: FINANCIAL_SMALL)  ── acting agent
 *
 * Stripe sees the leaf delegatee's scope (`small`) and a max-tx cap of $100.
 * It never sees the human's identity, the root agent's broader authority, or
 * the intermediate hops — only the most-narrowed cap.
 *
 * This adapter is a pure mapping layer: it consumes a `BolyraVerifiedContext`
 * (already-verified handshake + chain) and returns a `StripeACPContext`. It
 * deliberately does NOT call into the SDK. Verify the bundle with
 * `@bolyra/mcp`'s `verifyBundle` or via direct SDK calls, then pass the
 * result here.
 *
 * @see https://github.com/stripe/agent-toolkit (Stripe Agent Commerce Protocol)
 */

import type {
  BolyraVerifiedContext,
  StripeACPContext,
  StripeACPSpendDecision,
  StripeACPSpendingLimits,
  StripeACPSpendingTier,
} from './types';

// ---------------------------------------------------------------------------
// Bit layout (mirrors CLAUDE.md §"Permissions Model")
// ---------------------------------------------------------------------------

const BIT_FINANCIAL_SMALL = 1n << 2n;     // bit 2: < $100
const BIT_FINANCIAL_MEDIUM = 1n << 3n;    // bit 3: < $10K
const BIT_FINANCIAL_UNLIMITED = 1n << 4n; // bit 4: unlimited
const BIT_SIGN_ON_BEHALF = 1n << 5n;      // bit 5: sign on behalf

/** Per-tx caps in minor units (USD cents). 0 with tier="unlimited" → no cap. */
const TIER_CAPS = {
  none: 0,
  small: 10_000,        // $100
  medium: 1_000_000,    // $10K
  unlimited: 0,         // no cap
} as const;

// ---------------------------------------------------------------------------
// Bitmask → Spending limits
// ---------------------------------------------------------------------------

/**
 * Derive Stripe ACP spending limits from a Bolyra scope bitmask.
 *
 * Pure function — no I/O, no SDK calls. Suitable for both production checks
 * and offline policy preview.
 */
export function bitmaskToStripeSpendingLimits(
  bitmask: bigint,
  currency: string = 'USD',
): StripeACPSpendingLimits {
  const financialSmall = (bitmask & BIT_FINANCIAL_SMALL) !== 0n;
  const financialMedium = (bitmask & BIT_FINANCIAL_MEDIUM) !== 0n;
  const financialUnlimited = (bitmask & BIT_FINANCIAL_UNLIMITED) !== 0n;
  const signOnBehalf = (bitmask & BIT_SIGN_ON_BEHALF) !== 0n;

  // Most-permissive wins. Cumulative-bit semantics (per CLAUDE.md): bit 4
  // implies 2+3, bit 3 implies 2. We do not enforce the implication here —
  // that is the circuit's job. We just pick the highest tier whose bit is set.
  let tier: StripeACPSpendingTier;
  if (financialUnlimited) {
    tier = 'unlimited';
  } else if (financialMedium) {
    tier = 'medium';
  } else if (financialSmall) {
    tier = 'small';
  } else {
    tier = 'none';
  }

  return {
    maxTransactionAmount: TIER_CAPS[tier],
    currency,
    financialSmall,
    financialMedium,
    financialUnlimited,
    signOnBehalf,
    tier,
  };
}

// ---------------------------------------------------------------------------
// Verified context → ACP context
// ---------------------------------------------------------------------------

function buildDid(network: string, commitmentDecimal: string): string {
  const hex = BigInt(commitmentDecimal).toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

/**
 * Reshape a verified Bolyra context into a Stripe ACP context.
 *
 * The caller is responsible for verification (via `@bolyra/mcp`'s
 * `verifyBundle` or direct SDK calls). The adapter trusts `ctx.verified`
 * and surfaces any pre-existing warnings.
 *
 * @param ctx              Verified Bolyra context (leaf scope already collapsed)
 * @param rootCommitment   Root credential commitment as decimal string —
 *                         needed to compute the originating-agent DID when
 *                         a delegation chain is present.
 * @param network          DID network suffix (default "base-sepolia")
 * @param currency         ISO 4217 currency for the limits (default "USD")
 */
export function authContextToStripeACPContext(
  ctx: BolyraVerifiedContext,
  rootCommitment: string,
  network: string = 'base-sepolia',
  currency: string = 'USD',
): StripeACPContext {
  const warnings: string[] = [...ctx.warnings];

  const spendingLimits = bitmaskToStripeSpendingLimits(
    ctx.permissionBitmask,
    currency,
  );

  if (spendingLimits.tier === 'none' && ctx.verified) {
    warnings.push(
      'Effective scope grants no FINANCIAL_* authority — agent cannot initiate payments.',
    );
  }

  // Acting agent = leaf delegatee (or root if no chain).
  const actingAgentDid = buildDid(network, ctx.effectiveCommitment);
  // Root agent = the credential the human originally authorized. Always the
  // bundle.credentialCommitment — passed in by the caller because the
  // verified context only carries the leaf.
  const rootAgentDid = buildDid(network, rootCommitment);

  return {
    actingAgentDid,
    rootAgentDid,
    delegationDepth: ctx.chainDepth,
    spendingLimits,
    effectiveScope: ctx.permissionBitmask.toString(),
    verified: ctx.verified,
    score: ctx.score,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Spend authorization check
// ---------------------------------------------------------------------------

/**
 * Decide whether a proposed Stripe charge is authorized by the ACP context.
 *
 * Rules:
 *   1. Context must be verified.
 *   2. Currency must match.
 *   3. Amount must be > 0.
 *   4. Tier must be "small" | "medium" | "unlimited" (not "none").
 *   5. For tiers other than "unlimited", amount must be <= the cap.
 *
 * Does NOT enforce SIGN_ON_BEHALF — callers that require it should check
 * `ctx.spendingLimits.signOnBehalf` themselves before calling, since the
 * requirement is endpoint-specific (e.g., `pi.confirm` needs it, `pi.create`
 * with manual confirmation may not).
 */
export function verifyStripeACPSpend(
  ctx: StripeACPContext,
  amount: number,
  currency: string,
): StripeACPSpendDecision {
  const tier = ctx.spendingLimits.tier;
  const cap = ctx.spendingLimits.maxTransactionAmount;

  if (!ctx.verified) {
    return {
      allowed: false,
      reason: 'Bolyra context did not verify.',
      capChecked: cap,
      tier,
    };
  }
  if (currency !== ctx.spendingLimits.currency) {
    return {
      allowed: false,
      reason: `Currency mismatch: ctx=${ctx.spendingLimits.currency}, requested=${currency}.`,
      capChecked: cap,
      tier,
    };
  }
  if (!Number.isFinite(amount) || amount <= 0) {
    return {
      allowed: false,
      reason: `Invalid amount: ${amount}.`,
      capChecked: cap,
      tier,
    };
  }
  if (tier === 'none') {
    return {
      allowed: false,
      reason: 'Agent has no FINANCIAL_* authority.',
      capChecked: cap,
      tier,
    };
  }
  if (tier !== 'unlimited' && amount > cap) {
    return {
      allowed: false,
      reason: `Amount ${amount} exceeds ${tier}-tier cap of ${cap} ${currency}.`,
      capChecked: cap,
      tier,
    };
  }
  return {
    allowed: true,
    capChecked: cap,
    tier,
  };
}
