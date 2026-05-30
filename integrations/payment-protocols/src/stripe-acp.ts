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

// BN254 scalar field modulus — every Poseidon-hashed commitment lives in [0, p).
const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// 8-bit permission bitmask domain (bits 0-7).
const BITMASK_MAX = 0xffn;

// Codex P1-1 / P2-5 alignment: ISO 4217 currencies are 3-letter; Stripe sends
// them lowercase. Normalize both sides to lowercase before comparing.
function normalizeCurrency(c: string): string {
  return c.toLowerCase();
}

// ---------------------------------------------------------------------------
// Runtime validation (Codex P1-3 / P1-4 / P1-8 / P2-8)
// ---------------------------------------------------------------------------
//
// TypeScript interfaces are NOT a runtime trust boundary. The adapter
// consumes BolyraVerifiedContext objects that may originate from JSON
// deserialization, inter-process channels, or third-party verifiers — any
// of which can produce a payload that "fits" the interface structurally
// but carries adversarial values (negative bigints set every bit under
// bitwise operations, "false" as a string is truthy, BigInt("abc") throws
// at hash time, etc.). Validate at the adapter boundary, fail closed.

function isPlainBoolean(v: unknown): v is boolean {
  return typeof v === 'boolean';
}

function isFiniteNumberInRange(v: unknown, min: number, max: number): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;
}

function isDecimalString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0 && /^[0-9]+$/.test(v);
}

function isWellFormedBolyraDid(v: unknown): v is string {
  return (
    typeof v === 'string' &&
    /^did:bolyra:[a-z0-9-]+:[0-9a-f]{64}$/.test(v)
  );
}

/**
 * Assert a BolyraVerifiedContext is structurally and semantically safe to
 * map into a Stripe ACP context. Throws with a precise message on any
 * boundary violation. Pure function; no I/O.
 *
 * Rejects:
 *   - non-boolean `verified` (e.g., the string "false")
 *   - non-finite or out-of-range `score`
 *   - malformed `did` (missing prefix, wrong network shape, non-hex tail)
 *   - non-bigint, negative, or >8-bit `permissionBitmask`
 *   - non-integer, negative, or >MAX_DELEGATION_HOPS `chainDepth`
 *   - non-decimal-string `effectiveCommitment`, or value outside BN254
 *   - non-array or non-string-element `warnings`
 */
function validateBolyraVerifiedContext(ctx: BolyraVerifiedContext): void {
  if (!isPlainBoolean(ctx.verified)) {
    throw new TypeError(
      `BolyraVerifiedContext.verified must be a boolean (got ${typeof ctx.verified}: ${String(ctx.verified)})`,
    );
  }
  if (!isFiniteNumberInRange(ctx.score, 0, 100)) {
    throw new TypeError(
      `BolyraVerifiedContext.score must be a finite number in [0,100] (got ${String(ctx.score)})`,
    );
  }
  if (!isWellFormedBolyraDid(ctx.did)) {
    throw new TypeError(
      `BolyraVerifiedContext.did is not a well-formed did:bolyra:<network>:<64-hex> (got ${String(ctx.did)})`,
    );
  }
  if (typeof ctx.permissionBitmask !== 'bigint') {
    throw new TypeError(
      `BolyraVerifiedContext.permissionBitmask must be a bigint (got ${typeof ctx.permissionBitmask})`,
    );
  }
  if (ctx.permissionBitmask < 0n || ctx.permissionBitmask > BITMASK_MAX) {
    throw new RangeError(
      `BolyraVerifiedContext.permissionBitmask must be in [0,255] (got ${ctx.permissionBitmask.toString()})`,
    );
  }
  if (
    !Number.isInteger(ctx.chainDepth) ||
    ctx.chainDepth < 0 ||
    ctx.chainDepth > 3 /* MAX_DELEGATION_HOPS */
  ) {
    throw new RangeError(
      `BolyraVerifiedContext.chainDepth must be an integer in [0,3] (got ${String(ctx.chainDepth)})`,
    );
  }
  if (!isDecimalString(ctx.effectiveCommitment)) {
    throw new TypeError(
      `BolyraVerifiedContext.effectiveCommitment must be a non-empty decimal string (got ${String(ctx.effectiveCommitment)})`,
    );
  }
  // BigInt() on a non-decimal string throws; isDecimalString already gated.
  const commitmentBig = BigInt(ctx.effectiveCommitment);
  if (commitmentBig < 0n || commitmentBig >= BN254_FIELD_MODULUS) {
    throw new RangeError(
      `BolyraVerifiedContext.effectiveCommitment outside BN254 field [0, p)`,
    );
  }
  if (!Array.isArray(ctx.warnings) || !ctx.warnings.every((w) => typeof w === 'string')) {
    throw new TypeError(
      `BolyraVerifiedContext.warnings must be string[]`,
    );
  }
}

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
  currency: string = 'usd',
): StripeACPSpendingLimits {
  // Codex P1-4 / P2-8 guard: a negative bigint sets every bit under bitwise
  // AND, which would otherwise grant max authority. Out-of-domain values
  // are an immediate fail-closed, not a silent zero.
  if (typeof bitmask !== 'bigint') {
    throw new TypeError(
      `bitmaskToStripeSpendingLimits: bitmask must be a bigint (got ${typeof bitmask})`,
    );
  }
  if (bitmask < 0n || bitmask > BITMASK_MAX) {
    throw new RangeError(
      `bitmaskToStripeSpendingLimits: bitmask must be in [0,255] (got ${bitmask.toString()})`,
    );
  }
  const financialSmall = (bitmask & BIT_FINANCIAL_SMALL) !== 0n;
  const financialMedium = (bitmask & BIT_FINANCIAL_MEDIUM) !== 0n;
  const financialUnlimited = (bitmask & BIT_FINANCIAL_UNLIMITED) !== 0n;
  const signOnBehalf = (bitmask & BIT_SIGN_ON_BEHALF) !== 0n;

  // Codex P1-5: enforce cumulative-bit semantics at the adapter boundary
  // (defense-in-depth — the circuit enforces this on-chain). Per CLAUDE.md
  // §"Permissions Model": bit 4 implies 2+3, bit 3 implies 2. A malformed
  // bitmask with bit 4 alone (no 2/3) used to upgrade to "unlimited"; reject
  // it here so a downstream caller never sees max authority from a
  // structurally-broken proof. Highest-tier-wins ONLY when the implication
  // holds; otherwise collapse to "none" with a warning.
  let tier: StripeACPSpendingTier;
  const cumulativeViolation =
    (financialUnlimited && !(financialMedium && financialSmall)) ||
    (financialMedium && !financialSmall);
  if (cumulativeViolation) {
    tier = 'none';
  } else if (financialUnlimited) {
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
    currency: normalizeCurrency(currency),
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

// Build a did:bolyra:<network>:<64-hex> from a verified commitment decimal.
// Internal; only called on values that have already passed
// validateBolyraVerifiedContext (so BigInt() is guaranteed safe).
function buildDid(network: string, commitmentDecimal: string): string {
  const hex = BigInt(commitmentDecimal).toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

/**
 * Reshape a verified Bolyra context into a Stripe ACP context.
 *
 * The caller is responsible for verification (via `@bolyra/mcp`'s
 * `verifyBundle` or direct SDK calls). The adapter trusts `ctx.verified`
 * after running runtime validation on the structurally-typed input.
 *
 * Codex P1-7 fix: `rootAgentDid` is derived from the verified `ctx.did`,
 * NOT from a caller-supplied commitment. The caller cannot rebind the
 * acting credential to an unrelated chain's root.
 *
 * @param ctx       Verified Bolyra context (leaf scope already collapsed).
 *                  Must be produced by a trusted verifier; the adapter runs
 *                  runtime validation but does NOT re-run ZKP verification.
 * @param network   DID network suffix used to derive `actingAgentDid` from
 *                  the leaf commitment (default "base-sepolia"). Should
 *                  match the network embedded in `ctx.did`.
 * @param currency  ISO 4217 currency for the limits (default "usd"). Stripe
 *                  uses lowercase; the adapter normalizes both sides.
 */
export function authContextToStripeACPContext(
  ctx: BolyraVerifiedContext,
  network: string = 'base-sepolia',
  currency: string = 'usd',
): StripeACPContext {
  validateBolyraVerifiedContext(ctx);

  if (typeof network !== 'string' || !/^[a-z0-9-]+$/.test(network)) {
    throw new TypeError(
      `authContextToStripeACPContext: network must match /^[a-z0-9-]+$/ (got ${String(network)})`,
    );
  }

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
  // Root agent = whichever DID the verifier already bound to the root
  // credential. Trusting `ctx.did` (rather than a caller-supplied commitment)
  // is what closes the Codex P1-7 hole: a caller cannot pass an allowlisted
  // root B while the verified chain anchors to root A.
  const rootAgentDid = ctx.did;

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
 * Operation surface for a Stripe ACP charge.
 *
 *   "authorize" — creating a PaymentIntent on behalf of the user (does NOT
 *                 require `SIGN_ON_BEHALF`).
 *   "confirm"   — confirming an existing PaymentIntent on the user's behalf
 *                 (REQUIRES `SIGN_ON_BEHALF` per CLAUDE.md §"Permissions Model"
 *                 bit 5).
 *
 * Defaults to "authorize" for backward compatibility. The README documents
 * "confirm" as the path that needs bit 5.
 */
export type StripeACPOperation = 'authorize' | 'confirm';

/**
 * Decide whether a proposed Stripe charge is authorized by the ACP context.
 *
 * Rules:
 *   1. Context must be verified.
 *   2. Currency must match.
 *   3. Amount must be a positive safe integer in minor units (Stripe rejects
 *      fractional or unsafe-integer cents).
 *   4. Tier must be "small" | "medium" | "unlimited" (not "none").
 *   5. For tiers other than "unlimited", amount must be STRICTLY LESS than
 *      the cap. CLAUDE.md defines bit 2 as `< $100` and bit 3 as `< $10K`,
 *      so $100 against tier=small or $10K against tier=medium is rejected.
 *   6. If `operation === "confirm"`, the leaf scope must include
 *      `SIGN_ON_BEHALF` (bit 5). `pi.confirm`-style paths fail closed
 *      without it.
 */
export function verifyStripeACPSpend(
  ctx: StripeACPContext,
  amount: number,
  currency: string,
  operation: StripeACPOperation = 'authorize',
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
  // Codex P2-5: Stripe sends lowercase currency codes. Normalize both sides
  // before comparing so an "usd" charge against a "USD"-defaulted context
  // isn't silently denied (or worse, treated as a different currency).
  if (normalizeCurrency(currency) !== normalizeCurrency(ctx.spendingLimits.currency)) {
    return {
      allowed: false,
      reason: `Currency mismatch: ctx=${ctx.spendingLimits.currency}, requested=${currency}.`,
      capChecked: cap,
      tier,
    };
  }
  // Codex P2-6 (HARDEN): Stripe amounts are integer minor units. 9999.5
  // cents must NEVER authorize; values above MAX_SAFE_INTEGER round before
  // comparison and can sneak past the cap. Require a finite, positive,
  // safe-integer minor-unit amount.
  if (
    typeof amount !== 'number' ||
    !Number.isInteger(amount) ||
    !Number.isSafeInteger(amount) ||
    amount <= 0
  ) {
    return {
      allowed: false,
      reason: `Invalid amount: ${amount} (must be a positive safe integer in minor units).`,
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
  // Codex P1-9 (HARDEN): the bit semantics in CLAUDE.md are strict-less-than
  // (`< $100`, `< $10K`). The previous `amount > cap` check allowed the
  // boundary value through — a $100 charge against tier=small or a $10K
  // charge against tier=medium. Reject `amount >= cap` for capped tiers.
  if (tier !== 'unlimited' && amount >= cap) {
    return {
      allowed: false,
      reason: `Amount ${amount} meets or exceeds ${tier}-tier cap of ${cap} ${currency} (cap is strict).`,
      capChecked: cap,
      tier,
    };
  }
  // Codex P1-6 (HARDEN): `pi.confirm` requires SIGN_ON_BEHALF (bit 5). The
  // previous adapter exposed the flag but left enforcement to integrators —
  // most treated `allowed: true` from this function as the final ACP
  // decision. Fail closed when the leaf scope is missing bit 5 and the
  // caller is asking about a confirm-class operation.
  if (operation === 'confirm' && !ctx.spendingLimits.signOnBehalf) {
    return {
      allowed: false,
      reason: 'Confirm operation requires SIGN_ON_BEHALF (bit 5) on the leaf scope.',
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
