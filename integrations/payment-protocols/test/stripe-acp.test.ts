/**
 * Stripe ACP adapter tests — pure mapping layer, no SDK calls.
 *
 * Covers:
 *   - Bitmask → tier collapse (none / small / medium / unlimited)
 *   - Verified-context → ACP context (acting agent = leaf, root = root)
 *   - Spend authorization gate (currency, amount, tier, verified)
 *   - Narrowing story: root unlimited → hop1 medium → hop2 small, Stripe
 *     sees only the leaf cap.
 */

import {
  bitmaskToStripeSpendingLimits,
  authContextToStripeACPContext,
  verifyStripeACPSpend,
} from '../src/stripe-acp';
import type { BolyraVerifiedContext, StripeACPContext } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ROOT_COMMITMENT = '111111111111111111111111111';
const LEAF_COMMITMENT = '999999999999999999999999999';

// Bolyra cumulative bits per CLAUDE.md §"Permissions Model"
const BIT_READ = 0b00000001n;
const BIT_WRITE = 0b00000010n;
const BIT_FIN_SMALL = 0b00000100n;
const BIT_FIN_MEDIUM = 0b00001000n;
const BIT_FIN_UNLIMITED = 0b00010000n;
const BIT_SIGN_ON_BEHALF = 0b00100000n;

function makeCtx(overrides: Partial<BolyraVerifiedContext> = {}): BolyraVerifiedContext {
  return {
    verified: true,
    score: 100,
    did: `did:bolyra:base-sepolia:${'0'.repeat(63)}1`,
    permissionBitmask: BIT_READ | BIT_WRITE | BIT_FIN_SMALL,
    chainDepth: 0,
    effectiveCommitment: ROOT_COMMITMENT,
    warnings: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// bitmaskToStripeSpendingLimits
// ---------------------------------------------------------------------------

describe('bitmaskToStripeSpendingLimits', () => {
  it('tier="none" when no financial bits set', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_READ | BIT_WRITE);
    expect(limits.tier).toBe('none');
    expect(limits.maxTransactionAmount).toBe(0);
    expect(limits.financialSmall).toBe(false);
    expect(limits.financialMedium).toBe(false);
    expect(limits.financialUnlimited).toBe(false);
  });

  it('tier="small" with $100 cap when only FINANCIAL_SMALL', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_READ | BIT_FIN_SMALL);
    expect(limits.tier).toBe('small');
    expect(limits.maxTransactionAmount).toBe(10_000); // $100 in cents
    expect(limits.financialSmall).toBe(true);
    expect(limits.financialMedium).toBe(false);
  });

  it('tier="medium" with $10K cap when MEDIUM+SMALL set (cumulative)', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_FIN_SMALL | BIT_FIN_MEDIUM);
    expect(limits.tier).toBe('medium');
    expect(limits.maxTransactionAmount).toBe(1_000_000); // $10K in cents
    expect(limits.financialMedium).toBe(true);
    expect(limits.financialSmall).toBe(true);
  });

  it('tier="unlimited" with no cap when UNLIMITED+MEDIUM+SMALL set', () => {
    const limits = bitmaskToStripeSpendingLimits(
      BIT_FIN_SMALL | BIT_FIN_MEDIUM | BIT_FIN_UNLIMITED,
    );
    expect(limits.tier).toBe('unlimited');
    expect(limits.maxTransactionAmount).toBe(0); // 0 means "no cap" for unlimited tier
    expect(limits.financialUnlimited).toBe(true);
  });

  it('picks highest tier when bits collide (bit 4 wins over 3 wins over 2)', () => {
    // Highest-bit-wins even if implication is broken — circuit enforces cumulative shape.
    expect(bitmaskToStripeSpendingLimits(BIT_FIN_UNLIMITED).tier).toBe('unlimited');
    expect(bitmaskToStripeSpendingLimits(BIT_FIN_MEDIUM).tier).toBe('medium');
  });

  it('surfaces SIGN_ON_BEHALF flag independent of tier', () => {
    const withSign = bitmaskToStripeSpendingLimits(BIT_FIN_SMALL | BIT_SIGN_ON_BEHALF);
    expect(withSign.signOnBehalf).toBe(true);
    expect(withSign.tier).toBe('small');

    const withoutSign = bitmaskToStripeSpendingLimits(BIT_FIN_SMALL);
    expect(withoutSign.signOnBehalf).toBe(false);
  });

  it('defaults currency to USD, honors override', () => {
    expect(bitmaskToStripeSpendingLimits(BIT_FIN_SMALL).currency).toBe('USD');
    expect(bitmaskToStripeSpendingLimits(BIT_FIN_SMALL, 'EUR').currency).toBe('EUR');
  });
});

// ---------------------------------------------------------------------------
// authContextToStripeACPContext
// ---------------------------------------------------------------------------

describe('authContextToStripeACPContext', () => {
  it('maps a v=1 (no chain) context — acting == root', () => {
    const ctx = makeCtx({
      chainDepth: 0,
      effectiveCommitment: ROOT_COMMITMENT,
    });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    expect(acp.actingAgentDid).toBe(acp.rootAgentDid);
    expect(acp.delegationDepth).toBe(0);
    expect(acp.spendingLimits.tier).toBe('small');
    expect(acp.verified).toBe(true);
  });

  it('maps a v=2 (2-hop chain) context — acting = leaf, root = root', () => {
    const ctx = makeCtx({
      chainDepth: 2,
      effectiveCommitment: LEAF_COMMITMENT,
      permissionBitmask: BIT_FIN_SMALL, // narrowed at the leaf
    });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    expect(acp.actingAgentDid).not.toBe(acp.rootAgentDid);
    expect(acp.actingAgentDid).toContain(BigInt(LEAF_COMMITMENT).toString(16));
    expect(acp.rootAgentDid).toContain(BigInt(ROOT_COMMITMENT).toString(16));
    expect(acp.delegationDepth).toBe(2);
    expect(acp.spendingLimits.tier).toBe('small');
  });

  it('uses leaf scope for limits, not root authority (narrowing wedge)', () => {
    // Root authorized UNLIMITED but the chain narrowed the leaf to SMALL.
    // The Stripe ACP context must reflect the leaf cap ($100), not the root's.
    const ctx = makeCtx({
      chainDepth: 2,
      effectiveCommitment: LEAF_COMMITMENT,
      permissionBitmask: BIT_FIN_SMALL,
    });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    expect(acp.spendingLimits.tier).toBe('small');
    expect(acp.spendingLimits.maxTransactionAmount).toBe(10_000);
  });

  it('appends "no financial authority" warning when tier=none on a verified ctx', () => {
    const ctx = makeCtx({
      verified: true,
      permissionBitmask: BIT_READ | BIT_WRITE,
    });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    expect(acp.warnings.some(w => w.includes('no FINANCIAL_'))).toBe(true);
  });

  it('does NOT add tier=none warning when ctx is unverified (verification warnings already speak)', () => {
    const ctx = makeCtx({
      verified: false,
      permissionBitmask: BIT_READ,
      warnings: ['ZKP failed'],
    });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    expect(acp.warnings).toEqual(['ZKP failed']);
  });

  it('honors network and currency overrides', () => {
    const ctx = makeCtx();
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT, 'base', 'EUR');
    expect(acp.actingAgentDid.startsWith('did:bolyra:base:')).toBe(true);
    expect(acp.spendingLimits.currency).toBe('EUR');
  });

  it('preserves warnings from the verified context', () => {
    const ctx = makeCtx({ warnings: ['nonce close to expiry'] });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    expect(acp.warnings).toContain('nonce close to expiry');
  });
});

// ---------------------------------------------------------------------------
// verifyStripeACPSpend
// ---------------------------------------------------------------------------

function makeACP(overrides: Partial<StripeACPContext> = {}): StripeACPContext {
  const base = authContextToStripeACPContext(makeCtx(), ROOT_COMMITMENT);
  return { ...base, ...overrides };
}

describe('verifyStripeACPSpend', () => {
  it('allows a $50 charge against a SMALL-tier context', () => {
    const acp = makeACP(); // tier=small, cap=$100
    const decision = verifyStripeACPSpend(acp, 5_000, 'USD');
    expect(decision.allowed).toBe(true);
    expect(decision.tier).toBe('small');
    expect(decision.capChecked).toBe(10_000);
  });

  it('denies a $200 charge against a SMALL-tier context', () => {
    const acp = makeACP();
    const decision = verifyStripeACPSpend(acp, 20_000, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('exceeds small-tier cap');
  });

  it('allows arbitrarily large charges against UNLIMITED tier', () => {
    const ctx = makeCtx({
      permissionBitmask: BIT_FIN_SMALL | BIT_FIN_MEDIUM | BIT_FIN_UNLIMITED,
    });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    const decision = verifyStripeACPSpend(acp, 999_999_999_99, 'USD');
    expect(decision.allowed).toBe(true);
    expect(decision.tier).toBe('unlimited');
  });

  it('denies any charge when tier=none', () => {
    const ctx = makeCtx({ permissionBitmask: BIT_READ | BIT_WRITE });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    const decision = verifyStripeACPSpend(acp, 1, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('no FINANCIAL_');
  });

  it('denies on currency mismatch', () => {
    const acp = makeACP();
    const decision = verifyStripeACPSpend(acp, 100, 'EUR');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('Currency mismatch');
  });

  it('denies on zero or negative amount', () => {
    const acp = makeACP();
    expect(verifyStripeACPSpend(acp, 0, 'USD').allowed).toBe(false);
    expect(verifyStripeACPSpend(acp, -1, 'USD').allowed).toBe(false);
  });

  it('denies when context did not verify', () => {
    const ctx = makeCtx({ verified: false });
    const acp = authContextToStripeACPContext(ctx, ROOT_COMMITMENT);
    const decision = verifyStripeACPSpend(acp, 100, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('did not verify');
  });
});

// ---------------------------------------------------------------------------
// End-to-end narrowing scenario (the Phase 5c wedge)
// ---------------------------------------------------------------------------

describe('narrowing wedge: root UNLIMITED → hop1 MEDIUM → hop2 SMALL', () => {
  it('Stripe sees the leaf-narrowed cap, not the root authority', () => {
    // Root agent had UNLIMITED authority. After two delegation hops the
    // acting agent is restricted to SMALL ($100 max). Stripe ACP must enforce
    // the $100 cap and reject larger charges, even though the root could
    // have spent more.
    const leafCtx = makeCtx({
      chainDepth: 2,
      effectiveCommitment: LEAF_COMMITMENT,
      permissionBitmask: BIT_READ | BIT_WRITE | BIT_FIN_SMALL,
    });
    const acp = authContextToStripeACPContext(leafCtx, ROOT_COMMITMENT);

    // Acting != root, both DIDs surfaced for audit
    expect(acp.actingAgentDid).not.toBe(acp.rootAgentDid);
    expect(acp.delegationDepth).toBe(2);
    expect(acp.spendingLimits.tier).toBe('small');

    // $50 PaymentIntent → allowed.
    expect(verifyStripeACPSpend(acp, 5_000, 'USD').allowed).toBe(true);

    // $500 PaymentIntent → denied (narrowed cap is $100, even though
    // upstream root had UNLIMITED).
    const overCap = verifyStripeACPSpend(acp, 50_000, 'USD');
    expect(overCap.allowed).toBe(false);
    expect(overCap.tier).toBe('small');
    expect(overCap.capChecked).toBe(10_000);
  });
});
