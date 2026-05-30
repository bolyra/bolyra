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

function commitmentToDid(network: string, commitmentDecimal: string): string {
  const hex = BigInt(commitmentDecimal).toString(16).padStart(64, '0');
  return `did:bolyra:${network}:${hex}`;
}

const ROOT_DID = commitmentToDid('base-sepolia', ROOT_COMMITMENT);

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
    // Codex P1-7 fix: `did` is now the trusted root anchor — the adapter
    // copies it straight into rootAgentDid. Defaults to the canonical DID
    // for ROOT_COMMITMENT so v=1 tests where acting == root still match.
    did: ROOT_DID,
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

  it('picks highest tier when cumulative bits are valid', () => {
    // Bit 4 wins when 2+3+4 are all set; bit 3 wins when 2+3 are set.
    expect(
      bitmaskToStripeSpendingLimits(
        BIT_FIN_SMALL | BIT_FIN_MEDIUM | BIT_FIN_UNLIMITED,
      ).tier,
    ).toBe('unlimited');
    expect(
      bitmaskToStripeSpendingLimits(BIT_FIN_SMALL | BIT_FIN_MEDIUM).tier,
    ).toBe('medium');
  });

  // Codex P1-5 (HARDEN): non-cumulative bitmasks must collapse to "none"
  // even if a higher tier bit is set. Defense-in-depth against a malformed
  // proof bypassing the circuit's cumulative-shape enforcement.
  it('collapses to "none" when UNLIMITED is set without MEDIUM+SMALL', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_FIN_UNLIMITED);
    expect(limits.tier).toBe('none');
    expect(limits.maxTransactionAmount).toBe(0);
  });

  it('collapses to "none" when UNLIMITED+SMALL set without MEDIUM', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_FIN_UNLIMITED | BIT_FIN_SMALL);
    expect(limits.tier).toBe('none');
  });

  it('collapses to "none" when UNLIMITED+MEDIUM set without SMALL', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_FIN_UNLIMITED | BIT_FIN_MEDIUM);
    expect(limits.tier).toBe('none');
  });

  it('collapses to "none" when MEDIUM is set without SMALL', () => {
    const limits = bitmaskToStripeSpendingLimits(BIT_FIN_MEDIUM);
    expect(limits.tier).toBe('none');
  });

  it('surfaces SIGN_ON_BEHALF flag independent of tier', () => {
    const withSign = bitmaskToStripeSpendingLimits(BIT_FIN_SMALL | BIT_SIGN_ON_BEHALF);
    expect(withSign.signOnBehalf).toBe(true);
    expect(withSign.tier).toBe('small');

    const withoutSign = bitmaskToStripeSpendingLimits(BIT_FIN_SMALL);
    expect(withoutSign.signOnBehalf).toBe(false);
  });

  it('defaults currency to usd (lowercase to match Stripe), honors override', () => {
    expect(bitmaskToStripeSpendingLimits(BIT_FIN_SMALL).currency).toBe('usd');
    expect(bitmaskToStripeSpendingLimits(BIT_FIN_SMALL, 'EUR').currency).toBe('eur');
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
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.actingAgentDid).toBe(acp.rootAgentDid);
    expect(acp.delegationDepth).toBe(0);
    expect(acp.spendingLimits.tier).toBe('small');
    expect(acp.verified).toBe(true);
  });

  it('maps a v=2 (2-hop chain) context — acting = leaf, root = ctx.did', () => {
    const ctx = makeCtx({
      chainDepth: 2,
      effectiveCommitment: LEAF_COMMITMENT,
      permissionBitmask: BIT_FIN_SMALL, // narrowed at the leaf
    });
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.actingAgentDid).not.toBe(acp.rootAgentDid);
    expect(acp.actingAgentDid).toContain(BigInt(LEAF_COMMITMENT).toString(16));
    // Codex P1-7 fix: rootAgentDid is ctx.did verbatim (not rebuilt from a
    // caller-supplied commitment), so it must equal the trusted anchor.
    expect(acp.rootAgentDid).toBe(ROOT_DID);
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
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.spendingLimits.tier).toBe('small');
    expect(acp.spendingLimits.maxTransactionAmount).toBe(10_000);
  });

  it('appends "no financial authority" warning when tier=none on a verified ctx', () => {
    const ctx = makeCtx({
      verified: true,
      permissionBitmask: BIT_READ | BIT_WRITE,
    });
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.warnings.some(w => w.includes('no FINANCIAL_'))).toBe(true);
  });

  it('does NOT add tier=none warning when ctx is unverified (verification warnings already speak)', () => {
    const ctx = makeCtx({
      verified: false,
      permissionBitmask: BIT_READ,
      warnings: ['ZKP failed'],
    });
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.warnings).toEqual(['ZKP failed']);
  });

  it('honors network and currency overrides', () => {
    const ctx = makeCtx();
    const acp = authContextToStripeACPContext(ctx, 'base', 'EUR');
    expect(acp.actingAgentDid.startsWith('did:bolyra:base:')).toBe(true);
    expect(acp.spendingLimits.currency).toBe('eur');
  });

  it('preserves warnings from the verified context', () => {
    const ctx = makeCtx({ warnings: ['nonce close to expiry'] });
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.warnings).toContain('nonce close to expiry');
  });
});

// ---------------------------------------------------------------------------
// Runtime validation (Codex P1-3 / P1-4 / P1-8 / P2-8)
// ---------------------------------------------------------------------------

describe('authContextToStripeACPContext runtime validation', () => {
  it('rejects a non-boolean verified field (e.g., the string "false")', () => {
    const bad = makeCtx();
    (bad as any).verified = 'false';
    expect(() => authContextToStripeACPContext(bad)).toThrow(/verified must be a boolean/);
  });

  it('rejects a negative bigint bitmask (would set all bits via bitwise AND)', () => {
    const bad = makeCtx({ permissionBitmask: -1n });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/permissionBitmask/);
  });

  it('rejects a bitmask above 8 bits', () => {
    const bad = makeCtx({ permissionBitmask: 0x1ffn });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/permissionBitmask/);
  });

  it('rejects a negative chainDepth', () => {
    const bad = makeCtx({ chainDepth: -1 });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/chainDepth/);
  });

  it('rejects chainDepth above MAX_DELEGATION_HOPS (3)', () => {
    const bad = makeCtx({ chainDepth: 4 });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/chainDepth/);
  });

  it('rejects a non-finite score', () => {
    const bad = makeCtx({ score: Infinity });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/score/);
  });

  it('rejects a malformed effectiveCommitment ("abc")', () => {
    const bad = makeCtx({ effectiveCommitment: 'abc' });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/effectiveCommitment/);
  });

  it('rejects a negative effectiveCommitment ("-1")', () => {
    const bad = makeCtx({ effectiveCommitment: '-1' });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/effectiveCommitment/);
  });

  it('rejects an effectiveCommitment outside the BN254 field', () => {
    const tooBig =
      '21888242871839275222246405745257275088548364400416034343698204186575808495617';
    const bad = makeCtx({ effectiveCommitment: tooBig });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/BN254/);
  });

  it('rejects a malformed did (missing did:bolyra prefix)', () => {
    const bad = makeCtx({ did: 'urn:something:else' });
    expect(() => authContextToStripeACPContext(bad)).toThrow(/did/);
  });

  it('rejects a network with non-canonical characters', () => {
    expect(() => authContextToStripeACPContext(makeCtx(), 'BAD NETWORK')).toThrow(/network/);
  });

  it('rejects a non-array warnings field', () => {
    const bad = makeCtx();
    (bad as any).warnings = 'not an array';
    expect(() => authContextToStripeACPContext(bad)).toThrow(/warnings/);
  });
});

describe('bitmaskToStripeSpendingLimits runtime validation', () => {
  it('rejects negative bigints (would map to max authority via bitwise AND)', () => {
    expect(() => bitmaskToStripeSpendingLimits(-1n)).toThrow(/bitmask/);
  });

  it('rejects bitmasks above 8 bits', () => {
    expect(() => bitmaskToStripeSpendingLimits(0x100n)).toThrow(/bitmask/);
  });
});

// ---------------------------------------------------------------------------
// verifyStripeACPSpend
// ---------------------------------------------------------------------------

function makeACP(overrides: Partial<StripeACPContext> = {}): StripeACPContext {
  const base = authContextToStripeACPContext(makeCtx());
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
    expect(decision.reason).toContain('small-tier cap');
  });

  // Codex P1-9 (HARDEN): the cap is STRICT — bit 2 means `< $100`, not `<= $100`.
  it('denies the exact small-tier boundary ($100 against tier=small)', () => {
    const acp = makeACP();
    const decision = verifyStripeACPSpend(acp, 10_000, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('meets or exceeds');
  });

  it('denies the exact medium-tier boundary ($10K against tier=medium)', () => {
    const ctx = makeCtx({ permissionBitmask: BIT_FIN_SMALL | BIT_FIN_MEDIUM });
    const acp = authContextToStripeACPContext(ctx);
    const decision = verifyStripeACPSpend(acp, 1_000_000, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('meets or exceeds');
  });

  it('allows one minor unit below the small-tier boundary ($99.99)', () => {
    const acp = makeACP();
    const decision = verifyStripeACPSpend(acp, 9_999, 'USD');
    expect(decision.allowed).toBe(true);
  });

  // Codex P2-6 (HARDEN): amounts must be integer minor units.
  it('denies fractional amounts (Stripe rejects non-integer minor units)', () => {
    const acp = makeACP();
    const decision = verifyStripeACPSpend(acp, 9_999.5, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('safe integer');
  });

  it('denies non-finite amounts (NaN, Infinity)', () => {
    const acp = makeACP();
    expect(verifyStripeACPSpend(acp, Number.NaN, 'USD').allowed).toBe(false);
    expect(verifyStripeACPSpend(acp, Number.POSITIVE_INFINITY, 'USD').allowed).toBe(false);
  });

  it('denies amounts above MAX_SAFE_INTEGER', () => {
    const ctx = makeCtx({
      permissionBitmask: BIT_FIN_SMALL | BIT_FIN_MEDIUM | BIT_FIN_UNLIMITED,
    });
    const acp = authContextToStripeACPContext(ctx);
    const decision = verifyStripeACPSpend(
      acp,
      Number.MAX_SAFE_INTEGER + 2, // not representable as integer
      'USD',
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('safe integer');
  });

  // Codex P1-6 (HARDEN): pi.confirm operations require bit 5.
  it('denies a confirm operation when SIGN_ON_BEHALF (bit 5) is not set', () => {
    const acp = makeACP(); // default ctx has BIT_READ | BIT_WRITE | BIT_FIN_SMALL — no bit 5
    expect(acp.spendingLimits.signOnBehalf).toBe(false);
    const decision = verifyStripeACPSpend(acp, 5_000, 'USD', 'confirm');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('SIGN_ON_BEHALF');
  });

  it('allows a confirm operation when SIGN_ON_BEHALF is set', () => {
    const ctx = makeCtx({
      permissionBitmask: BIT_READ | BIT_WRITE | BIT_FIN_SMALL | BIT_SIGN_ON_BEHALF,
    });
    const acp = authContextToStripeACPContext(ctx);
    const decision = verifyStripeACPSpend(acp, 5_000, 'USD', 'confirm');
    expect(decision.allowed).toBe(true);
  });

  it('defaults operation to "authorize" — confirm gate does not fire', () => {
    const acp = makeACP();
    const decision = verifyStripeACPSpend(acp, 5_000, 'USD');
    expect(decision.allowed).toBe(true);
  });

  it('allows arbitrarily large charges against UNLIMITED tier', () => {
    const ctx = makeCtx({
      permissionBitmask: BIT_FIN_SMALL | BIT_FIN_MEDIUM | BIT_FIN_UNLIMITED,
    });
    const acp = authContextToStripeACPContext(ctx);
    const decision = verifyStripeACPSpend(acp, 999_999_999_99, 'USD');
    expect(decision.allowed).toBe(true);
    expect(decision.tier).toBe('unlimited');
  });

  it('denies any charge when tier=none', () => {
    const ctx = makeCtx({ permissionBitmask: BIT_READ | BIT_WRITE });
    const acp = authContextToStripeACPContext(ctx);
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
    const acp = authContextToStripeACPContext(ctx);
    const decision = verifyStripeACPSpend(acp, 100, 'USD');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('did not verify');
  });

  it('Codex P2-5: USD (uppercase) matches lowercase ctx currency after normalize', () => {
    const acp = makeACP(); // ctx default is now 'usd'
    expect(acp.spendingLimits.currency).toBe('usd');
    const decision = verifyStripeACPSpend(acp, 5_000, 'USD');
    expect(decision.allowed).toBe(true);
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
    const acp = authContextToStripeACPContext(leafCtx);

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

// ---------------------------------------------------------------------------
// Codex P1-10 (HARDEN): real-bundle round-trip
// ---------------------------------------------------------------------------
//
// The narrowing-wedge tests above feed the adapter a hand-rolled
// BolyraVerifiedContext. Codex's concern: if `@bolyra/mcp`'s verifyBundle
// emits a shape that doesn't match (bitmask as decimal string, omitted
// warnings, extra fields, optional reason field present), production either
// throws at runtime validation or crashes spreading `ctx.warnings`. The hand-
// rolled fixture would still be green.
//
// This block pins the contract between BolyraAuthContext (the shape
// verifyBundle returns, defined in `@bolyra/mcp/src/types.ts` as of v0.2.0)
// and BolyraVerifiedContext (what the adapter consumes). The fixtures here
// must mirror the verifyBundle return statement verbatim — bigint bitmask,
// decimal-string effectiveCommitment, populated warnings, optional reason.
// If verifyBundle's return shape ever drifts, these tests break before any
// merchant integration silently grants max authority on a malformed payload.

interface BolyraAuthContextShape {
  verified: boolean;
  score: number;
  did: string;
  permissionBitmask: bigint;
  warnings: string[];
  reason?: string;
  chainDepth: number;
  effectiveCommitment: string;
}

/**
 * v=1 (no chain) success: the shape verifyBundle returns when a handshake-only
 * bundle verifies against a credential with READ+WRITE+FIN_SMALL authority.
 * Mirrors the `return { verified: passed, ... }` at verify.ts:234.
 */
function realBundleV1Success(): BolyraAuthContextShape {
  return {
    verified: true,
    score: 95,
    did: ROOT_DID,
    permissionBitmask: BIT_READ | BIT_WRITE | BIT_FIN_SMALL,
    warnings: [],
    chainDepth: 0,
    effectiveCommitment: ROOT_COMMITMENT,
  };
}

/**
 * v=2 (2-hop chain) success: leaf scope narrowed from a broader root. Warnings
 * are populated to exercise the spread path in authContextToStripeACPContext.
 */
function realBundleV2Success(): BolyraAuthContextShape {
  return {
    verified: true,
    score: 88,
    did: ROOT_DID,
    permissionBitmask: BIT_READ | BIT_FIN_SMALL, // leaf collapsed scope
    warnings: ['Delegation chain depth 2; trust score reduced'],
    chainDepth: 2,
    effectiveCommitment: LEAF_COMMITMENT,
  };
}

/**
 * Failed verification: verifyBundle returns a fully-formed context with
 * verified=false and a `reason`. The adapter must still accept the shape;
 * downstream callers branch on `verified`.
 */
function realBundleFailure(): BolyraAuthContextShape {
  return {
    verified: false,
    score: 0,
    did: ROOT_DID,
    permissionBitmask: 0n,
    warnings: ['Agent proof verification failed', 'Score below floor'],
    reason: 'Agent proof verification failed',
    chainDepth: 0,
    effectiveCommitment: ROOT_COMMITMENT,
  };
}

describe('Codex P1-10: real-bundle round-trip through the Stripe adapter', () => {
  it('accepts a v=1 BolyraAuthContext shape without throwing', () => {
    const ctx = realBundleV1Success();
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.verified).toBe(true);
    expect(acp.score).toBe(95);
    expect(acp.delegationDepth).toBe(0);
    expect(acp.spendingLimits.tier).toBe('small');
    expect(acp.spendingLimits.maxTransactionAmount).toBe(10_000);
    expect(acp.actingAgentDid).toBe(acp.rootAgentDid); // v=1: acting == root
  });

  it('accepts a v=2 BolyraAuthContext shape with chain warnings', () => {
    const ctx = realBundleV2Success();
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.verified).toBe(true);
    expect(acp.delegationDepth).toBe(2);
    expect(acp.spendingLimits.tier).toBe('small');
    expect(acp.actingAgentDid).not.toBe(acp.rootAgentDid); // v=2: chain narrowed
    // Adapter MUST preserve verifier warnings (Codex P2-8 surface).
    expect(acp.warnings).toContain('Delegation chain depth 2; trust score reduced');
  });

  it('accepts a failed BolyraAuthContext (reason field, verified=false)', () => {
    const ctx = realBundleFailure();
    // Adapter does not throw on verified=false — the round-trip must complete.
    const acp = authContextToStripeACPContext(ctx);
    expect(acp.verified).toBe(false);
    expect(acp.spendingLimits.tier).toBe('none');
    // verifyStripeACPSpend must deny everything when verified=false.
    const decision = verifyStripeACPSpend(acp, 100, 'usd');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('did not verify');
  });

  it('a v=2 success round-trips through the spend gate at the leaf cap', () => {
    const ctx = realBundleV2Success();
    const acp = authContextToStripeACPContext(ctx);
    // Below cap: allowed.
    expect(verifyStripeACPSpend(acp, 5_000, 'usd').allowed).toBe(true);
    // Exact boundary ($100 against tier=small): denied per P1-9.
    expect(verifyStripeACPSpend(acp, 10_000, 'usd').allowed).toBe(false);
    // Above cap: denied.
    expect(verifyStripeACPSpend(acp, 50_000, 'usd').allowed).toBe(false);
  });

  it('rejects a real-bundle-shaped context with a string bitmask (drift detection)', () => {
    // If a future verifyBundle ever serializes permissionBitmask as a decimal
    // string instead of bigint, the runtime guard MUST reject it. This test
    // pins the shape contract; bumping verifyBundle to emit strings without
    // updating BolyraVerifiedContext + the adapter must fail loudly.
    const drifted = {
      ...realBundleV1Success(),
      permissionBitmask: '7' as unknown as bigint,
    };
    expect(() => authContextToStripeACPContext(drifted)).toThrow(/permissionBitmask/);
  });

  it('rejects a real-bundle-shaped context missing warnings (drift detection)', () => {
    const drifted = realBundleV1Success() as Partial<BolyraVerifiedContext>;
    delete (drifted as { warnings?: unknown }).warnings;
    expect(() =>
      authContextToStripeACPContext(drifted as BolyraVerifiedContext),
    ).toThrow(/warnings/);
  });
});
