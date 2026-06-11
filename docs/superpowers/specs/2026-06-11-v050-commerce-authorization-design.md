# v0.5.0 Design: Unified Commerce Authorization

**Date:** 2026-06-11
**Status:** Approved
**Theme:** "One API answers whether this commerce intent is authorized, across all rails."

## Summary

v0.5.0 adds a unified commerce authorization layer to
`@bolyra/payment-protocols`. One new file (`commerce-intent.ts`) with a
`CommerceIntent` type, an `authorizeCommerceIntent()` decision function,
and an unsigned `CommerceAuthorizationReceipt`. Two adapters fully wired
(Stripe ACP, x402), two stubbed with fail-closed behavior (Visa TAP,
Google AP2).

## Motivation

The payment-protocols package has 4 adapters (Stripe ACP, Visa TAP,
Google AP2, x402) totaling ~2,300 lines. Each answers a slightly
different authorization question:

- Stripe ACP checks tier + caps + currency + `SIGN_ON_BEHALF`
- x402 checks `amount <= maxTransactionAmount` but doesn't hard-gate
  credential resolution or currency
- Visa TAP computes a trust score but doesn't make a pay/don't-pay
  decision
- Google AP2 verifies credential shape but doesn't authorize a concrete
  payment amount

No unified decision surface exists. A developer using multiple rails has
to understand each adapter's semantics independently.

## Non-Goals

- Signed receipts (no format defined, no partner waiting)
- Pluggable spend stores (pretending enforcement without real state is
  worse than no enforcement)
- Cumulative spend windows (needs idempotency, rollback, race handling)
- Deep Visa TAP / Google AP2 normalization (stub only in v0.5.0)
- SQL persistence
- Full conformance suite (v0.5.0 tests shape + obvious allow/deny)
- New package (stays in `@bolyra/payment-protocols`)
- Changes to `@bolyra/sdk` or `@bolyra/mcp` (stay at 0.4.0)

## 1. Types

### 1.1 `CommerceRail`

```typescript
export type CommerceRail = 'stripe-acp' | 'x402' | 'visa-tap' | 'google-ap2';
```

### 1.2 `CommerceIntent`

Normalized representation of what an agent wants to do with money.
Adapters produce rail-specific artifacts; `CommerceIntent` is what the
authorization decision operates on.

```typescript
export interface CommerceIntent {
  /** Which payment rail processes this intent. */
  rail: CommerceRail;
  /** Amount in minor units (cents for USD, wei for ETH). */
  amount: number;
  /** ISO 4217 currency code or crypto asset symbol (e.g., 'USD', 'ETH'). */
  currency: string;
  /** Merchant/recipient identifier (rail-specific). */
  merchantId?: string;
  /** Merchant Category Code for category-based policy. */
  mcc?: string;
  /** Operation type. Stripe ACP distinguishes authorize vs confirm. */
  operation?: 'authorize' | 'confirm';
  /** Idempotency key / transaction ID for dedup. */
  transactionId?: string;
  /** Pass-through metadata for adapters. */
  metadata?: Record<string, unknown>;
}
```

### 1.3 `CommerceAuthorizationInput`

Discriminated union: the intent plus the rail-specific adapter output
that has already been computed. `authorizeCommerceIntent()` does NOT
call adapters — the caller does that first and passes the result.

```typescript
export type CommerceAuthorizationInput =
  | {
      intent: CommerceIntent & { rail: 'stripe-acp' };
      /** Output of verifyStripeACPSpend(). */
      spendDecision: StripeACPSpendDecision;
      /** The StripeACPContext that produced the decision — carries did,
       *  score, warnings needed for the unified output. */
      acpContext: StripeACPContext;
    }
  | {
      intent: CommerceIntent & { rail: 'x402' };
      /** Output of verifyX402Authorization(). */
      adapterResult: X402VerifyDecision;
    }
  | {
      intent: CommerceIntent & { rail: 'visa-tap' };
      /** Output of createVisaTAPVerification() (async, returns full
       *  TAPVerificationResult). Do NOT use computeTAPScore() — it
       *  returns only { score, warnings }, not the full result. */
      adapterResult: TAPVerificationResult;
    }
  | {
      intent: CommerceIntent & { rail: 'google-ap2' };
      /** Output of verifyAP2AgentCredential(). */
      adapterResult: AgentPaymentVerification;
    };
```

**Type location notes (Codex finding):**
- `StripeACPSpendDecision` is in `types.ts:275` — has `allowed`,
  `reason`, `capChecked`, `tier` but NOT `did`, `score`, `grade`,
  or `warnings`. Those live on `StripeACPContext` (`types.ts:297`).
  The input must carry both.
- `X402VerifyDecision` is defined in `x402.ts:89`, not `types.ts`.
  It currently lacks `credentialResolved` and `currency` fields —
  these must be added as part of the x402 hardening (Section 3).
- `TAPVerificationResult` comes from `createVisaTAPVerification()`
  (async), not `computeTAPScore()` which returns a narrower shape.
- `AgentPaymentVerification.warnings` is optional — normalize to
  `warnings ?? []` when mapping to the unified output.

### 1.4 `CommerceAuthorizationDecision`

Uniform output shape regardless of rail.

```typescript
export interface CommerceAuthorizationDecision {
  /** Whether the intent is authorized. */
  allowed: boolean;
  /** Which rail was evaluated. */
  rail: CommerceRail;
  /** Human-readable reason when denied. */
  reason?: string;
  /** Agent DID from the verified handshake/credential. */
  did: string;
  /** Trust score (0-100), carried from the adapter. */
  score: number;
  /** Trust grade, carried from the adapter. */
  grade: PaymentTrustGrade;
  /** The normalized intent that was evaluated. */
  intent: CommerceIntent;
  /** Warnings from the adapter (non-fatal issues). */
  warnings: string[];
  /** Unsigned receipt for logging/audit. */
  receipt: CommerceAuthorizationReceipt;
}
```

### 1.5 `CommerceAuthorizationReceipt`

Unsigned, deterministic. For demos and logging only. Cryptographic
signing is deferred to v0.6.0.

```typescript
export interface CommerceAuthorizationReceipt {
  /** Schema version. */
  v: 1;
  /** Deterministic receipt ID (hash of intent + timestamp + rail). */
  id: string;
  /** Which rail. */
  rail: CommerceRail;
  /** SHA-256 hash of the serialized CommerceIntent. */
  intentHash: string;
  /** Agent DID. */
  did: string;
  /** Decision. */
  allowed: boolean;
  /** Unix seconds when the decision was made. */
  issuedAt: number;
}
```

Receipt ID generation: `SHA-256(JSON.stringify({ intentHash, did,
issuedAt, rail }))` truncated to first 16 hex chars. Deterministic
given the same inputs.

**`issuedAt` injection (Codex finding):** `authorizeCommerceIntent()`
accepts an optional `options?: { issuedAt?: number }` second parameter.
Defaults to `Math.floor(Date.now() / 1000)`. Tests pass a fixed
timestamp for deterministic receipt assertions.

## 2. `authorizeCommerceIntent()`

Pure, synchronous decision function. No I/O, no state, no side effects.

```typescript
export function authorizeCommerceIntent(
  input: CommerceAuthorizationInput,
): CommerceAuthorizationDecision;
```

### 2.1 Stripe ACP path (`rail: 'stripe-acp'`)

Maps `StripeACPSpendDecision` + `StripeACPContext` to the unified
decision shape:

- `allowed` = `spendDecision.allowed`
- `reason` = `spendDecision.reason`
- `did` = `acpContext.did`
- `score` = `acpContext.score`
- `grade` = derive from score (same thresholds as other adapters), or
  use `acpContext.grade` if available. If `StripeACPContext` has no
  `grade` field, compute it: `score >= 80 → 'high'`, etc.
- `warnings` = `acpContext.warnings ?? []`

No new authorization logic. Pure mapping. Stripe ACP already enforces
tier, cap, currency, and `SIGN_ON_BEHALF` for confirm operations.

### 2.2 x402 path (`rail: 'x402'`)

Maps the existing `X402VerifyDecision` to the unified shape, with two
hardening gates added:

1. **Credential resolution gate:** If the adapter result indicates
   credential was not resolved (`credentialResolved === false` or
   equivalent field), deny. Current code at `x402.ts:375` scores this
   but doesn't gate `verified`. v0.5.0 makes it a hard requirement.

2. **Currency match gate:** If `intent.currency` doesn't match the
   adapter result's currency/asset, deny with
   `"currency mismatch: intent=${intent.currency}, adapter=${actual}"`.

All other fields map directly from the adapter result.

### 2.3 Visa TAP path (`rail: 'visa-tap'`) — STUB

Returns:
```typescript
{
  allowed: false,
  reason: 'visa-tap commerce authorization is not fully wired in v0.5.0',
  // score, grade, did, warnings carried from adapter result
}
```

Fail-closed. The adapter output's `score`, `grade`, `did`, and
`warnings` are still populated for demos and dashboards. Only `allowed`
is forced to `false`.

### 2.4 Google AP2 path (`rail: 'google-ap2'`) — STUB

Same pattern as Visa TAP:
```typescript
{
  allowed: false,
  reason: 'google-ap2 commerce authorization is not fully wired in v0.5.0',
}
```

## 3. x402 Hardening

**Pre-existing bug (Codex finding):** `verifyX402Authorization()` at
`x402.ts:375` does not require `credentialResolved` for `verified` to be
`true`. An agent with an unresolved credential can pass verification
(scores 80 with default `minScore: 70`).

**Fix:** In `verifyX402Authorization()`, add credential resolution as a
hard gate before setting `verified = true`. This is a production bug fix
independent of the commerce intent layer.

**Currency check:** Also verify that the x402 bundle's currency/asset
matches the server requirements. Current code checks amount but not
currency.

**Type change (Codex finding):** `X402VerifyDecision` (defined in
`x402.ts:89`, not `types.ts`) currently lacks `credentialResolved` and
`currency` fields. Add them to the return type so the commerce layer
can read them:

```typescript
// Add to X402VerifyDecision
credentialResolved: boolean;
currency: string;  // from the bundle's spend policy or requirements
```

Both fixes ship as part of v0.5.0 since they affect x402 correctness
regardless of the commerce layer.

## 4. File Map

### New files
| File | Responsibility |
|------|---------------|
| `integrations/payment-protocols/src/commerce-intent.ts` | Types + `authorizeCommerceIntent()` + receipt generation |
| `integrations/payment-protocols/test/commerce-intent.test.ts` | Cross-rail authorization tests |

### Modified files
| File | Change |
|------|--------|
| `integrations/payment-protocols/src/x402.ts` | Hard-gate credential resolution + currency match |
| `integrations/payment-protocols/src/index.ts` | Export `authorizeCommerceIntent`, types |
| `integrations/payment-protocols/src/types.ts` | Add commerce types (or import from commerce-intent.ts) |
| `integrations/payment-protocols/package.json` | Version bump to 0.5.0 |
| `CHANGELOG.md` | v0.5.0 entry |

### Unchanged
| File | Why |
|------|-----|
| `stripe-acp.ts` | Already correct; commerce layer wraps its output |
| `visa-tap.ts` | Stubbed, no changes needed |
| `google-ap2.ts` | Stubbed, no changes needed |
| `spend-policy.ts` | Not reconciled with commerce layer in v0.5.0 |
| `sdk/` | No changes |
| `integrations/mcp/` | No changes |

## 5. Tests

`integrations/payment-protocols/test/commerce-intent.test.ts`:

| Test Case | Rail | Asserts |
|-----------|------|---------|
| Allow under cap | stripe-acp | `allowed: true`, receipt generated |
| Deny over cap | stripe-acp | `allowed: false`, reason includes "cap" |
| Deny confirm without SIGN_ON_BEHALF | stripe-acp | `allowed: false`, reason includes "SIGN_ON_BEHALF" |
| Allow verified + amount fits | x402 | `allowed: true` |
| Deny unverified | x402 | `allowed: false` |
| Deny currency mismatch | x402 | `allowed: false`, reason includes "currency mismatch" |
| Deny unresolved credential | x402 | `allowed: false`, reason includes "credential" |
| Stub denial | visa-tap | `allowed: false`, reason includes "not fully wired" |
| Stub denial | google-ap2 | `allowed: false`, reason includes "not fully wired" |
| Uniform shape | all | Every decision has `allowed`, `rail`, `did`, `score`, `grade`, `intent`, `warnings`, `receipt` |
| Receipt determinism | stripe-acp | Same input + fixed `issuedAt` produces same receipt ID |

Additionally, **direct x402 hardening tests** in the existing
`test/x402.test.ts` (not just via the commerce wrapper):

| Test Case | Asserts |
|-----------|---------|
| Deny unresolved credential | `verifyX402Authorization()` returns `verified: false` when credential is not resolved |
| Deny currency mismatch | `verifyX402Authorization()` returns `verified: false` when bundle currency differs from requirements |

## 6. Version Bump

| Package | Current | v0.5.0 | Reason |
|---------|---------|--------|--------|
| `@bolyra/payment-protocols` | 0.3.1 | 0.5.0 | Commerce authorization layer, x402 hardening |
| `@bolyra/sdk` | 0.4.0 | 0.4.0 | unchanged |
| `@bolyra/mcp` | 0.4.0 | 0.4.0 | unchanged |
| `@bolyra/openclaw` | 0.3.0 | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.3.0 | 0.3.0 | unchanged |

Cohort base advances to 0.5. Per cohort policy, only the package with
runtime changes bumps.

Note: skipping 0.4.x for payment-protocols because the cohort base is
now 0.4 (from SDK/MCP). Jumping to 0.5.0 keeps the cohort aligned.

**Dep range (Codex finding):** `@bolyra/payment-protocols` currently
depends on `@bolyra/sdk ^0.3.0`. Bump to `^0.4.0` to align with the
published SDK. The x402 and Stripe adapters import SDK types; the
range should match what's tested against.

## 7. Implementation Order

1. x402 hardening (credential resolution + currency gate)
2. Commerce types in `commerce-intent.ts`
3. `authorizeCommerceIntent()` — Stripe ACP path
4. `authorizeCommerceIntent()` — x402 path
5. `authorizeCommerceIntent()` — TAP + AP2 stubs
6. Receipt generation
7. Export from `index.ts`
8. Tests
9. CHANGELOG, version bump, release

## 8. Success Criteria

- `authorizeCommerceIntent()` returns the same shape for all 4 rails
- Stripe ACP allow/deny matches existing `verifyStripeACPSpend()` logic
- x402 denies on unresolved credential (new behavior)
- x402 denies on currency mismatch (new behavior)
- TAP and AP2 always deny with clear message
- Receipt ID is deterministic
- All existing payment-protocols tests still pass
- New commerce-intent tests pass

## 9. Risks

- **Adapter type drift:** The `CommerceAuthorizationInput` union
  references specific adapter result types. If adapter return types
  change in a future release, the union breaks at compile time (which
  is the desired behavior — forces update).
- **Stub confusion:** Developers may not realize TAP/AP2 always deny.
  Mitigated by: clear reason string, README documentation, JSDoc on the
  stub paths.
- **x402 hardening is breaking:** Denying on unresolved credentials
  changes behavior. Any existing x402 consumer that relied on
  `verified: true` without credential resolution will break. This is
  the correct behavior — the old behavior was a bug — but document it
  as a breaking change in CHANGELOG.

## 10. Deferred to v0.6.0

- Signed `CommerceAuthorizationReceipt` with cryptographic attestation
- Pluggable spend stores (`NoopSpendStore`, `MemorySpendStore`,
  `SqlSpendStore`)
- Cumulative spend windows with idempotency and rollback
- Full Visa TAP and Google AP2 authorization wiring
- Cross-rail conformance suite (amount boundaries, MCC restrictions,
  replay protection)
- Spend policy reconciliation with commerce layer
