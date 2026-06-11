# v0.5.0 Unified Commerce Authorization — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. **Codex review after each task.**

**Goal:** Ship `authorizeCommerceIntent()` — one API that answers whether a commerce intent is authorized across Stripe ACP, x402, Visa TAP, and Google AP2.

**Architecture:** One new file (`commerce-intent.ts`) in `@bolyra/payment-protocols`. Pure decision wrapper over existing adapter outputs. Stripe ACP and x402 fully wired; Visa TAP and AP2 stubbed fail-closed. x402 hardened with credential resolution + currency gates.

**Tech Stack:** TypeScript, Jest, `@bolyra/payment-protocols`, `@bolyra/sdk`

**Spec:** `docs/superpowers/specs/2026-06-11-v050-commerce-authorization-design.md`

---

## File Map

### New files
| File | Responsibility |
|------|---------------|
| `integrations/payment-protocols/src/commerce-intent.ts` | Types + `authorizeCommerceIntent()` + receipt generation |
| `integrations/payment-protocols/test/commerce-intent.test.ts` | Cross-rail authorization tests |

### Modified files
| File | Change |
|------|--------|
| `integrations/payment-protocols/src/x402.ts:375` | Hard-gate `credentialResolved`, add currency check, add fields to `X402VerifyDecision` |
| `integrations/payment-protocols/src/index.ts` | Export commerce types + function |
| `integrations/payment-protocols/package.json` | Version 0.5.0, SDK dep `^0.4.0` |
| `integrations/payment-protocols/test/x402.test.ts` | Add credential + currency gate tests |
| `CHANGELOG.md` | v0.5.0 entry |

---

## Task 1: x402 Hardening

**Files:**
- Modify: `integrations/payment-protocols/src/x402.ts`
- Modify: `integrations/payment-protocols/test/x402.test.ts`

- [ ] **Step 1: Read x402.ts and x402.test.ts to understand current patterns**

- [ ] **Step 2: Add `credentialResolved` and `currency` to `X402VerifyDecision`**

In `x402.ts`, add to the `X402VerifyDecision` interface (after `warnings`):

```typescript
/** Whether the credential was resolved via the resolver. */
credentialResolved: boolean;
/** Currency/asset from the bundle's spend policy. */
currency: string;
```

- [ ] **Step 3: Hard-gate `credentialResolved` in verify logic**

In `x402.ts:375`, change:
```typescript
// Before:
const verified = zkVerified && policyFit && score >= cfg.minScore;

// After:
const verified = zkVerified && credentialResolved && policyFit && score >= cfg.minScore;
```

- [ ] **Step 4: Add currency check against requirements**

After the policyFit check (~line 367), add:
```typescript
const currencyMatch = requirements.asset.toLowerCase() === bundle.spendPolicy.currency.toLowerCase();
if (!currencyMatch) {
  warnings.push(
    `currency mismatch: required ${requirements.asset}, bundle offers ${bundle.spendPolicy.currency}`,
  );
}
```

Update verified gate:
```typescript
const verified = zkVerified && credentialResolved && policyFit && currencyMatch && score >= cfg.minScore;
```

- [ ] **Step 5: Return the new fields**

In the return statement (~line 377), add:
```typescript
credentialResolved,
currency: bundle.spendPolicy.currency,
```

Also update the `rejection()` helper to include these fields with safe defaults.

- [ ] **Step 6: Add tests for credential + currency gates**

In `test/x402.test.ts`, add:
- Test: unresolved credential → `verified: false`, `credentialResolved: false`
- Test: currency mismatch → `verified: false`, warnings contain "currency mismatch"
- Test: `credentialResolved` field is `true` when resolver returns a credential

- [ ] **Step 7: Run tests**

Run: `cd ~/Projects/bolyra/integrations/payment-protocols && npx jest test/x402.test.ts`
Expected: All pass including new tests.

- [ ] **Step 8: Commit**

```
fix(payment-protocols): hard-gate x402 credential resolution + currency

verifyX402Authorization now requires credentialResolved for verified=true
and checks currency match against requirements. Previously an unresolved
credential scored 80 and passed the default minScore:70 gate.

Breaking: X402VerifyDecision gains credentialResolved + currency fields.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 2: Commerce Intent Types + authorizeCommerceIntent()

**Files:**
- Create: `integrations/payment-protocols/src/commerce-intent.ts`
- Modify: `integrations/payment-protocols/src/index.ts`

- [ ] **Step 1: Create `commerce-intent.ts` with types**

All types from spec Section 1: `CommerceRail`, `CommerceIntent`,
`CommerceAuthorizationInput`, `CommerceAuthorizationDecision`,
`CommerceAuthorizationReceipt`.

Import existing types from `./types` and `./x402`:
- `StripeACPSpendDecision`, `StripeACPContext`, `PaymentTrustGrade`,
  `AgentPaymentVerification`, `TAPVerificationResult` from `./types`
- `X402VerifyDecision` from `./x402`

- [ ] **Step 2: Implement receipt generation**

```typescript
import { createHash } from 'crypto';

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
```

- [ ] **Step 3: Implement `authorizeCommerceIntent()`**

```typescript
export function authorizeCommerceIntent(
  input: CommerceAuthorizationInput,
  options?: { issuedAt?: number },
): CommerceAuthorizationDecision {
  const issuedAt = options?.issuedAt ?? Math.floor(Date.now() / 1000);

  switch (input.intent.rail) {
    case 'stripe-acp':
      return authorizeStripe(input, issuedAt);
    case 'x402':
      return authorizeX402(input, issuedAt);
    case 'visa-tap':
      return stubDenial(input, 'visa-tap', issuedAt);
    case 'google-ap2':
      return stubDenial(input, 'google-ap2', issuedAt);
  }
}
```

- [ ] **Step 4: Implement Stripe ACP path**

```typescript
function authorizeStripe(
  input: CommerceAuthorizationInput & { intent: { rail: 'stripe-acp' } },
  issuedAt: number,
): CommerceAuthorizationDecision {
  const { spendDecision, acpContext } = input as any; // discriminated union
  const grade = gradeFromScore(acpContext.score);
  return {
    allowed: spendDecision.allowed,
    rail: 'stripe-acp',
    reason: spendDecision.reason,
    did: acpContext.actingAgentDid,
    score: acpContext.score,
    grade,
    intent: input.intent,
    warnings: acpContext.warnings ?? [],
    receipt: generateReceipt(input.intent, acpContext.actingAgentDid, spendDecision.allowed, issuedAt),
  };
}
```

Import or duplicate the `gradeFromScore` helper (check if it's exported
from x402.ts or types.ts — if not, inline a simple version).

- [ ] **Step 5: Implement x402 path**

```typescript
function authorizeX402(
  input: CommerceAuthorizationInput & { intent: { rail: 'x402' } },
  issuedAt: number,
): CommerceAuthorizationDecision {
  const { adapterResult } = input as any;
  const decision = adapterResult as X402VerifyDecision;

  // Commerce-layer gates (on top of adapter's own checks)
  let allowed = decision.verified;
  let reason = allowed ? undefined : (decision.warnings[0] ?? 'x402 verification failed');

  if (allowed && !decision.credentialResolved) {
    allowed = false;
    reason = 'credential not resolved';
  }

  if (allowed && input.intent.currency &&
      decision.currency.toLowerCase() !== input.intent.currency.toLowerCase()) {
    allowed = false;
    reason = `currency mismatch: intent=${input.intent.currency}, adapter=${decision.currency}`;
  }

  return {
    allowed,
    rail: 'x402',
    reason,
    did: decision.did,
    score: decision.score,
    grade: decision.grade,
    intent: input.intent,
    warnings: decision.warnings,
    receipt: generateReceipt(input.intent, decision.did, allowed, issuedAt),
  };
}
```

- [ ] **Step 6: Implement stub denial for TAP + AP2**

```typescript
function stubDenial(
  input: CommerceAuthorizationInput,
  rail: CommerceRail,
  issuedAt: number,
): CommerceAuthorizationDecision {
  const result = (input as any).adapterResult as AgentPaymentVerification;
  return {
    allowed: false,
    rail,
    reason: `${rail} commerce authorization is not fully wired in v0.5.0`,
    did: result.did ?? '',
    score: result.score ?? 0,
    grade: result.grade ?? 'F',
    intent: input.intent,
    warnings: result.warnings ?? [],
    receipt: generateReceipt(input.intent, result.did ?? '', false, issuedAt),
  };
}
```

- [ ] **Step 7: Export from index.ts**

Add to `integrations/payment-protocols/src/index.ts`:

```typescript
// Commerce Authorization (v0.5.0)
export {
  authorizeCommerceIntent,
} from './commerce-intent';
export type {
  CommerceRail,
  CommerceIntent,
  CommerceAuthorizationInput,
  CommerceAuthorizationDecision,
  CommerceAuthorizationReceipt,
} from './commerce-intent';
```

- [ ] **Step 8: Commit**

```
feat(payment-protocols): add authorizeCommerceIntent() — unified commerce layer

One API normalizes authorization across Stripe ACP, x402, Visa TAP,
and Google AP2. Stripe + x402 fully wired; TAP + AP2 stubbed fail-closed.
Unsigned deterministic receipts for logging.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 3: Cross-Rail Tests

**Files:**
- Create: `integrations/payment-protocols/test/commerce-intent.test.ts`

- [ ] **Step 1: Write tests**

11 test cases from the spec:

1. Stripe: allow under cap
2. Stripe: deny over cap
3. Stripe: deny confirm without SIGN_ON_BEHALF
4. x402: allow verified + amount fits
5. x402: deny unverified
6. x402: deny currency mismatch
7. x402: deny unresolved credential
8. Visa TAP: stub denial
9. Google AP2: stub denial
10. All rails: uniform shape (every field present)
11. Receipt determinism (fixed issuedAt → same ID)

Each test constructs a mock adapter result matching the real type shape,
calls `authorizeCommerceIntent()`, and asserts the decision.

- [ ] **Step 2: Run tests**

Run: `cd ~/Projects/bolyra/integrations/payment-protocols && npx jest test/commerce-intent.test.ts -v`
Expected: All 11 pass.

- [ ] **Step 3: Run full suite**

Run: `cd ~/Projects/bolyra/integrations/payment-protocols && npx jest`
Expected: All tests pass (existing + new).

- [ ] **Step 4: Commit**

```
test(payment-protocols): cross-rail commerce authorization tests

11 tests: Stripe allow/deny/SIGN_ON_BEHALF, x402 allow/deny/currency/credential,
TAP+AP2 stub denial, uniform shape, receipt determinism.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 4: Docs + Version Bump + Release

**Files:**
- Modify: `integrations/payment-protocols/package.json`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump version to 0.5.0 and SDK dep to ^0.4.0**

In `integrations/payment-protocols/package.json`:
- `"version": "0.5.0"`
- `"@bolyra/sdk": "^0.4.0"` (both dependencies and peerDependencies)

- [ ] **Step 2: Write CHANGELOG entry**

Add v0.5.0 section above the v0.4.0 entry. Cover:
- `authorizeCommerceIntent()` unified commerce layer
- x402 credential resolution + currency hard gates (breaking)
- Visa TAP + AP2 stubbed
- Unsigned `CommerceAuthorizationReceipt`

- [ ] **Step 3: Rebuild and verify**

```bash
cd ~/Projects/bolyra/integrations/payment-protocols
npm run build
npm pack --dry-run 2>&1 | grep commerce
```

Confirm `dist/commerce-intent.js` and `dist/commerce-intent.d.ts` in tarball.

- [ ] **Step 4: Run full test suite**

```bash
cd ~/Projects/bolyra/integrations/payment-protocols && npx jest
```

- [ ] **Step 5: Commit**

```
chore(payment-protocols): bump to 0.5.0, SDK dep to ^0.4.0

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

- [ ] **Step 6: Tag and publish**

```bash
cd ~/Projects/bolyra
git tag -s @bolyra/payment-protocols@0.5.0 -m "@bolyra/payment-protocols@0.5.0"
git push && git push origin @bolyra/payment-protocols@0.5.0
```
