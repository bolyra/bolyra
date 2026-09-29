# @bolyra/payment-protocols

> ZKP privacy layer for agentic commerce payment protocols.
> Open-source protocol research — not production software.

## What This Does

When AI agents make purchases on behalf of humans, payment networks need to verify:
1. **Is this agent authorized?** (identity)
2. **What can it spend?** (policy)
3. **Did the human consent?** (authorization)

Today, Visa's [Trusted Agent Protocol (TAP)](https://developer.visa.com/capabilities/trusted-agent-protocol) and Google's [Agent Payments Protocol (AP2)](https://github.com/google-agentic-commerce/AP2) answer these questions with centralized registries and plain-text mandates. The merchant sees everything — the user's identity, their exact budget, their full policy.

**Bolyra replaces that with zero-knowledge proofs.** The merchant learns only:
- "This agent is authorized" (yes/no)
- "The spend policy is sufficient for this transaction" (yes/no)
- A trust score (0–100)

The merchant never sees: the human's identity, the exact spend limit, the full vendor allowlist, or the delegation chain structure.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Human       │────▸│  Bolyra SDK      │────▸│  ZKP Proof   │
│  (identity)  │     │  (handshake +    │     │  (public      │
│              │     │   spend policy)  │     │   signals     │
└──────────────┘     └──────────────────┘     │   only)       │
                                              └──────┬───────┘
                                                     │
                              ┌───────────────────────┼───────────────────────┐
                              ▼                       ▼                       ▼
                     ┌────────────────┐     ┌────────────────┐     ┌─────────────────┐
                     │  Visa TAP      │     │  Google AP2    │     │  Spend Policy   │
                     │  Adapter       │     │  Adapter       │     │  Encoder        │
                     │                │     │                │     │                 │
                     │  TAP payment   │     │  AP2 mandate   │     │  Bitmask        │
                     │  signal +      │     │  proof +       │     │  encoding +     │
                     │  trust score   │     │  delegation    │     │  verification   │
                     └────────────────┘     └────────────────┘     └─────────────────┘
```

## Protocol Mapping

### Visa TAP

| TAP Concept | Bolyra Equivalent |
|---|---|
| Agent registry lookup | ZKP proof of human authorization |
| HTTP Message Signature (RFC 9421) | ZKP proof + scope commitment |
| Payment Instructions API | Spend policy encoded in permission bitmask |
| Payment Signals API | Scope commitment + agent nullifier |
| Trust tier | Score-based grading (A/B/C/D/F) |

### Google AP2

| AP2 Concept | Bolyra Equivalent |
|---|---|
| Intent Mandate | Bolyra handshake proof (human → agent) |
| Cart Mandate | Spend policy ZKP (covers specific transaction) |
| Payment Mandate | Off-chain verified proof (batch mode) |
| Agent-to-agent delegation | Bolyra delegation chain with hop tracking |
| Mandate signature | ZKP proof (Groth16 for human, PLONK for agent) |

### Stripe Agent Commerce Protocol (ACP)

| Stripe ACP Concept | Bolyra Equivalent |
|---|---|
| Acting agent | Leaf delegatee in the v=2 bundle's `delegationChain` |
| Originating agent | Root credential the human authorized at handshake |
| Delegation depth | `chainDepth` from the verified context |
| Spending cap | Collapsed from cumulative `FINANCIAL_*` bits (2/3/4) on the leaf scope |
| `sign_on_behalf` flag | Bit 5 of the leaf scope (for `pi.confirm` flows) |

The narrowing wedge: a root agent with `FINANCIAL_UNLIMITED` can delegate down to a sub-agent with `FINANCIAL_SMALL` ($100 cap). Stripe ACP sees only the leaf's $100 cap, even though the root could have spent more.

## Usage

### Visa TAP Verification

```typescript
import { createVisaTAPVerification } from '@bolyra/payment-protocols';

const result = await createVisaTAPVerification(
  humanIdentity,
  agentCredential,
  {
    maxTransactionAmount: 50_000, // $500
    maxCumulativeAmount: 100_000, // $1,000
    currency: 'USD',
    timeWindow: { start: now, end: now + 86400 },
  },
  {
    agentDid: 'did:bolyra:base-sepolia:...',
    merchantId: 'visa-merchant-123',
    amount: 5_000,
    currency: 'USD',
    transactionId: 'txn-abc-123',
  },
);

// result.verified: boolean
// result.score: 0-100
// result.grade: 'A' | 'B' | 'C' | 'D' | 'F'
// result.paymentSignal: opaque token for TAP Payment Signals API
```

### Google AP2 Agent Credential

```typescript
import { createAP2AgentCredential, verifyAP2AgentCredential } from '@bolyra/payment-protocols';

// Agent side: create credential
const credential = await createAP2AgentCredential(
  humanIdentity,
  agentCredential,
  [
    { name: 'purchase', maxAmount: 50_000, currency: 'USD' },
    { name: 'price_compare', maxAmount: 0, currency: 'USD' },
  ],
);

// Merchant side: verify credential
const verification = await verifyAP2AgentCredential(credential);
// verification.verified: boolean
// verification.score: 0-100
```

### Stripe ACP — narrowing wedge

```typescript
import {
  authContextToStripeACPContext,
  verifyStripeACPSpend,
} from '@bolyra/payment-protocols';
import { verifyBundle } from '@bolyra/mcp';

// 1. Verify the v=2 bundle once (handshake + delegation chain).
const ctx = await verifyBundle(bundle, mcpConfig);

// 2. Reshape into a Stripe ACP context. The leaf delegatee becomes the
//    acting agent; the root credential the human authorized stays as the
//    originating agent for audit.
// rootAgentDid comes from ctx.did (set by verifyBundle from the verified
// credential commitment) — no caller-supplied root, no chain rebinding.
const acp = authContextToStripeACPContext(
  ctx,
  'base-sepolia', // DID network for actingAgentDid (must match ctx.did's network)
  'usd',          // ISO 4217 currency; lowercase per Stripe convention
);

// 3. Gate each PaymentIntent against the leaf-narrowed cap.
const decision = verifyStripeACPSpend(acp, 5_000, 'USD'); // $50
if (!decision.allowed) {
  throw new Error(`Stripe ACP denied: ${decision.reason}`);
}

// Example: root had FINANCIAL_UNLIMITED, but the chain narrowed the leaf
// to FINANCIAL_SMALL. Stripe sees a $100 cap, not the root's authority.
//   decision.tier === 'small'
//   decision.capChecked === 10_000  // $100 in cents
```

### Spend Policy Encoding

```typescript
import { encodeSpendPolicy, verifySpendPolicyProof } from '@bolyra/payment-protocols';

// Encode for ZKP circuit
const bitmask = encodeSpendPolicy({
  maxTransactionAmount: 50_000,
  maxCumulativeAmount: 100_000,
  currency: 'USD',
  timeWindow: { start: now, end: now + 86400 },
  categoryRestriction: { allowedMCCs: ['5411', '5812'] },
});

// Merchant-side verification (from ZKP public signals)
const { satisfied, reasons } = verifySpendPolicyProof(bitmask, {
  minTransactionAmount: 10_000,
  requiredMCCs: ['5411'],
});
```

## x402 EVC profile — issuer-quoted payee binding (§4.2)

The x402 EVC authorization-evidence profile (`spec/x402-evc-profile-v0.md`)
carries "who permitted this spend?" through the 402/retry round-trip. Its
payee check is byte equality `audience === payTo`. When a 402 leg names a
placeholder `payTo` and carries an issuer-signed quote, an agent-side host
can bind the payee to the quote issuer instead:

```ts
import {
  createIssuerQuotePayeeResolver,
  verifyX402EvcAuthorization,
  x402LocalChallenge,
} from '@bolyra/payment-protocols';

const resolvePayee = await createIssuerQuotePayeeResolver({
  issuers: new Map([['https://x402.tavily.com', {
    payTo: 'urn:x402:agent-pay:see-quote', scheme: 'agent-pay', network: 'aws:base',
    audience: 'aws:marketplace', payToRole: 'seller',
    keys: new Map([['tavily-agentpay-x402-signing-key', { alg: 'ES384', jwk /* provisioned out of band */ }]]),
    products: new Map([['https://x402.tavily.com/search', {
      reference: 'tavily-search-advanced', 'settlement.product_id': 'prod-maeet6sajeg42',
    }]]),
    settlementFields: [
      { challenge: 'extra.reference', claim: 'reference' },
      { challenge: 'extra.settlement.product_id', claim: 'settlement.product_id' },
    ],
    unboundExtraFields: ['tier'], // present on the leg, unverified, never reaches checkedLeg
  }]]),
});

const local = x402LocalChallenge({
  headerValue: response.headers.get('payment-required')!, // exactly as received
  resource: 'https://x402.tavily.com/search',             // host-known outbound URL
  legIndex: 1, now: Math.floor(Date.now() / 1000), maxSeconds: 300,
});

const decision = await verifyX402EvcAuthorization(presentation, {
  localChallenge: local, audience: 'https://x402.tavily.com', resolvePayee,
  verifier: { kind: 'classical', trustedOperators }, nonceStore /* shared, durable */,
});
if (decision.allowed) settle(decision.checkedLeg); // the ONLY leg to settle
```

What a successful binding proves: the holder of the issuer's key quoted this
product at this price within this window, and the challenge's settlement
fields match that quote. What it does NOT prove: ownership of any derived
on-chain address (an unbound derived `payTo` still denies), that the quote
was addressed to this host, who ultimately receives funds, or delivery.
`x402_evc.payee_binding` is a host assertion for audit; `payee` stays the
literal placeholder, and receipts under spec §4.1 do not commit to the
binding. `token_sha256` is an audit handle, not a unique quote identifier
(ECDSA signatures are malleable); replay identity is `(issuer, jti)`. Keys
are never discovered; a resolver never touches the network. Any leaf under
`extra` that is not the token, a bound settlement field, or a declared
`unboundExtraFields` entry denies, and `checkedLeg.extra` carries only the
verified paths.

The issuer, key id and product identifiers above are the shape observed on
a public 402 on 2026-09-29 and are used as an example only; no endorsement
is implied.

## Design Principles

1. **Thin glue** — all cryptographic work delegates to `@bolyra/sdk`
2. **Lazy SDK import** — heavy crypto deps load only when needed
3. **Score-based results** — consistent with the OpenClaw adapter pattern
4. **Off-chain by default** — batch verification for high-throughput commerce
5. **Privacy-preserving** — merchant never learns more than necessary
6. **Protocol-agnostic core** — spend policy encoding works with any payment protocol

## License

Apache-2.0 — open-source protocol research.
