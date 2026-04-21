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

## Design Principles

1. **Thin glue** — all cryptographic work delegates to `@bolyra/sdk`
2. **Lazy SDK import** — heavy crypto deps load only when needed
3. **Score-based results** — consistent with the OpenClaw adapter pattern
4. **Off-chain by default** — batch verification for high-throughput commerce
5. **Privacy-preserving** — merchant never learns more than necessary
6. **Protocol-agnostic core** — spend policy encoding works with any payment protocol

## License

Apache-2.0 — open-source protocol research.
