# Bolyra Quickstart

## Installation

```bash
npm install @bolyra/sdk
```

## Human Identity

```typescript
import { createHumanIdentity, proveHandshake } from "@bolyra/sdk";

// Create a human identity from a secret
const human = await createHumanIdentity(mySecret);
```

## Agent Credential

```typescript
import { createAgentCredential } from "@bolyra/sdk";

const agent = await createAgentCredential(
  modelHash,
  operatorPrivKey,
  permissions, // 8-bit cumulative encoding
  expiry
);
```

## Mutual Handshake

```typescript
import { proveHandshake, verifyHandshake } from "@bolyra/sdk";

const { humanProof, agentProof } = await proveHandshake(human, agent);
const valid = await verifyHandshake(humanProof, agentProof, nonce);
```

## Root Staleness and Proof Validity

The on-chain IdentityRegistry maintains a **root history buffer** of the
30 most recent Merkle roots for each identity tree (human and agent).
This means your proof remains valid even if new enrollments land between
the time you generate the proof and submit it for verification — as long
as fewer than 30 new enrollments have occurred for that tree.

If verification fails with a `RootNotFound` error, your proof was
generated against a root that has been evicted from the buffer.
**Regenerate the proof** against the current root and resubmit:

```typescript
// If verifyHandshake throws RootNotFound, regenerate:
const { humanProof, agentProof } = await proveHandshake(human, agent);
const valid = await verifyHandshake(humanProof, agentProof, freshNonce);
```

> **Tip:** In high-enrollment environments (>30 enrollments between proof
> generation and submission), consider submitting proofs promptly or
> listening for enrollment events to time your submissions.

## Permissions

Bolyra uses 8-bit cumulative encoding — higher tiers imply lower:

| Bit | Permission         | Notes              |
|-----|--------------------|--------------------||
| 0   | `READ_DATA`        |                    |
| 1   | `WRITE_DATA`       |                    |
| 2   | `FINANCIAL_SMALL`  | < $100             |
| 3   | `FINANCIAL_MEDIUM` | < $10K (implies 2) |
| 4   | `FINANCIAL_UNLIMITED` | implies 2+3     |
| 5   | `SIGN_ON_BEHALF`   |                    |
| 6   | `SUB_DELEGATE`     |                    |
| 7   | `ACCESS_PII`       |                    |

## Next Steps

- [Circuit formal properties](../circuits/FORMAL-PROPERTIES.md)
- [DID method specification](../spec/did-method-bolyra.md)
- [OWASP agentic threat mapping](owasp-agentic-mapping.md)
