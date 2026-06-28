# Bolyra Quickstart

Get started with the Bolyra identity protocol in under 5 minutes.

## Install

```bash
npm install @bolyra/sdk
```

## Create a Human Identity

```typescript
import { createHumanIdentity } from "@bolyra/sdk";

const human = await createHumanIdentity("my-secret-entropy");
console.log("Commitment:", human.commitment);
```

## Create an Agent Credential

```typescript
import { createAgentCredential } from "@bolyra/sdk";

const agent = await createAgentCredential(
  modelHash,
  operatorPrivKey,
  0b00000011, // READ_DATA + WRITE_DATA
  Math.floor(Date.now() / 1000) + 3600 // 1 hour expiry
);
```

## Prove & Verify a Handshake

```typescript
import { proveHandshake, verifyHandshake } from "@bolyra/sdk";

// Generate proofs
const { humanProof, agentProof } = await proveHandshake(human, agent);

// Verify (on-chain)
const result = await verifyHandshake(humanProof, agentProof, nonce, {
  provider: "https://sepolia.base.org",
  registryAddress: "0x...",
});

// Verify (off-chain)
const offChainResult = await verifyHandshake(humanProof, agentProof, nonce, {
  historicalHumanRoots: ["0xabc...", "0xdef..."],
  historicalAgentRoots: ["0x123...", "0x456..."],
});
```

> **Proof validity window**: Human proofs are valid for up to 30
> subsequent enrollments, not indefinitely. The on-chain
> `IdentityRegistry` maintains a 30-root history ring buffer — once 30
> new humans enroll after your proof was generated, your proof's Merkle
> root is evicted and the proof becomes invalid. For long-lived sessions,
> subscribe to `HumanRootHistoryUpdated` events and re-prove before your
> root is evicted. See the [DID method spec](../spec/did-method-bolyra.md)
> for full semantics.

## Permissions (8-bit cumulative)

| Bit | Permission | Notes |
|-----|------------|-------|
| 0 | `READ_DATA` | |
| 1 | `WRITE_DATA` | |
| 2 | `FINANCIAL_SMALL` | < $100 |
| 3 | `FINANCIAL_MEDIUM` | < $10K (implies bit 2) |
| 4 | `FINANCIAL_UNLIMITED` | implies bits 2+3 |
| 5 | `SIGN_ON_BEHALF` | |
| 6 | `SUB_DELEGATE` | |
| 7 | `ACCESS_PII` | |

## Next Steps

- [DID Method Spec](../spec/did-method-bolyra.md)
- [OWASP Agentic Mapping](owasp-agentic-mapping.md)
- [Circuit Formal Properties](../circuits/FORMAL-PROPERTIES.md)
