# @bolyra/sdk

TypeScript SDK for **Bolyra** — mutual ZKP authentication for humans and AI agents.

> **New here?** Start with the [5-minute Quickstart](./QUICKSTART.md) — from `npm install` to on-chain verification.

## Install

```bash
npm install @bolyra/sdk
```

## Quick Start

```typescript
import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  proveHandshake,
  verifyHandshake,
} from '@bolyra/sdk';

// 1. Create identities
const human = await createHumanIdentity(123456789n);
const agent = await createAgentCredential(
  12345n,
  operatorPrivateKey,
  [Permission.READ_DATA, Permission.WRITE_DATA],
  BigInt(Math.floor(Date.now() / 1000) + 86400),
);

// 2. Generate mutual handshake proofs (parallel, ~16s)
const { humanProof, agentProof, nonce } = await proveHandshake(human, agent);

// 3. Verify locally
const result = await verifyHandshake(humanProof, agentProof, nonce);
console.log('Verified:', result.verified); // true
console.log('Human nullifier:', result.humanNullifier);
console.log('Agent scope commitment:', result.scopeCommitment);

// 4. Submit to chain (via ethers.js)
// await registry.verifyHandshake(humanProof, agentProof, nonce);
```

## Permissions

Permissions use cumulative bit encoding — higher tiers imply lower ones:

| Bit | Permission          | Notes                    |
|-----|---------------------|--------------------------|
| 0   | `READ_DATA`         |                          |
| 1   | `WRITE_DATA`        |                          |
| 2   | `FINANCIAL_SMALL`   | < $100                   |
| 3   | `FINANCIAL_MEDIUM`  | < $10,000 (implies bit 2)|
| 4   | `FINANCIAL_UNLIMITED`| Unlimited (implies 2+3) |
| 5   | `SIGN_ON_BEHALF`    |                          |
| 6   | `SUB_DELEGATE`      |                          |
| 7   | `ACCESS_PII`        |                          |

## API Status

| Function                      | Status |
|-------------------------------|--------|
| `createHumanIdentity()`       | v0.1   |
| `createAgentCredential()`     | v0.1   |
| `permissionsToBitmask()`      | v0.1   |
| `validateCumulativeBitEncoding()` | v0.1 |
| `proveHandshake()`            | v0.2   |
| `verifyHandshake()`           | v0.2   |
| `delegate()`                  | v0.3 (stub) |
| `verifyDelegation()`          | v0.3 (stub) |

## License

Apache-2.0 — see [LICENSE](../LICENSE).
