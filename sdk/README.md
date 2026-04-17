# @bolyra/sdk

TypeScript SDK for **Bolyra (IdentityOS)** — mutual ZKP authentication for humans and AI agents.

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
} from '@bolyra/sdk';

// 1. Create a human identity (EdDSA keypair + Poseidon commitment)
const secret = BigInt(
  crypto.getRandomValues(new Uint8Array(32))
    .reduce((a, b) => a * 256n + BigInt(b), 0n)
);
const human = await createHumanIdentity(secret);
console.log('Human commitment:', human.commitment);
// => enroll human.commitment in the humanTree on-chain

// 2. Create an AI agent credential (operator-signed)
const modelHash = 42n; // hash of model identifier
const operatorKey = 123n; // operator's EdDSA private key
const expiry = BigInt(Math.floor(Date.now() / 1000) + 86400); // +1 day

const agent = await createAgentCredential(
  modelHash,
  operatorKey,
  [Permission.READ_DATA, Permission.WRITE_DATA],
  expiry,
);
console.log('Agent commitment:', agent.commitment);
// => enroll agent.commitment in the agentTree on-chain

// 3. Mutual handshake (coming in v0.2)
// const { humanProof, agentProof, nonce } = await proveHandshake(human, agent);
// const result = await verifyHandshake(humanProof, agentProof, nonce);
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
| `proveHandshake()`            | v0.2 (stub) |
| `verifyHandshake()`           | v0.2 (stub) |
| `delegate()`                  | v0.2 (stub) |
| `verifyDelegation()`          | v0.2 (stub) |

## License

MIT
