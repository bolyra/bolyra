# Bolyra Quickstart — 5 Minutes to Mutual ZKP Authentication

## Prerequisites

- Node.js 18+
- npm or yarn

## Install

```bash
npm install @bolyra/sdk
```

## 1. Create a Human Identity (30 seconds)

```typescript
import { createHumanIdentity } from '@bolyra/sdk';

// Generate a random secret (in production, derive from a secure source)
const secret = BigInt('0x' + crypto.randomUUID().replace(/-/g, ''));
const human = await createHumanIdentity(secret);

console.log('Human commitment:', human.commitment);
// This commitment is enrolled in the on-chain humanTree
```

## 2. Create an Agent Credential (30 seconds)

```typescript
import { createAgentCredential, Permission } from '@bolyra/sdk';

const agent = await createAgentCredential(
  12345n,                           // model hash (e.g., hash of "gpt-4o")
  operatorPrivateKey,               // 32-byte EdDSA private key (Buffer)
  [Permission.READ_DATA, Permission.WRITE_DATA],  // permissions
  BigInt(Math.floor(Date.now() / 1000) + 86400),   // expires in 24h
);

console.log('Agent commitment:', agent.commitment);
// This commitment is enrolled in the on-chain agentTree
```

## 3. Mutual Handshake (the magic part)

```typescript
import { proveHandshake, verifyHandshake } from '@bolyra/sdk';

// Generate both proofs in parallel (~16 seconds)
const { humanProof, agentProof, nonce } = await proveHandshake(human, agent);

// Verify locally
const result = await verifyHandshake(humanProof, agentProof, nonce);
console.log('Verified:', result.verified);        // true
console.log('Human nullifier:', result.humanNullifier);
console.log('Scope commitment:', result.scopeCommitment);
```

## 4. Verify On-Chain (Base Sepolia)

```typescript
import { ethers } from 'ethers';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const registry = new ethers.Contract(
  '0x2781dF8b6381462d881C833Fb703d68c661c9577', // Base Sepolia
  registryABI,
  signer,
);

// Submit both proofs in a single transaction
const tx = await registry.verifyHandshake(
  formatGroth16Proof(humanProof),
  humanProof.publicSignals,
  formatPlonkProof(agentProof),
  agentProof.publicSignals,
  nonce,
);
console.log('TX:', tx.hash);
```

## What Just Happened?

1. The human proved they're a member of the identity group — without revealing who they are
2. The agent proved its credential is valid, not expired, and satisfies the required permissions — without revealing the credential
3. Both proofs were bound to the same session nonce — preventing replay
4. The on-chain verifier checked both proofs atomically — one transaction, ~590k gas (~$0.15 on Base)
5. The agent's scope commitment was stored on-chain — ready for delegation chains

## Next Steps

- [Full API Reference](./README.md)
- [IETF Protocol Specification](../spec/draft-bolyra-mutual-zkp-auth-00.md)
- [LangChain Integration](../integrations/langchain/README.md)
- [Base Sepolia Deployment](../contracts/deployments/base-sepolia.json)

## Contract Addresses (Base Sepolia)

| Contract | Address |
|----------|---------|
| IdentityRegistry | `0x2781dF8b6381462d881C833Fb703d68c661c9577` |
| Groth16Verifier | `0x5467FCbebeEff1824F4589Dd64ab01Cf9ccd46bE` |
| PlonkVerifier | `0x28b99c48f19F1680a7D88733ffeb9AFbcB3B95Db` |
| DelegationVerifier | `0x285D2E315AdD9c82337d8a4BDF567AB3a9215B93` |
