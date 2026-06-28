# @bolyra/sdk Quickstart

## Installation

```bash
npm install @bolyra/sdk
```

## Basic Usage

```ts
import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from '@bolyra/sdk';

// 1. Create a human identity
const human = await createHumanIdentity(secretScalar);

// 2. Create an agent credential
const agent = await createAgentCredential(modelHash, operatorPrivKey, permissions, expiry);

// 3. Prove mutual handshake
const { humanProof, agentProof } = await proveHandshake(human, agent);

// 4. Verify
const valid = await verifyHandshake(humanProof, agentProof, nonce);
console.log('Handshake valid:', valid);
```

## Migration: Named Signal Envelopes (v0.3.0+)

Prior to v0.3.0, proof outputs were bare positional arrays:

```ts
// ❌ Old way — positional, error-prone:
const root = publicSignals[0]; // Is this the root? Or the nullifier?
const nullifier = publicSignals[2]; // Wrong! It's actually at [0].
```

Starting with v0.3.0, use `fromRaw()` to wrap proofs in a self-describing
`BolyraEnvelope` with named signal fields:

```ts
import { fromRaw, decode } from '@bolyra/sdk';

// ✅ New way — named fields, self-documenting:
const envelope = fromRaw('HumanUniqueness', 'groth16', proof, publicSignals);

// Access by name instead of index:
const root = envelope.signals.humanMerkleRoot;      // ✓ clear
const nullifier = envelope.signals.nullifierHash;    // ✓ unambiguous
const nonce = envelope.signals.nonceBinding;         // ✓ no off-by-one

// When you need positional arrays for snarkjs.verify():
const { proof: rawProof, publicSignals: rawSignals } = decode(envelope);
await snarkjs.groth16.verify(vkey, rawSignals, rawProof);
```

### Supported Circuits

| Circuit | Signal Fields |
|---|---|
| `HumanUniqueness` | `nullifierHash`, `nonceBinding`, `humanMerkleRoot`, `externalNullifier`, `sessionNonce` |
| `AgentPolicy` | `credentialHash`, `nonceBinding`, `agentMerkleRoot`, `currentTimestamp`, `requiredPermissions`, `sessionNonce` |
| `Delegation` | `delegationHash`, `narrowedPermissions`, `nonceBinding`, `delegationMerkleRoot`, `currentTimestamp`, `sessionNonce` |

### One-liner Migration

```ts
// Wrap any existing proof in one line:
const envelope = fromRaw('AgentPolicy', 'groth16', existingProof, existingSignals);
// Then use envelope.signals.credentialHash, envelope.signals.sessionNonce, etc.
```

## API Reference

| Function | Description |
|---|---|
| `createHumanIdentity(secret)` | Create human identity from secret scalar |
| `createAgentCredential(modelHash, privKey, perms, expiry)` | Create agent credential |
| `proveHandshake(human, agent)` | Generate mutual ZKP handshake |
| `verifyHandshake(humanProof, agentProof, nonce)` | Verify handshake proofs |
| `encode(circuit, provingSystem, proof, signals)` | Wrap raw proof in envelope |
| `decode(envelope)` | Extract positional `{ proof, publicSignals }` |
| `fromRaw(circuit, provingSystem, proof, signals)` | Alias for `encode()` (migration helper) |
