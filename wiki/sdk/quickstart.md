---
title: "Bolyra SDK Quickstart"
visibility: public
sources:
  - docs/quickstart.md
  - sdk/README.md
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [quickstart, getting-started, tutorial]
---

Get a working mutual ZKP handshake between a human and an AI agent in 5 minutes.

## Overview

This guide walks through installing the SDK, creating identities, generating mutual proofs, and verifying them. By the end you will have a working handshake that proves a human is unique (in a given scope) and an agent credential is authentic and unexpired.

## Prerequisites

- **Node.js 18+** (BigInt support required)
- **Circuit artifacts** -- compiled `.wasm` and `.zkey` files for HumanUniqueness and AgentPolicy circuits. Either build from `circuits/` or download prebuilt artifacts from the [releases page](https://github.com/bolyra/bolyra/releases).

## Key Concepts

- **Human identity:** EdDSA keypair derived from a secret, with a Poseidon commitment
- **Agent credential:** Operator-signed, time-bound, with scoped permissions
- **Handshake:** Two ZK proofs (human + agent) bound to a shared nonce
- **Nullifiers:** Deterministic per-scope (human) and per-session (agent) -- enables double-spend prevention

## How It Works

### 1. Install

```bash
npm install @bolyra/sdk
```

### 2. Create Identities

```ts
import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
} from "@bolyra/sdk";

// Human identity (EdDSA keypair + Poseidon commitment)
const secret = 123456789n; // Production: use crypto.getRandomValues()
const human = await createHumanIdentity(secret);

// Agent credential (operator-signed, time-bound)
const agent = await createAgentCredential(
  1001n,                                              // model hash
  42n,                                                // operator EdDSA key
  [Permission.READ_DATA, Permission.WRITE_DATA],      // scoped permissions
  BigInt(Math.floor(Date.now() / 1000) + 86400),      // expires in 24h
);
```

### 3. Generate Mutual Proofs

```ts
import { proveHandshake } from "@bolyra/sdk";

const { humanProof, agentProof, nonce } = await proveHandshake(human, agent, {
  scope: 1n,
});
```

Both proofs are generated in parallel. The human proof is Groth16 (HumanUniqueness circuit); the agent proof is also Groth16 (AgentPolicy circuit).

### 4. Verify

```ts
import { verifyHandshake } from "@bolyra/sdk";

const result = await verifyHandshake(humanProof, agentProof, nonce);
console.log("Verified:", result.verified);        // true
console.log("Human nullifier:", result.humanNullifier);
console.log("Agent nullifier:", result.agentNullifier);
```

### 5. What Each Step Does

| Step | Function | What happens |
|------|----------|-------------|
| 1 | `createHumanIdentity(secret)` | Derives a Baby Jubjub keypair, computes Poseidon2 commitment (Merkle leaf) |
| 2 | `createAgentCredential(...)` | Computes Poseidon5 commitment, EdDSA-signs with operator key |
| 3 | `proveHandshake(human, agent)` | Generates Groth16 proofs for both circuits in parallel |
| 4 | `verifyHandshake(...)` | Verifies both proofs against verification keys, returns nullifiers |

### Circuit Artifacts

`proveHandshake` expects compiled artifacts at `circuits/build/` by default. Override with:

```ts
const result = await proveHandshake(human, agent, {
  scope: 1n,
  config: { circuitDir: "/path/to/your/artifacts" },
});
```

Required files in the circuit directory:
- `HumanUniqueness_js/HumanUniqueness.wasm`
- `HumanUniqueness_final.zkey`
- `HumanUniqueness_vkey.json`
- `AgentPolicy_js/AgentPolicy.wasm`
- `AgentPolicy_final.zkey`
- `AgentPolicy_vkey.json`

### Dev Mode (No Circuit Artifacts)

For testing without compiled circuits:

```ts
import { createDevIdentities } from "@bolyra/sdk";

const { human, agent, operatorKey } = await createDevIdentities();
// Fixed-seed, deterministic identities -- never use in production
```

## Current Status

The quickstart covers the core handshake flow (v0.2). Additional capabilities:
- **Delegation** (v0.3): `delegate()` for scope-narrowing sub-delegation
- **Off-chain batching** (v0.3): `OffchainVerificationBatch` for gas-efficient verification
- **On-chain submission**: Proofs can be submitted to `IdentityRegistry.verifyHandshake()` on Base Sepolia

## See Also

- [TypeScript SDK](./typescript-sdk.md) -- full SDK overview
- [Python SDK](./python-sdk.md) -- Python bindings
- [API Reference](./api-reference.md) -- every exported function and type
- `docs/quickstart.md` -- canonical quickstart source
- [Circuit specifications](https://github.com/bolyra/bolyra/tree/main/circuits)
