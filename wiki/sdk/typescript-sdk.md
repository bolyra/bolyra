---
title: "@bolyra/sdk TypeScript SDK"
visibility: public
sources:
  - sdk/README.md
  - sdk/package.json
  - sdk/src/index.ts
  - sdk/src/types.ts
  - sdk/src/identity.ts
  - sdk/src/handshake.ts
  - sdk/src/delegation.ts
  - sdk/src/offchain.ts
  - sdk/src/prover.ts
  - sdk/src/envelope.ts
  - sdk/src/dev.ts
  - sdk/src/errors.ts
  - sdk/src/registry.ts
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [sdk, typescript, api, npm]
---

The `@bolyra/sdk` (v0.5.2) is the primary SDK for Bolyra. It provides mutual ZKP authentication between humans and AI agents -- identity creation, Groth16 proof generation/verification, delegation chains, off-chain batching, and a proof envelope wire format.

## Overview

- **Package:** `@bolyra/sdk` on npm
- **Language:** TypeScript, compiles to `dist/` via `tsc`
- **License:** Apache-2.0
- **Runtime:** Node.js 18+ (BigInt required)
- **Dependencies:** `circomlibjs` (direct); `snarkjs`, `ethers`, `@semaphore-protocol/core` (optional peer deps)

Install:

```bash
npm install @bolyra/sdk
```

## Key Concepts

**Identities and Credentials.** A `HumanIdentity` is a Baby Jubjub EdDSA keypair derived from a secret, with a Poseidon2 commitment. An `AgentCredential` is operator-signed, carrying a model hash, permission bitmask, and expiry.

**Handshake.** `proveHandshake()` generates a HumanUniqueness proof (Groth16) and an AgentPolicy proof in parallel, bound to a shared session nonce. `verifyHandshake()` checks both proofs locally via snarkjs.

**Delegation.** `delegate()` produces a Delegation proof that narrows scope one-way (permissions can only decrease, expiry can only shorten). Delegation chains are linked via scope commitments.

**Off-chain Batching.** `OffchainVerificationBatch` accumulates verified handshakes into a Poseidon Merkle tree. `postBatchRoot()` checkpoints the batch on-chain in a single transaction (~100x gas reduction).

**Proof Envelope.** `application/vnd.bolyra.proof+json` -- a self-describing wire format with circuit identity binding, version negotiation, and field element validation.

**Prover Backend.** The SDK auto-detects rapidsnark (native, ~5x faster) and falls back to snarkjs (pure JS). Controlled via the `ProverBackend` type: `'auto' | 'rapidsnark' | 'snarkjs'`.

**Permissions.** 8-bit cumulative encoding. Higher financial tiers imply lower ones (bit 4 implies bits 3 and 2). Enforced by `validateCumulativeBitEncoding()` and by the Delegation circuit on-chain.

## How It Works

1. Create identities with `createHumanIdentity(secret)` and `createAgentCredential(modelHash, operatorKey, permissions, expiry)`.
2. Generate mutual proofs with `proveHandshake(human, agent, { scope })`. Both proofs run in parallel.
3. Verify locally with `verifyHandshake(humanProof, agentProof, nonce)` or off-chain via `verifyHandshakeOffchain()`.
4. Optionally submit proofs on-chain to `IdentityRegistry.verifyHandshake()` or batch via `postBatchRoot()`.
5. For sub-delegation, use `delegate()` with a narrowed scope and shortened expiry.

For testing without circuit artifacts, `createDevIdentities()` returns fixed-seed identities.

## Current Status

| Module | Version | Notes |
|--------|---------|-------|
| Identity (`createHumanIdentity`, `createAgentCredential`) | v0.1 | Stable |
| Handshake (`proveHandshake`, `verifyHandshake`) | v0.2 | Stable |
| Delegation (`delegate`, `verifyDelegation`) | v0.3 | Stable |
| Off-chain batching | v0.3 | Stable |
| Prover backend (rapidsnark) | v0.4 | Stable |
| Dev mode (`createDevIdentities`) | v0.4 | Stable |
| Proof envelope | v0.5 | Stable |
| Registry resolver | v0.5 | Alpha |

## See Also

- [Python SDK](./python-sdk.md) -- thin shell over this SDK
- [Quickstart](./quickstart.md) -- 5-minute guide
- [API Reference](./api-reference.md) -- complete public API
- `sdk/README.md` -- canonical README
- `docs/quickstart.md` -- full quickstart with circuit artifact notes
