# Bolyra SDK Quickstart

## Install

```bash
npm install @bolyra/sdk
```

That's it. No Circom toolchain, no manual artifact downloads.

## Generate a Handshake Proof (Zero Config)

```typescript
import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from '@bolyra/sdk';

// 1. Create identities
const human = createHumanIdentity(mySecret);
const agent = createAgentCredential(modelHash, operatorPrivKey, permissions, expiry);

// 2. Prove — artifacts are fetched automatically on first run
const { humanProof, agentProof, sessionNonce } = await proveHandshake(human, agent);

// 3. Verify
const valid = await verifyHandshake(humanProof, agentProof, sessionNonce);
console.log('Handshake valid:', valid);
```

The first call to `proveHandshake()` downloads circuit artifacts (~15 MB total)
to `~/.bolyra/artifacts/` and caches them. Subsequent calls use the cache with
SHA-256 integrity verification — no network needed.

## Advanced: Local Artifacts

If you compile circuits yourself or run in CI, point the SDK at your build directory:

```bash
export BOLYRA_ARTIFACTS_DIR=./circuits/build
```

The SDK checks this directory first, skipping CDN fetch entirely.

## Advanced: Custom Cache Directory

```typescript
import { ArtifactResolver } from '@bolyra/artifacts';

const resolver = new ArtifactResolver({ cacheDir: '/tmp/my-cache' });
const artifacts = await resolver.resolveAll();
```

## What Gets Downloaded

| Circuit | Files | Purpose |
|---|---|---|
| HumanUniqueness | `.wasm`, `_groth16.zkey`, `_groth16.vkey.json` | Semaphore v4-style enrollment proof |
| AgentPolicy | `.wasm`, `_groth16.zkey`, `_groth16.vkey.json` | EdDSA-signed agent credential proof |
| Delegation | `.wasm`, `_groth16.zkey`, `_groth16.vkey.json` | Scope-narrowing delegation proof |

All artifacts are verified against SHA-256 digests pinned in `@bolyra/artifacts`.
See [INTEGRITY.md](../packages/artifacts/INTEGRITY.md) for the full security model.
