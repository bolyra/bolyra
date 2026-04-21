# @bolyra/openclaw

OpenClaw trust verification adapter for [Bolyra](https://bolyra.ai) — ZKP-native agent authentication.

Maps Bolyra's mutual ZKP handshake (Groth16 + PLONK) to OpenClaw's `TrustVerificationResult` interface, providing cryptographic agent identity verification at every OpenClaw verification point.

## Install

```bash
npm install @bolyra/openclaw @bolyra/sdk
```

## Quick Start

```typescript
import { createBolyraPlugin } from '@bolyra/openclaw';
import { createHumanIdentity } from '@bolyra/sdk';

// 1. Create your human identity (done once)
const human = await createHumanIdentity(mySecret);

// 2. Create the plugin with a credential resolver
const plugin = createBolyraPlugin(
  human,
  async (agentId) => credentialStore.get(agentId),
  { network: 'base-sepolia' }
);

// 3. Register with OpenClaw
openclaw.use(plugin);
```

## How It Works

When OpenClaw calls `onAgentVerify(agentId)`:

1. Resolves the agent's Bolyra credential from your credential store
2. Runs a mutual ZKP handshake (parallel Groth16 + PLONK proof generation)
3. Scores the result on 5 dimensions (proof validity, expiry, permissions, freshness, scope)
4. Returns a `TrustVerificationResult` with score (0-100), grade (A-F), and DID

## Scoring

| Dimension | Points | What it checks |
|-----------|--------|---------------|
| Proof validity | 40 | Both ZKP proofs verify |
| Credential expiry | 20 | Agent credential hasn't expired |
| Permission coverage | 20 | Agent has read/write permissions |
| Nonce freshness | 10 | Session nonce within maxProofAge |
| Scope commitment | 10 | Delegation chain initialized |

## Configuration

```typescript
createBolyraPlugin(human, resolver, {
  network: 'base-sepolia',     // DID network identifier
  minScore: 70,                // Minimum score for verified=true
  maxProofAge: 300,            // Cache TTL in seconds
  sdkConfig: {                 // Passthrough to @bolyra/sdk
    rpcUrl: 'https://sepolia.base.org',
    registryAddress: '0x2781...',
  },
});
```

## Standalone Verification

```typescript
import { verifyAgent, computeTrustScore } from '@bolyra/openclaw';

const result = await verifyAgent(human, agentCredential, { network: 'base' });
// { verified: true, score: 100, grade: 'A', did: 'did:bolyra:base:...', warnings: undefined }
```

## License

MIT
