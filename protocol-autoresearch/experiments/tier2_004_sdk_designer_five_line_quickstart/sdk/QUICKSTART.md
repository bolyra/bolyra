# @bolyra/sdk Quickstart

## 5-Line Verified Handshake

```bash
npm install @bolyra/sdk ethers
```

```typescript
import { BolyraClient } from '@bolyra/sdk';
import { ethers } from 'ethers';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const client = new BolyraClient({ provider });
const result = await client.handshake(humanSecret, agentCredential);
console.log(result.verified); // true
```

That's it. `BolyraClient` handles:
- Circuit artifact resolution (auto-discovers WASM/zkey from the installed package)
- Merkle proof fetching from the on-chain HumanRegistry
- Session nonce generation (cryptographically random, single-use)
- ZK proof generation and verification

### Using viem instead of ethers

```typescript
import { BolyraClient } from '@bolyra/sdk';
import { createPublicClient, http } from 'viem';
import { baseSepolia } from 'viem/chains';

const provider = createPublicClient({ chain: baseSepolia, transport: http() });
const client = new BolyraClient({ provider });
const result = await client.handshake(humanSecret, agentCredential);
```

### Options

```typescript
const client = new BolyraClient({
  provider,                          // ethers Provider or viem PublicClient (required)
  artifactsDir: './my-artifacts',    // override artifact path (optional)
  registryAddress: '0x...',          // override HumanRegistry address (optional)
});
```

### HandshakeResult

```typescript
interface HandshakeResult {
  verified: boolean;        // true if both human + agent proofs verified
  nullifierHash: string;    // unique per-session human identifier (no PII)
  sessionNonce: SessionNonce; // the random nonce bound to this handshake
  humanProof: unknown;      // raw Groth16 proof (for on-chain submission)
  agentProof: unknown;      // raw agent policy proof
}
```

---

## Advanced: Low-Level API

For callers who need custom path control, Merkle proof construction, or
non-standard proving flows, the low-level API remains available:

```typescript
import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
} from '@bolyra/sdk';

// 1. Create identities
const human = createHumanIdentity(secret);
const agent = createAgentCredential(modelHash, operatorPrivKey, permissions, expiry);

// 2. Build Merkle proof (your responsibility)
const merkleProof = { root, siblings, pathIndices };

// 3. Generate nonce
import { generateSessionNonce } from '@bolyra/sdk';
const nonce = generateSessionNonce();

// 4. Prove
const { humanProof, agentProof } = await proveHandshake(human, agent, {
  merkleProof,
  sessionNonce: nonce.toString('hex'),
  artifactPaths: {
    humanWasm: '/path/to/HumanUniqueness.wasm',
    humanZkey: '/path/to/HumanUniqueness_final.zkey',
    agentWasm: '/path/to/AgentPolicy.wasm',
    agentZkey: '/path/to/AgentPolicy_final.zkey',
  },
});

// 5. Verify
const verified = await verifyHandshake(humanProof, agentProof, {
  sessionNonce: nonce.toString('hex'),
  vkeyPaths: {
    humanVkey: '/path/to/HumanUniqueness_vkey.json',
    agentVkey: '/path/to/AgentPolicy_vkey.json',
  },
});
```

### Standalone Utilities

| Export | Purpose |
|---|---|
| `ArtifactResolver` | Resolve WASM/zkey paths with env-var and package fallbacks |
| `MerkleProofFetcher` | Query HumanRegistry for Merkle proofs (ethers or viem) |
| `generateSessionNonce()` | 32-byte crypto-random branded nonce |
| `ArtifactNotFoundError` | Actionable error with install hints |

### Environment Variables

| Variable | Purpose |
|---|---|
| `BOLYRA_ARTIFACTS_DIR` | Override circuit artifact directory |
| `FULL_PROOF` | Set to `1` to run slow proof-generation tests |
