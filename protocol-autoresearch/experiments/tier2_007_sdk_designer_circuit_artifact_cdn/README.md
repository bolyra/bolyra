# @bolyra/artifacts

Automatic circuit artifact fetching with SHA-256 integrity verification and local caching for the Bolyra identity protocol.

## Problem

The Bolyra SDK requires pre-built circuit artifacts (`.wasm`, `.zkey`, `.vkey.json`) to generate ZK proofs. Previously, developers had to install the Circom toolchain and manually compile circuits before using the SDK — the single biggest source of onboarding friction.

## Solution

`@bolyra/artifacts` lazily fetches versioned circuit artifacts from GitHub Releases, verifies SHA-256 integrity, and caches them locally in `~/.bolyra/artifacts/<version>/`. The SDK's `proveHandshake()` calls the resolver automatically — zero configuration required.

## Architecture

```
@bolyra/artifacts
├── src/
│   ├── index.ts      # ArtifactResolver, resolveArtifacts()
│   ├── registry.ts   # Version-pinned entries: circuit → URL + SHA-256
│   ├── fetcher.ts    # HTTP fetch + streaming SHA-256 + retry
│   ├── cache.ts      # ~/.bolyra/artifacts/ disk cache
│   └── errors.ts     # ArtifactIntegrityError, ArtifactFetchError, ArtifactNotFoundError
├── test/
│   ├── fetcher.test.ts      # Mock fetch, digest match/mismatch, retry
│   ├── cache.test.ts        # Cold miss, warm hit, tamper detection
│   ├── registry.test.ts     # Schema validation
│   └── integration.test.ts  # Full resolve against local HTTP fixture server
├── INTEGRITY.md     # Security model documentation
└── package.json
```

## Usage

```typescript
import { resolveArtifacts, ArtifactResolver } from '@bolyra/artifacts';

// Resolve all three circuits
const artifacts = await resolveArtifacts();
console.log(artifacts.HumanUniqueness.wasmPath);

// Or resolve a single circuit
const resolver = new ArtifactResolver();
const hu = await resolver.resolveCircuit('HumanUniqueness');
```

## Environment Variables

| Variable | Description |
|---|---|
| `BOLYRA_ARTIFACTS_DIR` | Skip CDN — use local artifacts from this directory |

## Security

See [INTEGRITY.md](./INTEGRITY.md) for the full integrity model, including digest format, verification flow, and artifact rotation procedures.

## License

Apache-2.0
