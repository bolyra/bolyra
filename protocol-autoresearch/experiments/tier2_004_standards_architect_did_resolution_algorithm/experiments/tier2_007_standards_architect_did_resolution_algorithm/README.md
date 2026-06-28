# Experiment: Complete DID Resolution Algorithm with Verification Methods

**ID:** `standards_architect_did_resolution_algorithm`  
**Dimension:** Standards  
**Priority:** High  
**Effort:** Days  

## Problem

The existing `spec/did-method-bolyra.md` defines the DID syntax but lacks a complete resolution algorithm per W3C DID Core section 7.1. Without this, no DID resolver library can implement `did:bolyra` support.

## Solution

This experiment delivers:

1. **Extended DID Method Spec** (`spec/did-method-bolyra.md`) — full W3C DID Core 7.1-compliant resolution algorithm, verification method definitions, service endpoints, and error codes.

2. **Standalone Resolution Algorithm** (`spec/did-resolution-algorithm.md`) — implementation-ready pseudo-code for `resolve(did, options)` covering both agent (EdDSA Baby Jubjub) and human (nullifier-based) DID subjects.

3. **Smart Contract Updates** (`contracts/src/IdentityRegistry.sol`) — `getRegistration(bytes32)` view function and indexed events (`RegistrationRecorded`, `RegistrationRevoked`) for off-chain resolver queries.

4. **SDK Resolver** (`sdk/src/resolver.ts`) — `resolve()` function and `getBolyraResolver()` driver compatible with the did-resolver npm package.

5. **DID Document Builder** (`sdk/src/didDocument.ts`) — typed constructors for `JsonWebKey2020` (agent) and `BolyraZkpAuthentication2024` (human) verification methods.

6. **Tests** (`sdk/test/resolver.test.ts`) — unit and integration tests against Hardhat in-process node.

7. **Conformance Test Vectors** (`spec/conformance/did-resolution-vectors.json`) — 4 cases: valid agent, valid human, malformed, deactivated.

8. **Integration Guide** (`docs/did-resolver-integration.md`) — driver registration, RPC configuration, Veramo integration, caching.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `spec/did-method-bolyra.md` | spec | Extended DID method specification |
| `spec/did-resolution-algorithm.md` | spec | Standalone resolution algorithm |
| `contracts/src/IdentityRegistry.sol` | contract | Registry with getRegistration() view |
| `sdk/src/resolver.ts` | sdk | DID resolver implementation |
| `sdk/src/didDocument.ts` | sdk | DID Document builder |
| `sdk/test/resolver.test.ts` | test | Unit + integration tests |
| `spec/conformance/did-resolution-vectors.json` | spec | Conformance test vectors |
| `docs/did-resolver-integration.md` | docs | Integration guide |

## Usage

### Run Tests

```bash
# From repo root
npx hardhat test sdk/test/resolver.test.ts
```

### Resolve a DID

```typescript
import { resolve } from "@bolyra/sdk/resolver";

const result = await resolve("did:bolyra:<commitment>", {
  provider: "https://sepolia.base.org",
  registryAddress: "0x<deployed>",
});
```

### did-resolver Integration

```typescript
import { Resolver } from "did-resolver";
import { getBolyraResolver } from "@bolyra/sdk/resolver";

const resolver = new Resolver(
  getBolyraResolver({
    provider: "https://sepolia.base.org",
    registryAddress: "0x<deployed>",
  })
);

const { didDocument } = await resolver.resolve("did:bolyra:<commitment>");
```

## Verification Method Types

### Agent: `JsonWebKey2020`

Baby Jubjub EdDSA public key encoded as JWK with `crv: "Baby-Jubjub"`.
Appears in both `authentication` and `assertionMethod`.

### Human: `BolyraZkpAuthentication2024`

Nullifier commitment reference (no key material exposed).
Appears ONLY in `authentication` — humans authenticate via ZKP, not signatures.

## DID Syntax

```
did:bolyra:<64-char-lowercase-hex-commitment>
```

- No `0x` prefix
- Lowercase only
- Exactly 64 hex characters (32 bytes)

## Dependencies

- `ethers` v6 — for contract interaction
- `did-resolver` (optional) — for standard resolver integration
- Hardhat — for contract deployment in tests
