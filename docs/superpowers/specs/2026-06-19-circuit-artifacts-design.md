# @bolyra/circuits -- Prebuilt Circuit Artifacts Package

**Date:** 2026-06-19
**Author:** Viswa + Claude Opus 4.6
**Status:** Draft (pending Gate 1 approval)
**Pipeline:** pdlc-2026-06-19-circuit-artifacts

## Problem

Bolyra's SDK (`@bolyra/sdk`) and integrations require compiled Circom circuit artifacts (`.wasm`, `.zkey`, `.vkey.json`) for ZKP proving and verification. Today these artifacts live in `circuits/build/` and are resolved via relative filesystem paths (`../../circuits/build`). This creates three problems:

1. **No standalone install.** Users who `npm install @bolyra/sdk` get no circuit artifacts. They must clone the monorepo, install Circom 2, compile circuits, and run trusted setup. This is a multi-hour onboarding barrier.

2. **Fragile path resolution.** The SDK hardcodes `path.join(__dirname, '../../circuits/build')` which only works when the SDK is consumed from within the monorepo source tree. Published `@bolyra/sdk` on npm cannot resolve these paths.

3. **Duplicated vkeys.** `@bolyra/payment-protocols` ships its own copy of `vkeys/` (currently only `AgentPolicy_groth16_vkey.json` and `HumanUniqueness_vkey.json`). These can drift from the canonical artifacts in `circuits/build/`.

## Solution

Publish a new npm package `@bolyra/circuits` containing prebuilt artifacts for all three production circuits (HumanUniqueness, AgentPolicy, Delegation). The package provides a programmatic API to resolve artifact paths at runtime.

## Package Structure

```
@bolyra/circuits/
  package.json
  src/
    index.ts           # Path resolution API + types
  dist/
    index.js           # Compiled JS
    index.d.ts         # Type declarations
  artifacts/
    HumanUniqueness/
      HumanUniqueness.wasm
      HumanUniqueness_groth16.zkey
      HumanUniqueness_groth16_vkey.json
    AgentPolicy/
      AgentPolicy.wasm
      AgentPolicy_groth16.zkey
      AgentPolicy_groth16_vkey.json
      AgentPolicy_plonk.zkey
      AgentPolicy_plonk_vkey.json
    Delegation/
      Delegation.wasm
      Delegation_groth16.zkey
      Delegation_groth16_vkey.json
      Delegation_plonk.zkey
      Delegation_plonk_vkey.json
```

### Naming Convention

Current `circuits/build/` uses inconsistent names (`HumanUniqueness_final.zkey` vs `AgentPolicy_plonk.zkey`). The published package normalizes to `{Circuit}_{system}.zkey` consistently:

| Current name | Published name |
|---|---|
| `HumanUniqueness_final.zkey` | `HumanUniqueness_groth16.zkey` |
| `AgentPolicy_final.zkey` | `AgentPolicy_groth16.zkey` |
| `AgentPolicy_plonk.zkey` | `AgentPolicy_plonk.zkey` (unchanged) |
| `AgentPolicy_groth16_vkey.json` | `AgentPolicy_groth16_vkey.json` (unchanged) |
| `AgentPolicy_vkey.json` | `AgentPolicy_plonk_vkey.json` |
| `Delegation_final.zkey` | `Delegation_groth16.zkey` |
| `Delegation_plonk.zkey` | `Delegation_plonk.zkey` (unchanged) |
| `Delegation_groth16_vkey.json` | `Delegation_groth16_vkey.json` (unchanged) |
| `Delegation_vkey.json` | `Delegation_plonk_vkey.json` |
| `HumanUniqueness_vkey.json` | `HumanUniqueness_groth16_vkey.json` |

### Excluded Files

- `.ptau` (72MB -- too large, only needed for setup, not runtime)
- `.r1cs` (only needed for circuit compilation, not runtime)
- `.sym` (debug symbols, not needed at runtime)
- `rapidsnark_prover` (native binary, platform-specific, separate concern)
- `ModelInstanceBinding_*` (not a production circuit in the current spec)

## API Design

```typescript
// @bolyra/circuits/src/index.ts

export type CircuitName = 'HumanUniqueness' | 'AgentPolicy' | 'Delegation';
export type ProvingSystem = 'groth16' | 'plonk';

export interface CircuitArtifacts {
  /** Absolute path to the .wasm witness calculator */
  wasmPath: string;
  /** Absolute path to the .zkey proving key */
  zkeyPath: string;
  /** Absolute path to the .vkey.json verification key */
  vkeyPath: string;
}

/**
 * Returns absolute file paths to the prebuilt circuit artifacts.
 *
 * @param circuit - Which circuit
 * @param system - Which proving system (default: 'groth16')
 * @throws if the requested circuit+system combination does not exist
 *         (e.g., HumanUniqueness+plonk)
 */
export function getCircuitArtifacts(
  circuit: CircuitName,
  system?: ProvingSystem,
): CircuitArtifacts;

/**
 * Returns the absolute path to the artifacts directory.
 * Useful for passing as circuitDir to @bolyra/sdk.
 */
export function getArtifactsDir(): string;

/**
 * Returns the parsed verification key JSON for a circuit.
 * Synchronous -- reads from disk and caches.
 */
export function getVerificationKey(
  circuit: CircuitName,
  system?: ProvingSystem,
): object;

/**
 * Lists all available circuit+system combinations.
 */
export function listAvailableCircuits(): Array<{
  circuit: CircuitName;
  system: ProvingSystem;
}>;
```

### Validation Rules

- `HumanUniqueness` only supports `groth16` (Semaphore v4 ceremony). Requesting `plonk` throws.
- `AgentPolicy` and `Delegation` support both `groth16` and `plonk`.
- Default proving system is `groth16` (matches current SDK behavior).

## SDK Integration

### Current State

The SDK resolves circuits via `config.circuitDir` (defaults to `../../circuits/build` relative to `__dirname`):

```typescript
// sdk/src/handshake.ts
const DEFAULT_CIRCUIT_DIR = path.join(__dirname, '../../circuits/build');
```

### Target State

The SDK adds `@bolyra/circuits` as an **optional peer dependency**. Resolution order:

1. Explicit `config.circuitDir` -- always wins (user override)
2. `BOLYRA_CIRCUITS_DIR` env var -- explicit environment override
3. `require.resolve('@bolyra/circuits')` -- use published package if installed
4. Monorepo fallback `../../circuits/build` -- works in dev

```typescript
// sdk/src/circuit-resolver.ts (new file)
function resolveCircuitDir(): string {
  // 1. Explicit config (handled at call site)
  // 2. Environment variable
  if (process.env.BOLYRA_CIRCUITS_DIR) {
    return process.env.BOLYRA_CIRCUITS_DIR;
  }
  // 3. Published @bolyra/circuits package
  try {
    const circuits = require('@bolyra/circuits');
    return circuits.getArtifactsDir();
  } catch {
    // Not installed
  }
  // 4. Monorepo fallback
  return path.join(__dirname, '../../circuits/build');
}
```

This is **fully backward-compatible**: existing monorepo users see no change. New users who `npm install @bolyra/sdk @bolyra/circuits` get artifacts automatically.

### Payment-Protocols Integration

`@bolyra/payment-protocols` currently ships its own `vkeys/` directory with 2 verification keys. After this change:

- Add `@bolyra/circuits` as an optional peer dependency
- Fall back to bundled `vkeys/` if `@bolyra/circuits` is not installed
- Long-term: remove bundled `vkeys/` once `@bolyra/circuits` adoption is established (not in this pipeline)

## Package Metadata

```json
{
  "name": "@bolyra/circuits",
  "version": "0.1.0",
  "description": "Prebuilt Circom circuit artifacts for the Bolyra ZKP identity protocol",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": [
    "dist/",
    "artifacts/",
    "LICENSE",
    "NOTICE"
  ],
  "repository": {
    "type": "git",
    "url": "https://github.com/bolyra/bolyra",
    "directory": "circuits-package"
  },
  "publishConfig": {
    "access": "public"
  },
  "license": "Apache-2.0",
  "keywords": ["zkp", "circom", "snarkjs", "groth16", "plonk", "bolyra", "identity"]
}
```

### npm Size Budget

| File | Size |
|---|---|
| HumanUniqueness_groth16.zkey | 8.1 MB |
| AgentPolicy_groth16.zkey | 9.8 MB |
| AgentPolicy_plonk.zkey | 146 MB |
| Delegation_groth16.zkey | 10 MB |
| Delegation_plonk.zkey | 146 MB |
| 3x .wasm | ~1 MB total |
| 5x .vkey.json | ~50 KB total |
| **Total** | **~321 MB** |

This is large but within npm's 500MB unpacked limit. The PLONK `.zkey` files dominate at ~292 MB combined.

### Size Mitigation Options

1. **Split into two packages:** `@bolyra/circuits` (Groth16 only, ~29 MB) and `@bolyra/circuits-plonk` (PLONK zkeys, ~292 MB). SDK defaults to Groth16.
2. **Ship Groth16-only initially:** PLONK support is secondary. Ship `@bolyra/circuits` with Groth16 artifacts only (~29 MB). Add PLONK later or as a separate package.
3. **Ship everything:** 321 MB. Users install once, works for all proving systems.

**Recommendation:** Option 2 -- ship Groth16 only in v0.1.0. The PLONK zkeys are 10x larger and PLONK is not the default proving system. The package still includes PLONK vkeys for verification (they're tiny). A `@bolyra/circuits-plonk` package can follow if there's demand.

This means the `artifacts/` layout becomes:

```
artifacts/
  HumanUniqueness/
    HumanUniqueness.wasm
    HumanUniqueness_groth16.zkey
    HumanUniqueness_groth16_vkey.json
  AgentPolicy/
    AgentPolicy.wasm
    AgentPolicy_groth16.zkey
    AgentPolicy_groth16_vkey.json
    AgentPolicy_plonk_vkey.json      # vkey only, no zkey
  Delegation/
    Delegation.wasm
    Delegation_groth16.zkey
    Delegation_groth16_vkey.json
    Delegation_plonk_vkey.json        # vkey only, no zkey
```

Total: ~29 MB. The API's `getCircuitArtifacts('AgentPolicy', 'plonk')` would throw an error explaining that PLONK proving keys are not included and directing users to install `@bolyra/circuits-plonk` (or download manually).

## Package Location in Monorepo

New directory: `circuits-package/` at repo root (sibling to `sdk/`, `circuits/`, etc.)

Rationale: `circuits/` already exists and contains the Circom source code, compiler scripts, and tests. The publishable package is a different concern -- curated, renamed artifacts with a TS API. Keeping them separate avoids polluting the circuit development workspace.

A build script (`circuits-package/scripts/prepare-artifacts.sh`) copies and renames files from `circuits/build/` into `circuits-package/artifacts/`. This runs as part of the package's `prepublishOnly` hook.

## Trusted Setup Provenance

The package README documents the provenance of each proving key:

- **HumanUniqueness (Groth16):** Reuses the Semaphore v4 Phase 2 ceremony (depth 20). Ceremony hash and attestation link provided. No project-specific trusted setup.
- **AgentPolicy (Groth16):** Project-specific Phase 2 ceremony using `pot16.ptau` (Hermez Cryptographic Ceremony, 2^16 powers). Deterministic from the circuit R1CS and ptau.
- **Delegation (Groth16):** Same as AgentPolicy.

This is critical for users who need to verify they're not using a backdoored proving key.

## Testing Strategy

1. **Unit tests for the API** (`circuits-package/test/`):
   - `getCircuitArtifacts` returns valid paths that exist on disk
   - `getCircuitArtifacts('HumanUniqueness', 'plonk')` throws
   - `getVerificationKey` returns parseable JSON
   - `listAvailableCircuits` returns expected combinations

2. **Integration test** (in `sdk/test/`):
   - SDK's `proveHandshake` works when `@bolyra/circuits` is installed and no explicit `circuitDir` is provided
   - Existing tests continue to pass with the monorepo fallback

3. **Artifact integrity test**:
   - SHA-256 checksums of all artifacts match a manifest file (`artifacts/CHECKSUMS.sha256`)
   - This ensures the prepare script doesn't corrupt files during copy/rename

## Non-Goals

- **PLONK proving keys in v0.1.0.** Too large. Ship vkeys for verification only.
- **Automated ceremony.** Trusted setup is manual and infrequent. Not automated.
- **CDN/URL download of artifacts.** npm is the distribution channel. No lazy download.
- **Platform-specific native provers.** `rapidsnark` is a separate concern.
- **ModelInstanceBinding circuit.** Not a production circuit per current spec.

## Risks

1. **Package size.** 29 MB is large for npm but within limits. Mitigation: Groth16-only.
2. **Artifact staleness.** If circuits change, the package must be re-published. Mitigation: `prepublishOnly` script always copies fresh from `circuits/build/`. CI can gate on checksum match.
3. **Breaking the SDK path resolution.** Changing `DEFAULT_CIRCUIT_DIR` logic could break existing monorepo workflows. Mitigation: fallback chain preserves existing behavior as last resort.

## Open Questions

None -- scope is well-defined by the user's request.
