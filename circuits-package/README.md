# @bolyra/circuits

Prebuilt Circom circuit artifacts for the [Bolyra](https://bolyra.ai) ZKP identity protocol.

Ships `.wasm` witness calculators, `.zkey` proving keys (Groth16), and `.vkey.json` verification keys for all three production circuits:

- **HumanUniqueness** -- Semaphore v4-style enrollment proof
- **AgentPolicy** -- EdDSA-signed agent credential proof
- **Delegation** -- One-way scope-narrowing delegation proof

## Install

```bash
npm install @bolyra/circuits
```

## Usage

```typescript
import {
  getCircuitArtifacts,
  getArtifactsDir,
  getVerificationKey,
  listAvailableCircuits,
} from '@bolyra/circuits';

// Get artifact paths for a circuit
const { wasm, zkey, vkey } = getCircuitArtifacts('HumanUniqueness');

// Use with snarkjs
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,
  wasm,
  zkey,
);

// Get the verification key as parsed JSON
const vkeyJson = getVerificationKey('HumanUniqueness');
const valid = await snarkjs.groth16.verify(vkeyJson, publicSignals, proof);

// List all available circuit/system combinations
const available = listAvailableCircuits();
// [{ circuit: 'HumanUniqueness', system: 'groth16' }, ...]

// Get the artifacts directory (useful for @bolyra/sdk integration)
const dir = getArtifactsDir();
```

## Available Circuits

| Circuit | Groth16 | Notes |
|---------|---------|-------|
| HumanUniqueness | Yes | Reuses Semaphore v4 ceremony (depth 20) |
| AgentPolicy | Yes | Project-specific Phase 2 ceremony |
| Delegation | Yes | Project-specific Phase 2 ceremony |

## Trusted Setup Provenance

- **HumanUniqueness (Groth16):** Reuses the Semaphore v4 Phase 2 ceremony at depth 20. No project-specific trusted setup required.
- **AgentPolicy (Groth16):** Project-specific Phase 2 ceremony using `pot16.ptau` (Hermez Cryptographic Ceremony, 2^16 powers).
- **Delegation (Groth16):** Same as AgentPolicy.

## Package Size

~29 MB (Groth16 artifacts only). PLONK proving keys (~146 MB each) are excluded. PLONK verification keys are included for verification-only use cases.

## Integration with @bolyra/sdk

When `@bolyra/circuits` is installed alongside `@bolyra/sdk`, the SDK automatically resolves circuit artifacts from this package. No configuration needed.

## License

Apache-2.0
