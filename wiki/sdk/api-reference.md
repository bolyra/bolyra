---
title: "@bolyra/sdk API Reference"
visibility: public
sources:
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
  - sdk/src/utils.ts
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [api, reference, typescript, sdk]
---

Complete public API reference for `@bolyra/sdk` v0.5.2. Every exported function, type, constant, and error class.

## Overview

The SDK exports are organized into 9 modules: identity, handshake, delegation, off-chain batching, prover backend, proof envelope, dev mode, registry resolver, and errors. All exports are re-exported from `sdk/src/index.ts`.

## Key Concepts

- All cryptographic values use `bigint` (not `number`)
- Poseidon hashes are BN254 field elements
- Public signals are `string[]` (decimal-encoded field elements)
- Permissions use cumulative bit encoding (8-bit)

---

## Identity

### `createHumanIdentity(secret: bigint): Promise<HumanIdentity>`

Create a human identity from a secret. Derives a Baby Jubjub keypair via scalar multiplication and computes a `Poseidon2(Ax, Ay)` commitment.

Throws `InvalidSecretError` if secret is zero, negative, or >= BN254 field order.

### `createAgentCredential(modelHash: bigint, operatorPrivateKey: bigint | Buffer, permissions: Permission[], expiryTimestamp: bigint): Promise<AgentCredential>`

Create an operator-signed agent credential. Computes `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` commitment and EdDSA-signs it.

Throws `InvalidPermissionError` if cumulative bit rules are violated or expiry is in the past.

### `permissionsToBitmask(permissions: Permission[]): bigint`

Convert an array of `Permission` flags to a 64-bit bitmask.

### `validateCumulativeBitEncoding(bitmask: bigint): void`

Validate cumulative bit rules: bit 4 implies bits 3+2, bit 3 implies bit 2. Throws `InvalidPermissionError` on violation.

### `validateHumanSecret(secret: bigint): void`

Validate a secret for `createHumanIdentity`. Throws `InvalidSecretError` if zero, negative, or >= `BN254_FIELD_ORDER`.

### `validateAgentExpiry(expiryTimestamp: bigint): void`

Validate an expiry timestamp is in the future. Throws `InvalidPermissionError` if not.

### `BN254_FIELD_ORDER: bigint`

The BN254 scalar field order: `21888242871839275222246405745257275088548364400416034343698204186575808495617n`.

---

## Handshake

### `proveHandshake(human: HumanIdentity, agent: AgentCredential, options?): Promise<{ humanProof: Proof; agentProof: Proof; nonce: bigint }>`

Generate mutual handshake proofs. Both proofs run in parallel.

Options:
- `scope?: bigint` -- scope identifier (default: `1n`)
- `nonce?: bigint` -- session nonce override (default: timestamped random)
- `config?: BolyraConfig` -- circuit directory override
- `backend?: ProverBackend` -- prover backend selection

Throws `CircuitArtifactNotFoundError` if circuit artifacts are missing, `ProofGenerationError` on proof failure.

### `verifyHandshake(humanProof: Proof, agentProof: Proof, nonce: bigint, config?: BolyraConfig): Promise<HandshakeResult>`

Verify both proofs locally via snarkjs Groth16 verify. Checks nonce binding -- returns `verified: false` (not an exception) if nonces don't match.

Throws `VerificationError` on malformed proof structure, `CircuitArtifactNotFoundError` if vkey files missing.

---

## Delegation

### `delegate(input: DelegateInput): Promise<{ proof: Proof; result: DelegationResult }>`

Generate a Delegation proof (Groth16). Scope narrowing is one-way: the circuit rejects any delegatee scope that is not a subset of the delegator's.

Pre-flight checks: scope escalation (`ScopeEscalationError`), expiry escalation (`BolyraError` with code `EXPIRY_ESCALATION`), chain link mismatch (`BolyraError` with code `CHAIN_LINK_MISMATCH`).

### `verifyDelegation(proof: Proof, previousScopeCommitment: bigint, sessionNonce: bigint, currentTimestamp: bigint, config?: BolyraConfig): Promise<DelegationResult>`

Verify a delegation proof off-chain. Checks public signal binding (previous scope, nonce, timestamp) and runs Groth16 verification.

### `DelegateInput` (interface)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `delegator` | `AgentCredential` | Yes | The delegating agent's credential |
| `delegatorOperatorPrivateKey` | `bigint \| Buffer` | Yes | Operator's EdDSA private key |
| `delegateeCommitment` | `bigint` | Yes | Recipient's identity commitment |
| `delegateeScope` | `bigint` | Yes | Narrowed scope (must be subset) |
| `delegateeExpiry` | `bigint` | Yes | Narrowed expiry (must be <=) |
| `previousScopeCommitment` | `bigint` | Yes | Prior chain link scope commitment |
| `sessionNonce` | `bigint` | Yes | Must match originating handshake |
| `currentTimestamp` | `bigint` | No | Default: `floor(Date.now() / 1000)` |
| `delegateeMerkleProof` | `DelegateeMerkleProof` | No | Default: single-leaf pattern |
| `hopIndex` | `number` | No | Informational, echoed in result |
| `config` | `BolyraConfig` | No | Circuit directory override |
| `backend` | `ProverBackend` | No | Prover backend selection |

---

## Off-chain Batching

### `verifyHandshakeOffchain(humanProof: Proof, agentProof: Proof, nonce: bigint, config?: BolyraConfig): Promise<HandshakeResult>`

Same as `verifyHandshake` but never touches the chain. Suitable for batching.

### `OffchainVerificationBatch` (class)

Accumulates verified handshake sessions into a Poseidon Merkle tree.

- `size: number` -- number of sessions in the batch
- `add(result: HandshakeResult): Promise<OffchainVerificationResult>` -- add a verified result (throws if `verified === false`)
- `getMerkleRoot(): Promise<bigint>` -- compute/cache the Poseidon Merkle root
- `getProofOfInclusion(sessionIndex: number): Promise<{ siblings: bigint[]; pathIndices: number[] }>` -- Merkle inclusion proof
- `getCommitment(index: number): bigint` -- session commitment at index
- `getCommitments(): bigint[]` -- all session commitments

### `postBatchRoot(batch: OffchainVerificationBatch, signer: ethers.Signer, registryAddress: string): Promise<BatchCheckpoint>`

Post a batch Merkle root on-chain. Single transaction for N sessions (~100x gas reduction).

### `computeSessionCommitment(result: HandshakeResult): Promise<bigint>`

Compute `Poseidon2(humanNullifier, Poseidon2(agentNullifier, sessionNonce))`.

### `verifyMerkleInclusion(leaf: bigint, siblings: bigint[], pathIndices: number[], expectedRoot: bigint): Promise<boolean>`

Verify a Merkle inclusion proof against a known root.

---

## Prover Backend

### `proveGroth16(input: Record<string, unknown>, wasmPath: string, zkeyPath: string, backend?: ProverBackend): Promise<Proof>`

Generate a Groth16 proof using the fastest available backend. Caches WASM witness calculators for reuse.

### `activeProverBackend(backend?: ProverBackend): 'rapidsnark' | 'snarkjs'`

Returns which backend would actually be used (diagnostic).

### `ProverBackend` (type)

`'auto' | 'rapidsnark' | 'snarkjs'`

- `auto`: use rapidsnark if available, else snarkjs
- `rapidsnark`: require native binary, throw if missing
- `snarkjs`: always use pure JS (slower)

---

## Proof Envelope

Wire format: `application/vnd.bolyra.proof+json`

### `serializeEnvelope(envelope: ProofEnvelope): string`

Serialize to JSON string.

### `deserializeEnvelope(json: string): ProofEnvelope`

Parse and validate a JSON string into a `ProofEnvelope`. Throws on invalid structure or field elements.

### `validateEnvelope(envelope: Record<string, unknown>): ProofEnvelope`

Validate a raw object as a `ProofEnvelope`. Checks version compatibility (major version match), circuit name, proof type, field element bounds (< BN254 field order), and structural completeness.

### `envelopeFromSnarkjsProof(circuitName: CircuitName, proof, publicSignals: string[], options?): ProofEnvelope`

Wrap raw snarkjs output into an envelope.

### Constants

- `CONTENT_TYPE = 'application/vnd.bolyra.proof+json'`
- `ENVELOPE_VERSION = '1.0.0'`

### Envelope Types

- `ProofEnvelope` -- top-level envelope with version, circuit, proofType, publicSignals, proof, metadata
- `ProofData` -- Groth16 coordinates: `pi_a`, `pi_b`, `pi_c` (decimal strings)
- `ProofMetadata` -- informational (prover, timestamp); verifiers MUST NOT reject based on these
- `CircuitIdentity` -- `{ name, version, vkeyHash? }`
- `CircuitName` -- `'HumanUniqueness' | 'AgentPolicy' | 'Delegation'`
- `ProofType` -- `'groth16'` (v1 only)

---

## Dev Mode

### `createDevIdentities(options?: DevIdentityOptions): Promise<DevIdentities>`

Create fixed-seed identities for testing. No circuit artifacts required. All values are deterministic. Prints a warning on first call.

### `DevIdentityOptions` (interface)

- `permissionBitmask?: bigint` -- default: `0b11111111` (all permissions)
- `expiryTimestamp?: bigint` -- default: `4102358400n` (2099-12-31)

### `DevIdentities` (interface)

- `human: HumanIdentity`
- `agent: AgentCredential`
- `operatorKey: Buffer` -- fixed 32-byte operator private key

---

## Registry Resolver

### `createRegistryResolver(config: RegistryConfig): (commitment: string) => Promise<AgentCredential | null>`

Create a resolver function that fetches an `AgentCredential` from the Bolyra credential registry API by commitment string. Returns `null` if not found or revoked.

### `RegistryConfig` (interface)

- `baseUrl: string` -- registry API base URL
- `apiKey: string` -- bearer token

---

## Utility Functions

### `poseidon2(a: bigint, b: bigint): Promise<bigint>`

Poseidon hash with 2 inputs.

### `poseidon3(a: bigint, b: bigint, c: bigint): Promise<bigint>`

Poseidon hash with 3 inputs.

### `poseidon4(a: bigint, b: bigint, c: bigint, d: bigint): Promise<bigint>`

Poseidon hash with 4 inputs.

---

## Types

### `HumanIdentity`

```ts
interface HumanIdentity {
  secret: bigint;                          // EdDSA secret (KEEP PRIVATE)
  publicKey: { x: bigint; y: bigint };     // Baby Jubjub public key
  commitment: bigint;                      // Poseidon2(Ax, Ay)
}
```

### `AgentCredential`

```ts
interface AgentCredential {
  modelHash: bigint;
  operatorPublicKey: { x: bigint; y: bigint };
  permissionBitmask: bigint;
  expiryTimestamp: bigint;
  signature: { R8: { x: bigint; y: bigint }; S: bigint };
  commitment: bigint;                      // Poseidon5(modelHash, Ax, Ay, bitmask, expiry)
}
```

### `Permission` (enum)

| Value | Name | Notes |
|-------|------|-------|
| 0 | `READ_DATA` | |
| 1 | `WRITE_DATA` | |
| 2 | `FINANCIAL_SMALL` | < $100 |
| 3 | `FINANCIAL_MEDIUM` | < $10,000 (implies bit 2) |
| 4 | `FINANCIAL_UNLIMITED` | Unlimited (implies bits 2+3) |
| 5 | `SIGN_ON_BEHALF` | |
| 6 | `SUB_DELEGATE` | |
| 7 | `ACCESS_PII` | |

### `HandshakeResult`

```ts
interface HandshakeResult {
  humanNullifier: bigint;
  agentNullifier: bigint;
  sessionNonce: bigint;
  scopeCommitment: bigint;
  verified: boolean;
}
```

### `DelegationResult`

```ts
interface DelegationResult {
  newScopeCommitment: bigint;
  delegationNullifier: bigint;
  delegateeMerkleRoot: bigint;
  hopIndex: number;
}
```

### `DelegateeMerkleProof`

```ts
interface DelegateeMerkleProof {
  length: number;
  index: number;
  siblings: bigint[];  // always length 20
}
```

### `Proof`

```ts
interface Proof {
  proof: any;              // snarkjs proof object
  publicSignals: string[];
}
```

### `OffchainVerificationResult`

Extends `HandshakeResult` with `batchIndex: number` and optional `batchRoot?: bigint`.

### `BatchCheckpoint`

```ts
interface BatchCheckpoint {
  root: bigint;
  timestamp: number;
  sessionCount: number;
}
```

### `BolyraConfig`

```ts
interface BolyraConfig {
  rpcUrl?: string;
  registryAddress?: string;
  circuitDir?: string;
  zkeyDir?: string;
}
```

---

## Errors

All errors extend `BolyraError`, which extends `Error` with `code: string` and optional `details: Record<string, unknown>`.

| Class | Code | Thrown by |
|-------|------|----------|
| `BolyraError` | (varies) | Base class |
| `ProofGenerationError` | `PROOF_GENERATION_FAILED` | `proveHandshake`, `delegate` |
| `VerificationError` | `VERIFICATION_FAILED` | `verifyHandshake`, `verifyDelegation` |
| `InvalidPermissionError` | `INVALID_PERMISSION` | `createAgentCredential`, `validateCumulativeBitEncoding` |
| `ExpiredCredentialError` | `CREDENTIAL_EXPIRED` | Credential expiry checks |
| `ScopeEscalationError` | `SCOPE_ESCALATION` | `delegate` |
| `StaleProofError` | `STALE_MERKLE_ROOT` | Merkle root staleness |
| `InvalidSecretError` | `INVALID_SECRET` | `createHumanIdentity`, `validateHumanSecret` |
| `CircuitArtifactNotFoundError` | `CIRCUIT_ARTIFACT_NOT_FOUND` | `proveHandshake`, `verifyHandshake`, `delegate` |
| `MerkleTreeError` | `MERKLE_TREE_ERROR` | Merkle tree operations |
| `ConfigurationError` | `CONFIGURATION_ERROR` | Config validation |

## See Also

- [TypeScript SDK](./typescript-sdk.md) -- overview and architecture
- [Python SDK](./python-sdk.md) -- Python bindings
- [Quickstart](./quickstart.md) -- getting started guide
- `sdk/src/index.ts` -- canonical export list
