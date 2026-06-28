# Bolyra Mutual ZKP Authentication — Draft 01 (Addendum: Cross-Chain Replay Prevention)

## Status

This section is an addendum to the existing `draft-bolyra-mutual-zkp-auth-01.md` spec.
It documents the `effectiveNonce` derivation and cross-chain replay prevention mechanism
added in the `chain_id_nonce_binding` experiment.

## 1. Motivation

The original handshake protocol binds proofs to a `sessionNonce` to prevent replay
within a single deployment. However, if Bolyra is deployed on multiple EVM chains
(e.g., Base and Arbitrum) that share the same identity Merkle root, a valid handshake
proof generated on chain A can be submitted on chain B — a **cross-chain replay attack**.

## 2. Effective Nonce Derivation

Both `HumanUniqueness` and `AgentPolicy` circuits now compute an `effectiveNonce`
that binds the session nonce to the chain:

```
effectiveNonce = Poseidon2(sessionNonce, chainId)
```

The `nonceBinding` output is then derived from the `effectiveNonce` rather than
the raw `sessionNonce`:

- **HumanUniqueness:** `nonceBinding = Poseidon2(identitySecret, effectiveNonce)`
- **AgentPolicy:** `nonceBinding = Poseidon2(credentialHash, effectiveNonce)`

### Why Poseidon2(sessionNonce, chainId)?

1. **Algebraic soundness:** Poseidon is the native hash in the BN254 scalar field.
   Using it for nonce derivation adds ~250 constraints — negligible overhead.
2. **Collision resistance:** Different `(sessionNonce, chainId)` pairs produce
   different `effectiveNonce` values with overwhelming probability.
3. **Composability:** The derivation is deterministic and can be verified by
   any party with knowledge of `sessionNonce` and `chainId`.

## 3. Updated Public Signal Tables

### HumanUniqueness (6 public signals, up from 5)

| Index | Signal             | Type   | Description                          |
|-------|--------------------|--------|--------------------------------------|
| 0     | `nullifierHash`    | output | Domain-separated nullifier           |
| 1     | `nonceBinding`     | output | Chain-bound nonce commitment         |
| 2     | `humanMerkleRoot`  | input  | Semaphore v4 identity tree root      |
| 3     | `externalNullifier`| input  | Application scope                    |
| 4     | `sessionNonce`     | input  | Fresh per-handshake nonce            |
| 5     | `chainId`          | input  | EIP-155 chain identifier             |

### AgentPolicy (7 public signals, up from 6)

| Index | Signal               | Type   | Description                        |
|-------|----------------------|--------|------------------------------------|
| 0     | `credentialHash`     | output | Agent credential commitment        |
| 1     | `nonceBinding`       | output | Chain-bound nonce commitment       |
| 2     | `agentMerkleRoot`    | input  | Agent registry tree root           |
| 3     | `currentTimestamp`   | input  | Expiry check reference time        |
| 4     | `requiredPermissions`| input  | Required permission bitmask        |
| 5     | `sessionNonce`       | input  | Fresh per-handshake nonce          |
| 6     | `chainId`            | input  | EIP-155 chain identifier           |

## 4. On-Chain Verification

`BolyraVerifier.verifyHandshake()` extracts `chainId` from both proofs' public
signal arrays and asserts:

```solidity
require(humanChainId == block.chainid, "ChainIdMismatch");
require(agentChainId == block.chainid, "ChainIdMismatch");
```

This check runs **before** the Groth16 pairing verification to fail fast on
cross-chain submissions.

## 5. Security Considerations — Cross-Chain Replay

### 5.1 Attack Vector

Without chain binding, an attacker who observes a valid `(humanProof, agentProof)`
pair on chain A can submit the same pair to a `BolyraVerifier` deployed on chain B
if both chains share the same Merkle root. The proofs would verify because:

- The circuit constraints are chain-agnostic.
- The `sessionNonce` does not encode which chain the proof was intended for.
- The Groth16 verification key is identical across deployments.

### 5.2 Mitigation

By computing `effectiveNonce = Poseidon2(sessionNonce, chainId)` inside the circuit,
the `nonceBinding` output becomes chain-specific. A proof generated for `chainId=8453`
(Base) produces a different `nonceBinding` than the same inputs with `chainId=42161`
(Arbitrum). The on-chain verifier's `block.chainid` check ensures that only proofs
generated for the current chain are accepted.

### 5.3 Multi-Chain Deployment Implications

- Provers must specify `chainId` when generating handshake proofs.
- A separate proof must be generated for each target chain.
- The SDK's `proveHandshake()` function now requires `chainId` as a mandatory parameter.
- Off-chain verifiers must also check that the `chainId` in public signals matches
  the expected deployment chain.

## 6. Constraint Cost

The addition costs approximately **250–300 constraints** per circuit (one Poseidon2
gate for `effectiveNonce` computation). This is well within the `pot16.ptau` SRS
capacity (2^16 = 65,536 constraints).
