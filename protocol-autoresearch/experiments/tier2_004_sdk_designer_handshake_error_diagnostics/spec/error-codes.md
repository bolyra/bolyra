# Bolyra Error Codes — Normative Specification

**Status:** Draft  
**Version:** 0.1.0  
**Date:** 2026-06-20  

## 1. Overview

Every Bolyra SDK implementation MUST surface failures as typed errors
carrying a machine-readable `code` from the enum below and a human-readable
`hint` string that guides the developer toward recovery.

SDK implementors SHOULD use the canonical hint templates (§3) but MAY
adjust wording for language idiom. The `{placeholder}` names and the
data they represent MUST match across implementations.

## 2. Error Code Enum

| Code | Numeric | Trigger Condition |
|---|---|---|
| `STALE_ROOT` | 1 | Merkle root in the proof is behind the on-chain history buffer head |
| `EXPIRED_CREDENTIAL` | 2 | Agent credential `expiryTimestamp` < current block/wall-clock time |
| `SCOPE_MISMATCH` | 3 | Delegated permission bitmask does not satisfy the required scope |
| `NONCE_REUSED` | 4 | Session nonce was already consumed on-chain |
| `NULLIFIER_SPENT` | 5 | Nullifier hash already recorded in the IdentityRegistry |
| `PROOF_INVALID` | 6 | ZK proof fails Groth16/PLONK verification (on-chain or off-chain) |
| `REGISTRY_REVERT` | 7 | On-chain tx reverted with a known IdentityRegistry custom error |
| `UNKNOWN` | 0 | Catch-all for errors that don't map to a known code |

## 3. Canonical Hint Templates

All `{placeholder}` values MUST be interpolated at throw-time with the
actual runtime values.

### STALE_ROOT

```
Root is {delta} blocks behind head; re-fetch with registry.latestRoot() and re-prove.
```

**Parameters:**
- `delta` (integer) — difference between the latest on-chain root index and
  the root used in the proof.

**Recovery:** Call `registry.latestHumanRoot()` / `registry.latestAgentRoot()`,
rebuild the Merkle inclusion proof against the fresh root, and re-generate
the ZK proof.

### EXPIRED_CREDENTIAL

```
Agent credential expired {ago} ago (expiry timestamp {expiry}). Rotate the credential with createAgentCredential().
```

**Parameters:**
- `ago` (duration string) — human-readable time since expiry.
- `expiry` (unix timestamp) — the credential's expiry value.

**Recovery:** Call `createAgentCredential()` with a future expiry, re-enroll
the agent in the Merkle tree, and retry the handshake.

### SCOPE_MISMATCH

```
Required scope 0b{required} is not a subset of provided scope 0b{provided}. Narrow via delegate() before retrying.
```

**Parameters:**
- `required` (8-char binary string) — the bitmask the verifier/relying party expects.
- `provided` (8-char binary string) — the bitmask in the proof.

**Recovery:** Use `delegate()` to narrow the parent credential's scope to
include the required bits, then re-prove.

### NONCE_REUSED

```
Session nonce {nonce} was already consumed. Generate a fresh nonce for each handshake.
```

**Parameters:**
- `nonce` (hex string) — the consumed nonce value.

**Recovery:** Generate a cryptographically random nonce and use it in a
new `proveHandshake()` call.

### NULLIFIER_SPENT

```
Nullifier {nullifier} has already been spent. This identity has already completed a handshake in this epoch.
```

**Parameters:**
- `nullifier` (hex string) — the spent nullifier hash.

**Recovery:** For human identities, wait for the next epoch (nullifier
rotation). For agent identities, generate a fresh credential to get a
new nullifier.

### PROOF_INVALID

```
Proof verification failed: {reason}. Check that circuit artifacts match the deployed verifier.
```

**Parameters:**
- `reason` (string) — the underlying verification engine's error message.

**Recovery:** Verify that `.wasm`, `.zkey`, and `.vkey.json` match the
deployed verifier contract. Re-compile circuits if the contract was
redeployed after a trusted setup change.

### REGISTRY_REVERT

```
IdentityRegistry reverted with {errorName}({errorArgs}). See spec/error-codes.md for recovery steps.
```

**Parameters:**
- `errorName` (string) — Solidity custom error name.
- `errorArgs` (string) — comma-separated argument values.

**Recovery:** Inspect the specific Solidity error name and cross-reference
with §4 below.

### UNKNOWN

```
Unexpected error: {message}. File a bug at github.com/bolyra/bolyra/issues.
```

**Parameters:**
- `message` (string) — the original error message.

## 4. IdentityRegistry Custom Errors

The Solidity contract defines the following custom errors. The SDK's
`mapRevertToBolyraError()` MUST map each to the corresponding `ErrorCode`.

| Solidity Error | Parameters | Maps To |
|---|---|---|
| `StaleRoot` | `uint256 providedBlock, uint256 latestBlock` | `STALE_ROOT` |
| `NullifierSpent` | `bytes32 nullifier` | `NULLIFIER_SPENT` |
| `ScopeMismatch` | `uint8 required, uint8 provided` | `SCOPE_MISMATCH` |
| `InvalidProof` | (none) | `PROOF_INVALID` |
| `NonceAlreadyUsed` | `bytes32 nonce` | `NONCE_REUSED` |
| `CredentialExpired` | `uint256 expiry` | `EXPIRED_CREDENTIAL` |
| `Unauthorized` | (none) | `REGISTRY_REVERT` |
| `RootNotFound` | `bytes32 root` | `STALE_ROOT` |

## 5. Cause Chaining

Every `BolyraError` SHOULD preserve the original upstream error in a
`cause` field (or language equivalent). This allows developers to
inspect the full chain:

```
BolyraError(STALE_ROOT) → ethers CALL_EXCEPTION → StaleRoot(100, 105)
```

## 6. Conformance

An SDK is conformant if:

1. Every thrown error carries a valid `ErrorCode`.
2. The `hint` field is non-empty and contains interpolated context.
3. `mapRevertToBolyraError()` correctly maps all 8 Solidity custom errors.
4. The `cause` chain is preserved for at least one level.
5. `BolyraError.wrap()` is idempotent — wrapping a `BolyraError` returns
   the same instance.
