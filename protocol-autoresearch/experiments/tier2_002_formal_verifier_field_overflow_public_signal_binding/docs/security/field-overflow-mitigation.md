# BN254 Field Overflow Mitigation

## Summary

All Bolyra contracts that accept public signals for ZKP verifier calls now enforce
`pubSignal < FIELD_MODULUS` before forwarding values to snarkjs-generated Groth16
or PLONK verifiers.

## Background

Bolyra's circuits operate over the **BN254 scalar field** with order:

```
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

This is approximately 2^254. However, Solidity's `uint256` supports values up to
2^256 − 1. Values in the range `[r, 2^256 − 1]` are valid `uint256` values but
are **reduced modulo r** inside the circuit's finite field arithmetic.

## Attack Vector

Consider `sessionNonce` — a public input used for replay protection:

1. A user submits a valid handshake with `sessionNonce = n`.
2. The contract marks `usedNonces[n] = true`.
3. An attacker submits `sessionNonce = n + r`.
4. **Without the field check:** the contract sees a "new" nonce (`n + r ≠ n` in
   `uint256` arithmetic), so `usedNonces[n + r]` is `false` — the nonce check
   passes. But the circuit reduces `n + r` to `n mod r = n`, so it produces the
   **same proof verification result** as the original. The attacker has replayed
   the proof.

The same class of attack applies to any public signal with contract-side semantic
meaning: `currentTimestamp`, `nullifierHash`, `humanMerkleRoot`, etc.

## Fix

### `FieldBoundLib.sol`

A minimal library exporting:

- `FIELD_MODULUS` — the BN254 scalar field order constant.
- `assertInField(uint256 v)` — reverts with `FieldModulusExceeded(v)` if
  `v >= FIELD_MODULUS`.

### `IdentityRegistry.sol`

Every external function that accepts public signals calls `assertInField()` on
**every** public signal parameter **before** any other logic — including
`usedNonces` lookups, root validity checks, and verifier calls.

Protected functions:
- `verifyHandshake()` — 5 human signals + 6 agent signals = 11 checks
- `verifyDelegation()` — 6 delegation signals = 6 checks

### Why before the verifier call?

The snarkjs-generated verifiers (`HumanUniquenessVerifier`, `AgentPolicyVerifier`,
`DelegationVerifier`) do check that **proof elements** (π_A, π_B, π_C) are valid
curve points, but they do **not** check that public signal inputs are canonical
field elements. The check must happen in the calling contract, before the
verifier is invoked, and critically before any contract-side logic (like nonce
deduplication) that depends on the signal's uint256 value matching the circuit's
field-element value.

## Formal Verification

A Certora CVL spec (`contracts/certora/specs/FieldBound.spec`) proves two rules:

1. **`publicSignalsInField`** — any call to `verifyHandshake()` or
   `verifyDelegation()` with a public signal ≥ `FIELD_MODULUS` must revert.
2. **`nonceNonBypassable`** — no pair `(n, n + r)` can both succeed as session
   nonces in `usedNonces`.

Run with: `certoraRun contracts/certora/confs/FieldBound.conf`

## References

- [EIP-197](https://eips.ethereum.org/EIPS/eip-197) — BN254 pairing precompile
- [snarkjs verifier template](https://github.com/iden3/snarkjs) — proof element
  checks but no public signal bounds
- `circuits/FORMAL-PROPERTIES.md` — circuit-level range-check properties
- `SECURITY.md` § Field Arithmetic Invariants
