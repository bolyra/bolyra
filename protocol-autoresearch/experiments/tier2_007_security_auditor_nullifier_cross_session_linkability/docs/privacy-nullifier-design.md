# Two-Layer Nullifier Design: Privacy vs Sybil Resistance

## Problem Statement

In Bolyra v2.0.0, the HumanUniqueness circuit produces a nullifier:

```
nullifierHash = Poseidon₃(DOMAIN_HUMAN, scope, secret)
```

This value is **constant across all sessions** for the same human. Any
verifier (or colluding set of verifiers) that records nullifier values
can trivially link all handshakes by the same identity.

### Threat Scenario

```
Verifier A records: nullifier = 0xabc123...
Verifier B records: nullifier = 0xabc123...

→ A and B conclude: "same human used both services"
```

This violates the privacy goals of a ZKP-based protocol. The human
proves enrollment without revealing their identity, but the static
nullifier acts as a persistent pseudonym.

## Solution: Two-Nullifier Architecture (v3.0.0)

### Before (v2.0.0)

```
┌─────────────────────────────────────┐
│        HumanUniqueness v2.0.0       │
│                                     │
│  Private: secret, identityNonce,    │
│           merklePath                │
│                                     │
│  Public:                            │
│    identityTreeRoot ────────────────┼──→ Merkle root
│    nullifierHash ───────────────────┼──→ Poseidon₃(1, scope, secret)
│    scope ───────────────────────────┼──→ Application scope
│                                     │
│  ⚠ nullifierHash is CONSTANT       │
│    across sessions → LINKABLE       │
└─────────────────────────────────────┘
```

### After (v3.0.0)

```
┌──────────────────────────────────────────────┐
│           HumanUniqueness v3.0.0             │
│                                              │
│  Private: secret, identityNonce,             │
│           sessionNonce, merklePath           │
│                                              │
│  Public:                                     │
│    identityTreeRoot ─────────────────────────┼──→ Merkle root
│    nullifierHash ────────────────────────────┼──→ Poseidon₄(1, scope, secret, sessionNonce)
│    scope ────────────────────────────────────┼──→ Application scope
│    externalNullifierCommitment ──────────────┼──→ Poseidon₁(Poseidon₃(1, scope, secret))
│                                              │
│  ✓ nullifierHash is UNIQUE per session       │
│  ✓ externalNullifierCommitment is STABLE     │
│    but one-way (commitment, not raw value)   │
└──────────────────────────────────────────────┘
```

## Signal Comparison

| Signal | v2.0.0 | v3.0.0 | Purpose |
|--------|--------|--------|---------|
| `nullifierHash` | Constant per identity | Unique per session | Replay prevention |
| `externalNullifierCommitment` | N/A | Constant per identity | Sybil/revocation |
| `sessionNonce` | N/A | Private input | Nullifier randomization |

## Why This Works

### Unlinkability

Different `sessionNonce` values produce completely different
`nullifierHash` outputs due to the avalanche property of Poseidon.
Two verifiers comparing nullifier values from different sessions
see unrelated field elements.

### Sybil Resistance

`externalNullifierCommitment` is deterministic for a given
(scope, secret) pair. The on-chain registry can enforce that
each commitment appears at most once per scope (if uniqueness is
required) or track it for revocation purposes.

### One-Way Commitment

The commitment is `Poseidon₁(externalNullifier)`, not the raw
`externalNullifier` itself. This adds a layer of protection:
even if the commitment is logged, the raw nullifier (which is
the same across all sessions) cannot be recovered.

## Constraint Cost

The two-nullifier architecture adds ~600 constraints over v2.0.0:

| Component | v2.0.0 | v3.0.0 | Delta |
|-----------|--------|--------|-------|
| Identity commitment (Poseidon₂) | ~250 | ~250 | 0 |
| Session nullifier (Poseidon₃→₄) | ~350 | ~450 | +100 |
| External nullifier (Poseidon₃) | — | ~350 | +350 |
| Ext. null. commitment (Poseidon₁) | — | ~150 | +150 |
| Merkle tree (depth 20) | ~40,000 | ~40,000 | 0 |
| Domain tag | 1 | 1 | 0 |
| **Total** | **~40,601** | **~41,201** | **+600** |

The 1.5% constraint increase has negligible impact on proving time.

## Verifier Obligations

1. **MUST NOT** log `externalNullifierCommitment` alongside
   session-identifying metadata (timestamps, IPs, user agents).
2. **MUST** generate `sessionNonce` using a CSPRNG with at least
   248 bits of entropy.
3. **SHOULD** discard `externalNullifierCommitment` after confirming
   non-revocation status with the on-chain registry.

## Migration Notes

- v3.0.0 changes the public signal layout (3 → 4 public outputs).
- Existing `.zkey` files are **invalid** after this change.
- A new project-specific Groth16 trusted setup is required.
- The Semaphore v4 ceremony can no longer be reused (different
  constraint shape).
- SDK `HumanProof` type gains `externalNullifierCommitment` and
  `sessionNonce` fields.
- `nullifierHash` semantics change: it is now per-session, not
  per-identity.
