# Bolyra DID Method Specification

## DID Method Name

`did:bolyra`

## DID Method Specific Identifier

```
did:bolyra:<network>:<identity-commitment>
```

Where:
- `<network>` is the chain identifier (e.g., `base-sepolia`, `base-mainnet`)
- `<identity-commitment>` is the hex-encoded Poseidon hash of the
  identity secret (for humans) or the credential hash (for agents)

## DID Document

A Bolyra DID document contains:
- The DID subject
- Verification methods referencing the on-chain Merkle tree
- Service endpoints for proof generation and verification

## DID Resolution

Resolvers query the IdentityRegistry contract to verify that the
identity commitment exists in the appropriate Merkle tree.

### Resolution Algorithm

1. Parse the DID to extract `<network>` and `<identity-commitment>`.
2. Connect to the IdentityRegistry on the specified network.
3. Verify the identity commitment is a leaf in the tree (via Merkle
   proof or direct lookup).
4. Construct the DID document with current tree metadata.

### Proof Freshness

Human-tree and agent-tree root proofs carry an implicit validity window
bounded by `ROOT_HISTORY_SIZE` (currently 30 for both trees). A proof
generated against a root that has been evicted from the ring buffer is
stale and MUST be rejected by resolvers.

Resolvers SHOULD surface root age metadata in the DID resolution
result so that relying parties can assess proof freshness. The
recommended metadata fields are:

- `rootHistoryIndex`: The current write index of the ring buffer.
- `proofRootAge`: The number of enrollments since the proof's attested
  root was the current root (i.e., `currentIndex - proofRootIndex`).
- `rootHistorySize`: The buffer capacity (30).

If `proofRootAge >= rootHistorySize`, the proof has aged out and the
resolver MUST return a `staleRoot` error in the resolution metadata.

The effective time-based validity depends on enrollment throughput:
`T_stale = ROOT_HISTORY_SIZE × avg_enrollment_interval`. Resolvers
MAY include an estimated `proofMaxAgeSec` field based on observed
enrollment rates.

## DID Deactivation

Bolyra DIDs are deactivated by consuming the nullifier associated with
the identity commitment. Once the nullifier is consumed, the DID
cannot generate new proofs (though existing valid proofs remain
verifiable until their root ages out of the history buffer).

## Security Considerations

See `draft-bolyra-mutual-zkp-auth-01.md` for the full security
analysis, including root staleness, nonce binding, and nullifier
uniqueness.
