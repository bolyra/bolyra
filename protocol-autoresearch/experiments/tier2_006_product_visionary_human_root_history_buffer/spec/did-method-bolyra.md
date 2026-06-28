# Bolyra DID Method Specification

`did:bolyra` — A DID method for zero-knowledge-proof-based identity.

## Method-Specific Identifier

```
did:bolyra:<network>:<commitment-hash>
```

Where:
- `network` is `base-sepolia` (testnet) or `base` (mainnet)
- `commitment-hash` is the hex-encoded Poseidon hash of the identity commitment

## CRUD Operations

### Create

A DID is created by enrolling an identity commitment into the on-chain
`IdentityRegistry`. For humans, this calls `enrollHuman(commitment, newRoot)`;
for agents, `enrollAgent(commitment, newRoot)`.

### Read (Resolve)

Resolution returns a DID Document containing:
- The verification method (ZKP-based, referencing the circuit type)
- The service endpoint for proof exchange
- The current Merkle root binding

### Update

Not supported. Identity commitments are immutable once enrolled.

### Deactivate

Deactivation is achieved by consuming the nullifier, which prevents
further proof generation for the same identity in the same scope.

## Proof Validity Window — Root History Buffer

Both the human tree and agent tree maintain a **30-root history buffer**
implemented as a ring buffer in the `IdentityRegistry` contract.

### Semantics

When a new identity is enrolled, the resulting Merkle root is pushed into
the corresponding ring buffer (`humanRootHistory[30]` or
`agentRootHistory[30]`). The write pointer (`humanRootHistoryIndex` /
`agentRootHistoryIndex`) increments monotonically; the slot written is
`index % 30`.

A proof is considered valid if its claimed Merkle root matches **any** of
the 30 buffered roots. This means:

- A proof generated against root `R` remains valid as long as `R` has not
  been evicted from the ring buffer.
- Eviction occurs when 30 subsequent enrollments overwrite the slot where
  `R` was stored.
- The validity window is therefore **enrollment-count-based, not
  wall-clock-based**. During high-enrollment periods, the window shrinks
  in wall-clock terms; during quiet periods, proofs remain valid
  indefinitely.

### Eviction Policy

| Enrollment count since proof root | Status |
|---|---|
| 0–29 | Valid — root still in buffer |
| 30 | Valid — root at boundary, not yet overwritten |
| 31+ | Invalid — root has been evicted |

### Implications for Verifiers

- **Short-lived sessions**: Proofs bind to a `sessionNonce`, so even if
  the root is still in the buffer, replaying a proof without the matching
  nonce will fail.
- **Long-lived sessions**: Applications that maintain sessions longer than
  the enrollment window SHOULD re-prove periodically. The recommended
  strategy is to subscribe to `HumanRootHistoryUpdated` /
  `AgentRootHistoryUpdated` events and trigger re-proof when the
  session's root is within 5 slots of eviction.
- **Off-chain verifiers**: When operating without on-chain access, the
  verifier MUST maintain its own root history set, populated by indexing
  enrollment events. The SDK's `verifyHandshake()` accepts an optional
  `historicalHumanRoots` / `historicalAgentRoots` array for this purpose.

### Rationale

The 30-root buffer mirrors the design used by Semaphore v4 and World ID.
It provides a practical tradeoff between:
- **Proof freshness**: stale roots are eventually evicted
- **Concurrency tolerance**: multiple users can enroll and prove
  concurrently without invalidating each other's in-flight proofs
- **Gas efficiency**: fixed 30-slot array avoids dynamic storage costs

## Security Considerations

See `docs/owasp-agentic-mapping.md` for the full OWASP agentic threat
model mapping.
