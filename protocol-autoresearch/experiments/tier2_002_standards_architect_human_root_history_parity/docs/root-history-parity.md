# Root History Parity: humanTree and agentTree

## Overview

The Bolyra IdentityRegistry maintains a `ROOT_HISTORY_SIZE` (30) ring
buffer for both the humanTree and agentTree Merkle roots. This document
explains the liveness guarantee, the rationale for the window size, and
how operators should configure proof submission timeouts.

## The Problem

Every new enrollment (human or agent) changes the Merkle tree root.
Without a history buffer, any in-flight proof — one generated before
the enrollment but submitted after — would fail verification because
the proof's attested root no longer matches the current root.

In high-throughput deployments, this creates a liveness failure:
legitimate proofs are rejected simply because another user enrolled
between proof generation and submission.

## The Solution: Ring Buffer

Both trees maintain a fixed-size circular buffer of 30 recent roots:

```solidity
bytes32[30] public humanRootHistory;
uint256 public humanRootHistoryIndex;

bytes32[30] public agentRootHistory;
uint256 public agentRootHistoryIndex;
```

On each enrollment, the new root is written to
`history[index % 30]` and the index is incremented. The
`isKnownHumanRoot()` and `isKnownAgentRoot()` view functions iterate
all 30 slots and return `true` if any slot matches the queried root.

### Why 30?

- **Gas cost**: Iterating 30 storage slots costs ~60k gas — acceptable
  for an on-chain verification step.
- **Storage**: 30 * 32 bytes = 960 bytes per tree — negligible.
- **Liveness**: At 1 enrollment/minute, proofs remain valid for ~30
  minutes. At 1/hour, ~30 hours. This covers realistic proof
  generation and submission latencies.
- **Semaphore parity**: Semaphore v4 uses a similar buffer depth.

### Why Symmetric?

Both trees use ROOT_HISTORY_SIZE=30. Asymmetric buffer sizes would
create confusing UX in mutual handshakes: a human proof might expire
before the agent proof (or vice versa), causing one side of the
handshake to fail while the other succeeds.

## Operator Guidance

### Proof Submission Timeout

Operators should set their proof submission timeout to:

```
timeout < ROOT_HISTORY_SIZE * avg_enrollment_interval
```

For example:
- If enrollments average 1 per minute: timeout < 30 minutes
- If enrollments average 1 per 10 minutes: timeout < 5 hours
- If enrollments average 1 per hour: timeout < 30 hours

### Monitoring

Operators SHOULD monitor:
- **Enrollment rate**: Track `HumanRootHistoryUpdated` and
  `AgentRootHistoryUpdated` events to compute the rolling average
  enrollment interval.
- **Stale proof rejections**: Track on-chain reverts with
  `isKnownHumanRoot` returning false to detect when the window is
  too narrow.
- **Buffer utilization**: Compare `humanRootHistoryIndex` against
  expected values to detect enrollment spikes.

### Adjusting ROOT_HISTORY_SIZE

If the effective staleness window drops below acceptable bounds,
operators can deploy a new IdentityRegistry with a larger
`ROOT_HISTORY_SIZE`. This is a contract upgrade — the buffer size
is a compile-time constant.

## SDK Support

The `@bolyra/sdk` exports a `RegistryClient` class with pre-flight
check methods:

```typescript
import { RegistryClient } from "@bolyra/sdk";

const client = new RegistryClient({
  provider: "https://sepolia.base.org",
  registryAddress: "0x...",
});

// Quick boolean check
const isValid = await client.isKnownHumanRoot(proofRoot);

// Full status with metadata
const status = await client.checkHumanRoot(proofRoot);
if (!status.isKnown) {
  console.warn(`Root stale — ${status.historyIndex} enrollments since proof`);
}
```

## References

- Contract: `contracts/src/IdentityRegistry.sol`
- Interface: `contracts/src/IIdentityRegistry.sol`
- IETF Draft: `spec/draft-bolyra-mutual-zkp-auth-01.md`
- DID Method: `spec/did-method-bolyra.md`
