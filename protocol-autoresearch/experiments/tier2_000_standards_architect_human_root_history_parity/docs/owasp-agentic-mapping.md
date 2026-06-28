# OWASP Agentic Security Mapping for Bolyra

This document maps Bolyra's security mechanisms to the OWASP Agentic
Security threat categories.

## Identity Spoofing

**Threat**: An attacker impersonates a legitimate human or agent.

**Mitigation**: HumanUniqueness circuit proves membership in the
Semaphore-style Merkle tree without revealing the identity commitment.
AgentPolicy circuit proves possession of a valid EdDSA-signed
credential with the correct permissions bitmap.

## Credential Replay

**Threat**: An attacker replays a previously valid proof to establish
a new session.

**Mitigation**: Every handshake binds both proofs to a fresh session
nonce (`nonceBinding`). Replaying `(humanProof, agentProof)` from a
previous session fails because the nonce will not match.

## Permission Escalation

**Threat**: A delegated agent expands its permissions beyond what the
delegator authorized.

**Mitigation**: The Delegation circuit enforces one-way scope narrowing
at the constraint level. The cumulative-bit encoding (8-bit) ensures
higher permission tiers imply lower ones, and the circuit proves that
`delegatedPermissions & parentPermissions == delegatedPermissions`.

## Replay / Staleness Attacks

**Threat**: A proof generated against a valid-but-outdated Merkle root
is accepted indefinitely, allowing replay after the prover's enrollment
status has changed.

**Mitigation**: Both the human and agent Merkle trees maintain a
`ROOT_HISTORY_SIZE` (30) ring buffer of recent roots in the
IdentityRegistry contract. A proof whose attested root has been evicted
from the buffer is stale and MUST be rejected.

The effective staleness window is:
```
T_stale = ROOT_HISTORY_SIZE × avg_enrollment_interval
```

Verifiers MUST call `isKnownHumanRoot(root)` or `isKnownAgentRoot(root)`
before accepting any proof. The SDK's `verifyHandshake()` function
enforces this check and returns `HUMAN_ROOT_STALE` or `AGENT_ROOT_STALE`
error codes when the root has aged out.

This closes the unlimited-validity gap that would otherwise exist if
only the current root were checked. See the IETF draft
(`draft-bolyra-mutual-zkp-auth-01.md`, Security Considerations §Root
Staleness) for the normative specification of this mechanism.

**Note on human/agent parity**: Both trees now use identical 30-root
ring buffers with the same `_push*Root()` / `isKnown*Root()` pattern.
The prior asymmetry — where human proofs had no history buffer and were
invalidated by any single new enrollment, while agent proofs survived
up to 30 enrollments — has been eliminated. This parity ensures that
both sides of a mutual handshake have the same staleness tolerance,
preventing race conditions where a valid agent proof is paired with an
already-stale human proof due to a concurrent enrollment.

## Race Condition: Concurrent Enrollment During Handshake

**Threat**: A new enrollment lands on-chain between the time a prover
generates their proof and the time the verifier checks it, causing
the proof's Merkle root to become stale.

**Mitigation**: The 30-root ring buffer on both human and agent trees
ensures that the prover's root remains valid for up to 30 subsequent
enrollments. The identical buffer depth for both trees guarantees that
neither side of a mutual handshake expires before the other.

Clients receiving a stale-root error SHOULD automatically retry by
fetching the current root, regenerating the Merkle proof, and
re-proving. The SDK handles this transparently.

## Nullifier Double-Spend

**Threat**: A human prover signals twice with the same identity.

**Mitigation**: The HumanUniqueness circuit derives a deterministic
nullifier from the prover's secret and the external nullifier. The
IdentityRegistry tracks consumed nullifiers and rejects duplicates.

## Agent Credential Expiry Bypass

**Threat**: An agent uses an expired credential to authenticate.

**Mitigation**: Agent credentials include an `expiry` field. On-chain
verification checks `expiry >= block.timestamp`; off-chain verifiers
check against the current epoch. Expired credentials are rejected even
if the Merkle root is still valid.

## Supply Chain / Dependency Attacks

**Threat**: Compromised dependencies introduce vulnerabilities.

**Mitigation**: Transitive vulnerabilities are pinned via per-manifest
`overrides` blocks. The `dependency-audit` CI job gates runtime
advisories. See `SECURITY.md` for the full triage log.
