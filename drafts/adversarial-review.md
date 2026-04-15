# Adversarial Patent Review — IDENTITYOS-PROV-001
Reviewed: 2026-04-15
Sources: Codex + Claude subagent (independent parallel reviews)
Status: 4 structural attacks + 5 code bugs identified

## Structural Attack Vectors (need claim strategy decisions)

### ATTACK 1: Alice 101 on Claim 1 — PENDING DECISION
Both reviewers: Claim 1 = "authenticate two parties" (abstract) + off-the-shelf crypto (WURC).
Defense options discussed, user chose "technical improvement" framing but paused before finalizing.
**Resume here: finalize 101 defense strategy, then address Attacks 2-4.**

### ATTACK 2: Obviousness (103) — not yet discussed
Claim 1: Semaphore v4 + World AgentKit + Aztec Connect combination
Claim 9: UCAN/Biscuit + Tornado Cash Nova + DAC (ePrint 2008/428)
Claim 15: Same refs + Tornado MerkleTreeWithHistory

### ATTACK 3: "Mutual authentication" overstated (112) — not yet discussed
Handshake doesn't cross-bind human proof to specific agent or vice versa.
Any valid human + any valid agent with same nonce can pair.

### ATTACK 4: Design-around paths — not yet discussed
Claim 1: Same proving system for both sides escapes "different proving system" element
Claim 9: BBS+ selective disclosure or UCAN-style signed JWTs avoid Poseidon scope commitments
Claim 15: Off-chain registry avoids blockchain element

## Code Bugs (fixable, ~30 min each)

1. **Delegation identity binding gap**: Delegation circuit doesn't bind delegatorPubkey to delegatorCredCommitment. Anyone who knows the public credCommitment can claim to be that delegator.
2. **Agent revocation dead code**: `revokeAgent()` writes to `agentRevocations` but handshake never reads it. No tree-level revocation is implemented.
3. **Delegation not tied to handshake**: `verifyDelegation()` doesn't require a successful handshake for that sessionNonce.
4. **Chain-linking is caller-supplied**: `expectedPreviousScopeCommitment` is a parameter, not derived on-chain.
5. **Privacy overstated**: Nullifiers and scope commitments are stable and emitted as events, making sessions linkable.

## Key Prior Art References

| Reference | Threatens | URL |
|-----------|----------|-----|
| Semaphore v4 | Claim 1 (a)(b) | https://semaphore.pse.dev |
| World AgentKit | Claim 1 (separate registries) | https://docs.world.org/agents/agent-kit |
| Iden3 circuits | Claims 1, 15 | https://docs.iden3.io/protocol/main-circuits/ |
| UCAN | Claim 9 (capability attenuation) | https://ucan.xyz |
| Biscuit | Claim 9 (attenuation chains) | https://doc.biscuitsec.org |
| Tornado Cash Nova | Claim 9 (chained commitments) | tornado.cash |
| Tornado MerkleTreeWithHistory | Claim 15 (root buffer) | tornado.cash |
| DAC (ePrint 2008/428) | Claim 9 (private delegation) | https://eprint.iacr.org/2008/428 |
| Aztec Connect | Claim 1 (batched proofs) | aztec.network |
