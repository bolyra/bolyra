# Codex Patent Review — IDENTITYOS-PROV-001
Reviewed: 2026-04-15
Status: 15 findings (5 critical, 7 high, 2 medium, 1 coverage gaps)

## Critical Findings

### 1. Nonce equality not enforced on-chain
Contract never checks `humanPubSignals[4] == agentPubSignals[5] == sessionNonce`. It only burns the function argument nonce. Fix: add explicit equality checks.

### 2. Agent revocation key mismatch
Contract stores revocations by `credentialCommitment` but handshake checks `agentRevocations[agentNullifier]`. Inconsistent. Fix: revoke/check by same key consistently.

### 3. Delegation chain doesn't bind delegator identity
`Delegation.circom` only proves `Poseidon(delegatorScope) == previousScopeCommitment`. Any actor with the same scope bits can satisfy the chain link. No identity binding. Fix: hash scope together with delegator credential commitment or public key.

### 4. "Strict subset" is actually just "subset"
Circuit allows equality (delegatee can have same scope as delegator). Patent says "strict." Fix: delete "strict" everywhere or add non-equality constraint.

### 5. Delegation replay + chain-linking not implemented on-chain
`verifyDelegation()` just verifies one proof and emits an event. No nullifier storage, no hop count enforcement, no cross-call linkage. Fix: implement or stop claiming.

## High Findings

### 6. "Batch-verified" is inaccurate
Two separate verifier calls in one transaction ≠ batch verification. Fix: say "verified in a single transaction."

### 7. Agent credential hashes only Ax, not Ay
`AgentPolicy.circom` uses `Poseidon4(modelHash, operatorPubkeyAx, bitmask, expiry)` — missing Ay. Fix: hash both coordinates or claim only x-coordinate.

### 8. Subgroup check is approximate
`HumanUniqueness.circom` checks `secret < 2^251`, not the exact Baby Jubjub subgroup order. Fix: correct the text or implement exact bound.

### 9. Human-to-agent delegation not actually implemented
Draft claims human→agent delegation but code only chains from AgentPolicy's scopeCommitment. Fix: disclose real human-origin delegation or stop claiming it.

### 10. Claim 1 weak in both directions
Broad enough for obviousness over Semaphore + known agent systems, narrow enough to design around. Fix: pull concrete crypto into the independent claim.

### 11. Claim 9 easy to design around
Competitor can switch hash, reveal scopes, use signed capability attenuation. Fix: claim hidden-scope arithmetic enforcement + identity-bound linking + expiry narrowing together.

### 12. Alice 101 risk on Claim 1
Reads like abstract auth with two proofs. Fix: pull Poseidon commitments, public/private input structure, nullifier derivation, Num2Bits range checks into the independent.

### 13. Prior art discussion incomplete
Missing: UCAN, Biscuit (capability chains), AnonCreds/BBS (privacy credentials), RLN (nullifier prior art). Indicio's mutual auth claims not adequately distinguished.

## Medium Findings

### 14. Restriction risk
Examiner likely splits: (i) handshake claims 1-8, (ii) delegation claims 9-14. Claim 15 forced into one group. Prepare for divisional.

### 15. Undefined terms
"Strict subset" unsupported, "recognized operator" undefined, "human"/"uniqueness" not backed by enrollment mechanism. Fix: define narrowly or disclose missing mechanisms.

## Claim Coverage Gaps (not in current claims)
- `Num2Bits(64)` field-overflow hardening to align circuit arithmetic with EVM semantics
- Asymmetric root-freshness model (current root for human, history buffer for agent)
- Identity-bound scope commitment chain (if the delegator-binding defect is fixed, this becomes its own independent claim)
