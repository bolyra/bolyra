# Adversarial Patent Review — IDENTITYOS-PROV-001
Reviewed: 2026-04-15
Sources: Codex + Claude subagent (independent parallel reviews)
Status: 4 structural attacks + 8 code bugs identified

## Resume Point
**Claim strategy discussion started (101 defense). User paused mid-review while travelling.
Resume: finalize 101 defense, then Attacks 2-4, then code fixes.**

---

## Structural Attack Vectors (need claim strategy decisions)

### ATTACK 1: Alice 101 — PENDING DECISION
Both reviewers: All 3 independent claims directed to abstract ideas + WURC primitives.
- Claim 1 = identity verification (see *Prism Technologies v. T-Mobile*)
- Claim 9 = authorization delegation (power of attorney predates computers)
- Claim 15 = "on a blockchain" doesn't save abstract concept (see *Burstiq v. Dentaquest*)

Every individual element is WURC: Poseidon (Grassi 2021), EdDSA/BabyJub (circomlib 2019), Groth16 (2016), PLONK (2019), Merkle trees, nullifiers (Semaphore/Tornado 2019-2020), Num2Bits, LessThan, LeanIMT, root history buffer (Tornado).

"Ordered combination" defense is weak (ordering is mathematical necessity, not inventive).

**Defense option chosen (not yet finalized): "technical improvement" framing** — mixed proving system optimizes different trust assumptions in single atomic transaction.

### ATTACK 2: Obviousness (103) — not yet discussed
**Claim 1:** Semaphore v4 + World AgentKit + Aztec Connect
- Semaphore: human identity, Groth16, LeanIMT, nullifiers, Baby Jubjub
- AgentKit: separate human/agent registries, agent credentials
- Aztec Connect: batched multi-proof verification in single tx
- Motivation: POSITA building human+agent identity would naturally combine the leading ZK identity primitive + the obvious agent extension + gas-efficient batching

**Claim 9:** UCAN + Tornado Cash Nova + Semaphore/circomlib
- UCAN: capability attenuation chains, subset enforcement, expiry narrowing, issuer signatures
- Tornado Nova: chained Poseidon commitments via ZK proofs, on-chain nullifiers
- Semaphore/circomlib: EdDSA in ZK, bitmask operations as R1CS
- Motivation: POSITA wanting privacy for UCAN-style delegation would implement in ZK circuits using commitment chaining (see Vitalik's Soulbound Tokens paper 2022)

**Both reviewers rate 103 as the MOST DANGEROUS attack (70%+ kill probability for Claims 1 and 9).**

### ATTACK 3: Enablement/112 — not yet discussed
1. **Sybil resistance is a stub** — claims cover complete system but spec only discloses passphrase enrollment
2. **"Mutual authentication" overstated** — handshake doesn't cross-bind human to specific agent. Any valid human + any valid agent with same nonce can pair
3. **"AI agent" undefined** — could be any credentialed software entity
4. **"Privacy-preserving" undefined** — system leaks nullifiers (linkable), scope commitments (stable), Merkle roots (narrows to group)
5. **"Identity-bound" is a coined term** without art antecedent

### ATTACK 4: Design-around paths — not yet discussed
**Claim 1 (cheapest escapes):**
- Use same proving system for both sides (escapes "different proving system")
- Use single tree with type flag (escapes "first tree / second tree")
- Verify in two transactions with commitment linking (escapes "single transaction")
- Use MiMC/Rescue/SHA256 instead of Poseidon

**Claim 9 (cheapest escapes):**
- Accumulate delegation cleartext off-chain, single ZK proof at verification (escapes per-hop proofs)
- Recursive SNARKs folding all hops into one proof (escapes per-hop on-chain verification)
- Pedersen or polynomial commitments instead of Poseidon2
- BBS+ selective disclosure instead of bitmask subset checking

**Claim 15:** Change any 2 of: hash function, tree structure, proving system pair, commitment structure.

---

## Code Bugs (fixable)

### From Codex review:
1. **Delegation identity binding gap**: Delegation circuit doesn't bind delegatorPubkey to delegatorCredCommitment. Anyone who knows the public credCommitment can claim to be that delegator. The EdDSA signature proves *some key* signed, not that the key belongs to the entity in the commitment.
2. **Agent revocation dead code**: `revokeAgent()` writes to `agentRevocations` mapping but no verification function reads it. Dead code.
3. **Delegation not tied to handshake**: `verifyDelegation()` doesn't require a successful handshake for that sessionNonce.
4. **Chain-linking is caller-supplied**: `expectedPreviousScopeCommitment` is a parameter from untrusted caller, not derived on-chain. Malicious relayer can skip hops.
5. **Privacy overstated**: Nullifiers and scope commitments are stable and emitted as events, making sessions linkable.

### Additional from Claude subagent:
6. **Cumulative bit encoding not enforced in AgentPolicy**: Only enforced in Delegation circuit. An agent enrolled with bit 4 but not bits 2-3 passes AgentPolicy. The "first agent" in a chain can have inconsistent bitmask. Patent claims it as a system invariant but only delegation enforces it.
7. **HumanTree has no root history buffer**: Human proofs go stale immediately on any new enrollment (checked against `_root()` only). Agent side has 30-entry buffer. Patent doesn't disclose this asymmetry. Human proof generated 1 second before a new enrollment fails.
8. **Signal ordering convention undisclosed**: The public signal order (outputs first, then inputs) is a snarkjs/circom implementation detail not specified in the patent. Accused infringer could argue ambiguity.

---

## Kill Probability Assessment (cross-model consensus)

| Attack | Severity | Kill Probability |
|--------|----------|-----------------|
| 103 Obviousness (Semaphore+AgentKit+UCAN+Tornado) | VERY HIGH | 70%+ |
| 101 Alice (abstract authentication + WURC) | HIGH | 40-50% |
| 112(a) Enablement (sybil stub, mutual auth overstated) | MEDIUM-HIGH | 50% for narrowing |
| 112(b) Indefiniteness (coined terms) | MEDIUM | 30% |
| Design-around: single proving system + single tree | CRITICAL | Competitor ships in weeks |
| Code gap: cumulative invariant not in AgentPolicy | MEDIUM | Inconsistency weakens claims |
| Code gap: chain-linking relies on trusted caller | MEDIUM | Weakens enforceability narrative |

---

## Key Prior Art References

| Reference | Threatens | URL |
|-----------|----------|-----|
| Semaphore v4 | Claim 1 (a)(b) nearly verbatim | https://semaphore.pse.dev |
| World AgentKit (Mar 2025) | Claim 1 (separate registries) | https://docs.world.org/agents/agent-kit |
| Iden3 circuits | Claims 1, 15 (signed ZK creds) | https://docs.iden3.io/protocol/main-circuits/ |
| UCAN | Claim 9 (capability attenuation) | https://ucan.xyz |
| Biscuit | Claim 9 (attenuation chains) | https://doc.biscuitsec.org |
| Tornado Cash Nova (2021) | Claim 9 (chained commitments) | tornado.cash |
| Tornado MerkleTreeWithHistory | Claim 15 (root buffer) | tornado.cash |
| DAC (ePrint 2008/428) | Claim 9 (private delegation) | https://eprint.iacr.org/2008/428 |
| Aztec Connect (2022) | Claim 1 (batched proofs) | aztec.network |
| MACI | Claim 1 (EdDSA Poseidon in circom) | github.com/privacy-scaling-explorations/maci |
| Vitalik SBT paper (2022) | Motivation to combine (private credentials) | — |
| *Prism Technologies v. T-Mobile* | 101 case law (auth = abstract) | 928 F.3d 1364 |
| *Burstiq v. Dentaquest* | 101 case law (blockchain ≠ eligible) | — |
