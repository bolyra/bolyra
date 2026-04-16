# Adversarial Review — Round 2 (post Attack 2 fixes)
Reviewed: 2026-04-16
Source: Claude subagent on narrowed claims
Status: 17 new issues identified

## Net assessment
Claims 1 and 9 improved meaningfully. Claim 15 (new super-claim) has
structural language problems. **5 issues are high severity; the rest
are medium-to-low. 2 are must-fix before filing.**

---

## MUST-FIX BEFORE FILING

### M1. Claim 15 uses functional/negative language without spec support
Phrases to excise:
- "sole authoritative source of chain-linking information" (15(b))
- "rejection conditions are checked exclusively against on-chain state" (15(d))

Neither "authoritative" nor "exclusively" has any supporting text in
the spec. 112(a) rejection near-certain.

**Fix:** Replace with concrete mechanics. Add definitional paragraph
to Section 7.5 explaining the chain-state mapping and why caller-supplied
continuity is rejected (replay across sessions, chain forking,
confused-deputy).

### M2. Claim 1(d)(iii) is a one-line design-around
Current: "stores the identity-bound scope commitment... as an on-chain
chain-state seed indexed by the session nonce."

Competitor escape: `emit ScopeCommitmentSeeded(...)` instead of storage
write. Delegation verifier reads from event log (EIP-3668 CCIP-read).

**Fix:** Broaden to "records the identity-bound scope commitment on the
blockchain in a manner retrievable by a subsequent delegation verification
function, comprising at least one of: a storage variable, an event log,
or a commitment to a root of such records."

---

## HIGH SEVERITY (5)

### H1. "Chain-state mapping" undefined in spec
Appears in Claims 9(a,d,i) and 15(b,c,d). Code has `lastScopeCommitment`
but spec never defines the term. 112(a) rejection.

**Fix:** Add Section 7.5 defining chain-state mapping, its seeding by
handshake, its advancement by each delegation, and its write-exclusivity.

### H2. Claim 9(b) "mutual authentication handshake" too generic
Invites TLS 1.3 mutual auth as prior art. Examiner combines TLS + UCAN +
Semaphore and argues the ZK "handshake" is obvious.

**Fix:** Tie back to specific ZK handshake of Claim 1 — e.g., "a verified
mutual authentication handshake comprising a Groth16 human membership
proof and a PLONK agent credential proof verified in a single blockchain
transaction, wherein said handshake seeded said chain-state mapping with
an identity-bound scope commitment."

### H3. Claim 15 agent-to-agent design-around
Claim 15(a) requires "a human user and an AI agent." Pure agent-to-agent
B2B systems don't infringe. **Cheapest escape for the entire patent.**

**Fix:** Add parallel Claim 15' for "any two ZK-provable identities"
(human or agent), keeping mutual-auth-seeded chain-state as the novel
feature.

### H4. Killer 103 combo still bites
**Semaphore v4 + Indicio ProvenAI + Aztec Connect + UCAN + Biscuit.**
All five are privacy-preserving authorization primitives. Motivation to
combine: each fixes another's acknowledged gap.

**Defense:** The specific Poseidon arities and integration pattern are
the distinguishing features. Add dependent claims reciting exact Poseidon
arities (Poseidon5 for credential, Poseidon2 for scope, Poseidon2 for
nullifier, Poseidon4 for delegation token). Arity-specific claims resist
KSR-style generic combination attacks.

### H5. Revoked human can still seed delegation
Human revoked at time T+1 after handshake at T. `verifyDelegation` doesn't
check `humanRevocations` (delegations are agent-to-agent). Revoked human's
authority persists in the chain.

**Fix:** Either (a) clear `lastScopeCommitment[nonce]` on human revocation,
(b) add revocation-epoch check, or (c) document as accepted risk.

---

## MEDIUM SEVERITY (7)

### M3. "Identity-bound" needs promoted definition
Appears in 3 independent claims. Current definition buried in §3.7.
**Fix:** Add §3.7.1 "Identity-Bound Commitment, Defined."

### M4. Hash-variant design-arounds
Claim 9(d) specifies `Poseidon2(bitmask, credCommitment)`. Competitor uses
`Poseidon3(bitmask, credCommitment, hopIndex)` or reversed order
`Poseidon2(credCommitment, bitmask)` — both escape literal infringement.
**Fix:** Broaden to "cryptographic commitment computed from at least..."
and add dependent for specific Poseidon2 preferred embodiment.

### M5. Delegation circuit doesn't enforce delegator Merkle inclusion
Claim 9(c) recites "Merkle-included in said agent credential tree." The
circuit doesn't directly constrain this — it's only transitively enforced
via chain-linking. 112(a) written description issue.
**Fix:** Either add Merkle-inclusion to Delegation circuit (~10k constraints)
or amend claim to "corresponding to a prior valid proof in the authentication
chain" (transitive language).

### M6. Revocation grace-window mismatch
Spec says revocation "invalidates all subsequent Merkle proofs." False —
pre-revocation roots stay in 30-entry buffer, so revoked agents can produce
valid handshakes until their root is evicted.
**Fix:** Document grace window in §7.4, or purge buffer on revocation,
or add immediate `revokedCredentials` mapping checked at handshake time.

### M7. 101 risk on Claim 15 functional language (see M1)

### M8. Cumulative invariant spec narrative is now stale
Spec §6 says enforced "at delegation time." Code now enforces in BOTH
AgentPolicy and Delegation. Mismatch.
**Fix:** Update §6 to reflect both enforcement points.

### M9. Nonce binding check — spec says re-checked on-chain; code doesn't
Redundant with Groth16 validity (circuit enforces correctness).
**Fix:** Remove false claim from §2.5.

---

## LOW SEVERITY (5)

### L1. `verifyDelegation` uses `usedNonces` proxy instead of `lastScopeCommitment != 0`
Works today but fragile if future code adds `usedNonces = true` paths
without seeding chain state.
**Fix:** `if (lastScopeCommitment[sessionNonce] == 0) revert
DelegationRequiresHandshake();`

### L2. Output signal ordering is fragile (no type check)
If circuit output declarations are reordered, contract breaks silently.
**Fix:** Add test that asserts `pubSignals[2]` equals expected
`Poseidon2(permissionBitmask, credentialCommitment)`.

### L3. Out-of-order delegation not addressed in spec
**Fix:** Add statement in spec: "delegation hops must be verified in
strict sequential order per session nonce."

### L4. Zero-commitment edge case
If agent's scope commitment happens to be 0 (astronomically improbable
under Poseidon), chain appears unseeded. Accept risk.

### L5. Session length vs. hop limit
MAX_DELEGATION_HOPS=3 means longer chains require new handshake. Document
that cross-session chains are not cryptographically linked.

---

## BOTTOM LINE

The narrowing helped. But filing as-is risks:
- **112(a) rejection on Claim 15 language** (near-certain)
- **One-line design-around on Claim 1(d)(iii)** (easy competitor escape)
- **103 obviousness via 5-reference combo** (still plausible)
- **Pure agent-to-agent systems entirely outside patent** (critical gap)

Before filing, apply M1 and M2 at minimum. H1-H5 strongly recommended.
M3-M9 can wait for non-provisional conversion (12 months).
