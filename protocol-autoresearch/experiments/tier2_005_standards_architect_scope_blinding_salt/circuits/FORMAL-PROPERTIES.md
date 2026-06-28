<!-- This file contains ONLY the new property addition. In the full document,
     this section is appended to the existing FORMAL-PROPERTIES.md. -->

## Property: scopeCommitment Binding (Blinding Salt)

**Added by:** scope-blinding-salt experiment  
**Circuits affected:** AgentPolicy, Delegation

### Statement

An adversary who knows `(permissionBitmask, credentialCommitment)` but does
not know `blindingSalt` cannot recover the committed bitmask from the
published `scopeCommitment`.

Formally:

```
Given:
  scopeCommitment = Poseidon(permissionBitmask, credentialCommitment, blindingSalt)
  credentialCommitment is public
  blindingSalt is private (254-bit, CSPRNG-generated)

Claim (Hiding):
  For any PPT adversary A that knows credentialCommitment and scopeCommitment:
    Pr[A outputs permissionBitmask] <= 256 / 2^254 ≈ 2^{-246}

Claim (Binding):
  Under Poseidon collision resistance over BN254:
    Pr[∃ (b1, s1) ≠ (b2, s2) : Poseidon(b1, C, s1) = Poseidon(b2, C, s2)] = negl(λ)
```

### Rationale

The original `scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)`
was trivially enumerable because `permissionBitmask` is only 8 bits (256
possible values). An adversary could compute all 256 candidate commitments
in < 1ms and match against the observed `scopeCommitment` to recover the
exact permission set.

Adding `blindingSalt` as a third Poseidon input expands the adversary's
search space from 2^8 to 2^254, making brute-force infeasible.

### Verification

- **Circuit test**: `AgentPolicy.test.ts` — "brute-force of 256 bitmask
  values with wrong salt fails to match published commitment"
- **Circuit test**: `AgentPolicy.test.ts` — "same bitmask + credCommitment
  but different salts produce distinct scopeCommitments"
- **Circuit test**: `AgentPolicy.test.ts` — "old 2-input commitment is
  trivially enumerable" (demonstrates the attack this property prevents)
- **Delegation test**: `Delegation.test.ts` — "per-hop salts produce
  different scope commitments"

### Dependencies

- Poseidon collision resistance over BN254 scalar field
- CSPRNG quality of `blindingSalt` generation (see IETF draft §9.1.3)
- Salt freshness per credential (no reuse across credentials or delegation hops)
