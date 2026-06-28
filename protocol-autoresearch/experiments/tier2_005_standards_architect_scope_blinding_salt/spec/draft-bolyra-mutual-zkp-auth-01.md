<!-- This file contains ONLY the new Section 9 addition to the existing IETF draft. -->
<!-- In the full spec, this subsection is appended to the existing Security Considerations. -->

## 9. Security Considerations

### 9.1. Scope Commitment Bitmask Enumeration Attack

#### 9.1.1. Attack Description

In the original AgentPolicy circuit design, `scopeCommitment` was computed as:

```
scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)
```

Since `permissionBitmask` is an 8-bit value (256 possible values) and
`credentialCommitment` is a public output of the AgentPolicy proof, an
observer who knows the `credentialCommitment` can precompute all 256
possible `scopeCommitment` values:

```
for bitmask in 0..255:
    candidate = Poseidon(bitmask, knownCredentialCommitment)
    if candidate == observedScopeCommitment:
        recoveredBitmask = bitmask
```

This offline enumeration attack runs in constant time (256 Poseidon
evaluations, < 1ms on commodity hardware) and completely breaks the
privacy of the permission set.

#### 9.1.2. Mitigation: Blinding Salt

The mitigation introduces a random blinding salt as a third input to the
scope commitment hash:

```
scopeCommitment = Poseidon(permissionBitmask, credentialCommitment, blindingSalt)
```

The `blindingSalt` is a private witness input — it is never revealed
on-chain or in any public signal. The `scopeCommitment` remains the sole
public output representing the agent's permission scope.

#### 9.1.3. Salt Requirements

Implementations MUST adhere to the following requirements:

1. **CSPRNG Generation**: The `blindingSalt` MUST be generated using a
   cryptographically secure pseudorandom number generator (CSPRNG) such
   as `crypto.getRandomValues()` (Web Crypto API) or `/dev/urandom`.

2. **Bit Length**: The salt MUST be at least 128 bits of entropy. The
   reference implementation uses 254 bits (fitting within the BN254
   scalar field).

3. **No Reuse**: The `blindingSalt` MUST NOT be reused across different
   credentials. Each call to `createAgentCredential()` MUST generate a
   fresh salt. Reusing a salt across two credentials with different
   bitmasks allows an observer to distinguish them via differential
   analysis.

4. **Secrecy**: The `blindingSalt` MUST be treated with the same
   confidentiality as the credential's private key material. It MUST NOT
   appear in logs, error messages, or any observable channel.

5. **Delegation Freshness**: When creating a delegated credential via
   the Delegation circuit, the delegated hop MUST use its own fresh
   `blindingSalt`, independent of the parent credential's salt. This
   prevents linking parent and delegated scope commitments.

#### 9.1.4. Security Analysis

Under the assumption that Poseidon is collision-resistant and
preimage-resistant over the BN254 scalar field:

- **Hiding**: Given `scopeCommitment` and `credentialCommitment`, an
  adversary cannot determine `permissionBitmask` without knowing
  `blindingSalt`. The search space is 2^254 (salt) rather than 2^8
  (bitmask), making brute-force computationally infeasible.

- **Binding**: An adversary cannot find two distinct
  `(bitmask, salt)` pairs that produce the same `scopeCommitment`
  for a given `credentialCommitment`, under Poseidon collision
  resistance.

- **Unlinkability**: Different credentials with the same permission
  bitmask produce distinct scope commitments (with overwhelming
  probability) due to independent salts.

#### 9.1.5. Constraint Cost

The change from 2-input to 3-input Poseidon adds approximately 30 R1CS
constraints (one additional S-box column in the Poseidon permutation).
Total AgentPolicy constraint count increases from ~250 to ~280. This has
negligible impact on proving time (< 5% increase for Groth16, measured
via `circuits/scripts/bench_rapidsnark.js`).
