# Fluent delegation chain builder with compile-time scope narrowing

The existing delegation API requires manually constructing Merkle proofs, scope bitmasks, and chaining `previousScopeCommitment` across hops — a footgun-rich surface. Build a `DelegationChain.from(agentCredential).narrowScope(Permission.FINANCIAL_SMALL | Permission.READ_DATA).delegateTo(delegateeCredential).build()` fluent builder that validates cumulative bit encoding at construction time (TypeScript generics prevent expanding scope), auto-fetches Merkle proofs from the registry, and serializes the chain into the wire format the contract expects. The builder produces a `DelegationChainProof` that `verifyHandshake` already knows how to consume.

## Status

Placeholder — awaiting implementation.
