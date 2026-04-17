# Fluent delegation chain builder API

The Delegation circuit requires manually constructing scope bitmasks, computing credential commitments, and threading previousScopeCommitment between hops. Build a DelegationChain builder with a fluent API: `DelegationChain.from(agentIdentity).narrow({ canRead: true, canWrite: false, financialLimit: '$1k' }).to(delegateeIdentity).expiresIn('1h').build()`. The builder should enforce cumulative bit encoding invariants (bit 4 implies bits 2+3) at construction time with clear errors, serialize the full chain as a portable JSON token, and handle multi-hop threading automatically up to the 3-hop contract limit.

## Status

Placeholder — awaiting implementation.
