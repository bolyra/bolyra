# Certora-style invariant properties for all three circuits

Write machine-checkable invariant specifications for HumanUniqueness, AgentPolicy, and Delegation. Properties include: (1) no private input can exceed its declared bit-width after Num2Bits decomposition, (2) nullifierHash is deterministic given (scope, secret) or (nonce, credCommitment), (3) scopeCommitment chain is monotonically narrowing across delegation hops (delegateeScope & ~delegatorScope == 0), (4) Merkle root output is uniquely determined by leaf + proof path. Express these in a property specification language (circomspect annotations or a standalone JSON property file) that can be consumed by circomspect or picus. Include 10+ negative witness test vectors that violate each property.

## Status

Placeholder — awaiting implementation.
