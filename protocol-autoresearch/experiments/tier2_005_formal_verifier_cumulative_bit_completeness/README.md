# Prove cumulative bit encoding is exhaustively enforced

The Delegation circuit enforces bit4 => bits 2+3 and bit3 => bit2 on the delegatee scope. Verify this is also enforced in AgentPolicy (it should be, since an agent minting a credential with bit4=1, bit3=0 would violate the invariant). Write an exhaustive property: for every satisfying assignment, the 64-bit decomposition of permissionBitmask satisfies all implication rules. Additionally verify that the subset check (delegateeScope & ~delegatorScope == 0) composes correctly with cumulative encoding — i.e., if delegatorScope is valid and delegateeScope is a subset, then delegateeScope is also valid.

## Status

Placeholder — awaiting implementation.
