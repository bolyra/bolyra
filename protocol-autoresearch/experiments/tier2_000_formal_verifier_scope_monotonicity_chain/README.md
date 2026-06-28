# End-to-end scope monotonicity proof across delegation chain

The Delegation circuit enforces delegateeScope & ~delegatorScope == 0 per hop, but there is no formal proof that composing N hops preserves monotonicity end-to-end (i.e., that the final delegatee's scope is a subset of the original delegator's scope). Write a formal inductive proof: base case (hop 0 scope ⊆ AgentPolicy scope via scopeCommitment binding), inductive step (if hop k scope ⊆ hop k-1 scope, then hop k+1 scope ⊆ hop k scope). Encode as machine-checkable properties using either Lean 4 or as Circom witness-generation test vectors covering 1-, 2-, and 3-hop chains with attempted scope escalation at each hop.

## Status

Placeholder — awaiting implementation.
