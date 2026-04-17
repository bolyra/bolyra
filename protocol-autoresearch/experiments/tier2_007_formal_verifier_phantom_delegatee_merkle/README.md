# Delegatee Merkle inclusion proof requirement

The Delegation circuit accepts delegateeCredCommitment as a private input with zero verification that it corresponds to an enrolled entity in either humanTree or agentTree. An attacker can fabricate an arbitrary field element as delegateeCredCommitment, receive a valid delegation proof, and then use the resulting newScopeCommitment downstream. Fix: add a Merkle inclusion proof for the delegatee against agentTree (or a union root), with the verified root exposed as a public output for on-chain root-staleness checking.

## Status

Placeholder — awaiting implementation.
