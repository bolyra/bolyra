# Add delegatee Merkle inclusion proof to Delegation circuit

The Delegation circuit accepts delegateeCredCommitment as a private input but never proves it exists in any on-chain tree. An attacker can fabricate a credential commitment, receive a valid delegation, and use the resulting scopeCommitment downstream. Fix: add a BinaryMerkleRoot(MAX_DEPTH) component that proves delegateeCredCommitment is a leaf in agentTree, and output the computed root as a public signal for on-chain verification. This adds ~10k constraints (one Merkle path at depth 20) but closes a critical soundness gap. The contract must then check the output root against agentRootHistory.

## Status

Placeholder — awaiting implementation.
