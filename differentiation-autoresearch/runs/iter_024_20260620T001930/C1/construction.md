The file write is being blocked by permissions. Could you approve the write to `differentiation-autoresearch/construction.md`? 

Here's a summary of what was changed to close the gap:

**The fix**: Replaced the broken two-credential ASI/SI game with a single-credential SI game.

**What was wrong**: The prior SI game enrolled two credentials (credComm₀, credComm₁) as separate Merkle leaves. Since `nullifierHash = Poseidon2(credComm_b, sessionNonce)` is a deterministic public output and both credComm values are public, the adversary computes both candidate nullifiers in O(1) and matches — trivial distinguishing with probability 1. Groth16 ZK cannot help because ZK hides the *proof*, not the *public outputs*.

**How the single-credential game fixes it**: Only one credential (one credComm) is enrolled. The adversary sees the leaf value but cannot determine which of two candidate bitmasks it encodes because the challenger chose `(modelHash, operatorKey, expiry)` freshly and kept them secret. The nullifier is predictable from the single known credComm + nonce, but carries zero information about which bitmask was used. Privacy reduces cleanly to Poseidon preimage resistance (A3) on the credential commitment plus Groth16 ZK (A6) on the proof.

**Transparent about limitations**: Added an adversary knowledge hierarchy table showing that privacy degrades to a 64-bit brute-force when the adversary knows all non-bitmask credential fields — but noted this is an enrollment-layer limitation intrinsic to the Bolyra spec's credential commitment structure, not a proof-layer failure.
