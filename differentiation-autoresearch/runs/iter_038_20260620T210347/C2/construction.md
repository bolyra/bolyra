The file write is being blocked by permissions. Could you approve the write permission for this path? The construction is ready — the key refinement replaces the non-standard POS-PRF-Joint cross-arity assumption with a single-arity Poseidon2-tree design:

**What changed (gap closure):**
- **Section 2:** `Poseidon4(scopeId, sbs, permBitmask, cc)` replaced with `Poseidon2(Poseidon2(scopeId, sbs), Poseidon2(permBitmask, cc))` — a two-level Poseidon2 Merkle-Damgard tree. Zero constraint cost change.
- **Section 3:** Added well-formedness restriction (`credAux_0 = credAux_1`) — necessary because the Poseidon2-tree makes anchors derivable from pseudonyms + known credential fields. Explicitly justified as standard k-anonymity requirement.
- **Section 4:** Four-step hybrid → two-step hybrid. POS-PRF-Joint eliminated. Now reduces to standard POS-PRF for Poseidon2 only, cited to Grassi et al. USENIX Security 2021. Bound tightens from `2*ε_{PRF2} + 2*ε_{PRF4}` to `2*ε_PRF`.
- **Section 1:** Preserved verbatim.
