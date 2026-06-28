The file write is being blocked by permissions. Could you approve the write to `differentiation-autoresearch/construction.md`?

Here's a summary of what was changed to close the gap:

**The fix**: Added a formal "Predicate proof vs selective disclosure" distinction in §3 (Threat model) and a new "Gap 0" in §8 (Why the baseline cannot match) that explicitly defeats SD-JWT and BBS+.

**What was wrong**: The prior construction's claim language ("selective scope proof") and Gap analysis didn't explicitly distinguish between *selective disclosure* (revealing a subset of claim values) and *predicate proof with full-bitmask hiding* (proving a Boolean function evaluates to true over a hidden input, leaking only 1 bit). SD-JWT and BBS+ both achieve selective disclosure, so they could be argued to satisfy the written claim.

**How the refinement closes the gap**:

1. **§3 — New subsection "Predicate proof vs selective disclosure: formal distinction"**: Defines the information-theoretic gap: selective disclosure leaks K claim values per query; predicate proof leaks 1 bit. Walks through exactly why SD-JWT (no predicate mechanism at all — `_sd` disclosures reveal `[salt, name, value]`) and BBS+ (linear proof size, structural information leak via hidden message commitment counts, no inter-message invariant enforcement) cannot satisfy the SI game.

2. **§3 — SI game analysis extended**: Added explicit "Why SD-JWT and BBS+ cannot satisfy the SI game" subsection showing that SD-JWT leaks |M_j| bits per query (claim values, not predicate outcome) and BBS+ proofs have variable structure (commitment count reveals hidden message count, breaking indistinguishability).

3. **§8 — New Gap 0**: "Predicate Proof vs Selective Disclosure (the decisive distinction)" — the lead gap, addressing SD-JWT (value revelation per disclosure, no predicate evaluation) and BBS+ (4 sub-points: no bitwise-AND predicate, linear proof size, structural information leak, no inter-message invariant enforcement).

4. **§8 — Summary table expanded**: Added SD-JWT as a separate column, showing it fails on every dimension. BBS+ column sharpened with "proof-size-leaking" and "proof structure leaks hidden message count."

**What was preserved verbatim**: Section 1 (Statement of claim) — unchanged word-for-word per the refinement rules.
