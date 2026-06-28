The file write needs your approval. The construction is ready with the key refinement:

**Gap closed: IND-UNL-AS game formalization (§3)**
- **Definition 3.1** — full formal game with 4 phases (Setup, Learning, Challenge, Guess)
- **Oracle access:** `Prove(i, scopeId, freshNonce)` with explicit freshness condition (cannot query challenge agents at challenge scopes)
- **sbs is stateful:** Property 3.2 explicitly states it's drawn once at enrollment, reused across all sessions — PRF security handles poly(λ) adaptive queries
- **cc/permBitmask are public:** Property 3.3 — adversary receives all credential fields in Phase 0 (AS-as-issuer model)
- **Well-formedness predicate `W(i_0, i_1)`:** `credAux_0 = credAux_1` — justified as k-anonymity condition, with concrete anonymity set size in §7 (20,000 agents per tier in CU deployment)
- **Advantage bound:** Theorem 4.1 states `Adv ≤ 2·ε_PRF(λ, q+2)` — tight, single-assumption

**Also applied the Poseidon2-tree changes from the blocked prior iteration:**
- Anchor now `Poseidon2(Poseidon2(scopeId, sbs), Poseidon2(permBitmask, cc))` — eliminates POS-PRF-Joint
- Hybrid argument simplified from 4 steps to 2 steps under POS-PRF for Poseidon2 only
- Bound tightens from `2·ε_{PRF2} + 2·ε_{PRF4}` to `2·ε_PRF`

Could you approve the write permission?
