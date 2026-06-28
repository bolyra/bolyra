The construction is ready. Here's a summary of the refinement:

**Gap closed: Baseline comparison now addresses PPID+RFC 8707+DPoP+BBS+ (Mode B), not vanilla RFC 7662**

Key changes across sections 3, 4, and 8:

1. **Section 3 — Baseline modeling subsection added.** Explicitly defines two baseline modes: Mode A (per-RS token issuance, trivially broken) and Mode B (BBS+ offline presentation — the genuine bar to beat). Enumerates 5 structural gaps in Mode B: (B1) PPID is AS-computed/embedded, (B2) issuer pubkey always disclosed, (B3) quasi-identifier attack under collusion, (B4) credential refresh timing, (B5) no formal unlinkability game.

2. **Section 4 — Theorem 4.6 added.** Formalizes BBS+ Mode B in the IND-UNL-AS game across three sub-cases: (Case 1) PPIDs embedded → AS dereferences via mapping table, Adv=1/2. (Case 2) No PPID → multi-show unlinkable but no account continuity, functionally incomplete. (Case 3) Agent-derived pseudonym from credential fields → AS knows all fields, can recompute, Adv=1/2. **In all functional cases, Adv=1/2.** Corollary 4.7 summary table now includes both Mode A and Mode B columns.

3. **Section 8 — Rewritten against BBS+ Mode B.** Drops the straw-man "AS sees every per-RS event" framing. The five structural impossibilities now address Mode B specifically: (1) no issuer-opaque persistent pseudonym, (2) forced tradeoff between continuity and unlinkability, (3) quasi-identifier attack, (4) delegation requires AS involvement, (5) no formal security definition against adversarial issuer.

4. **Section 7 — Deployment scenarios updated.** Both CU and healthcare scenarios now show concretely how BBS+ Mode B fails (PPID mapping table, no privacy-preserving delegation) and why Bolyra's `scopeBlindingSecret` creates the separation.

**Core insight:** The advantage doesn't evaporate against BBS+ because the structural gap isn't "AS sees per-RS events" (which BBS+ offline does fix) — it's "no persistent pseudonym exists that is both AS-opaque and RS-verifiable." The `scopeBlindingSecret` — a locally-generated secret never part of the issued credential — is the primitive that creates the `1/2 - negl(λ)` separation. No credential-based system where the issuer signs all claims can replicate it.
