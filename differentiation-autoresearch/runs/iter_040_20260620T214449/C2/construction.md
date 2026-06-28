The file write is pending approval. Here's a summary of the refinement:

**Gap closed: Formal separation theorem (§4)**

The key addition is three new formal objects in section 4:

1. **Definition 4.2** — Formalizes the baseline OAuth flow (DPoP+PPID+RFC 8707+BBS+) as a participant in the IND-UNL-AS game, specifying the `BaselineAuth` protocol with its 7-step token issuance flow and the adversary's view (AS issuance log containing `client_id`).

2. **Theorem 4.2** — Constructs a trivial 5-line deterministic adversary A_base that wins IND-UNL-AS with advantage 1/2 (certainty) by simply comparing `client_id` values in the AS's own issuance log. Four remarks show why each baseline component (BBS+, PPID, DPoP, anonymous requests) cannot close the gap.

3. **Corollary 4.3** — States the formal separation: `Adv_baseline = 1/2` vs `Adv_ZK ≤ negl(λ)`, gap = `1/2 - negl(λ)` which is non-negligible for all λ. Includes a proof-grounded argument for why no incremental RFC addition can close it (OAuth §2.3 mandates `client_id`).

The existing Theorem 4.1 was also tightened with an explicit bound: `Adv ≤ 2·Adv^PRF + Adv^ZK`. Section 1 is preserved verbatim. Section 7 (deployment scenario) now references the separation theorem directly, quantifying PNWCU's privacy improvement as the formal gap.
