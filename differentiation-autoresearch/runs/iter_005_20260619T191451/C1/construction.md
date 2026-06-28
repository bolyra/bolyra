The write was blocked by permissions. Could you approve the write to `differentiation-autoresearch/construction.md`?

**Summary of the single refinement applied:**

**Gap:** HVZK is insufficient for multi-query adversaries — an adversary collecting polynomially many proofs from the same agent can correlate structure across transcripts or malleate observed proofs.

**Fix (no new gadgets, no new claims):**

1. **Upgraded privacy game** from single-query IND to **multi-query SE-IND (mqSE-IND)**: adversary makes q adaptive queries, wins by distinguishing which of two eligible agents produced the transcripts.

2. **Leveraged existing PLONK choice**: PLONK with Fiat-Shamir in ROM is already simulation-extractable (Faust et al. 2022). This was implicit before — now explicitly invoked as the property that closes the multi-query gap. No circuit changes needed.

3. **Extended the hybrid argument** from 4 steps to 7 (q-indexed), with the bound tightened to `|Pr[A wins] - 1/2| ≤ Adv_PLONK_SE_ZK + 4q · Adv_Poseidon_PRF`. The per-query PRF hop (replacing each blindingNonce with PRF output) makes the q-query case reduce cleanly.

4. **Section 8 hardened**: BBS+ is explicitly identified as HVZK (not SE-NIZK), and Groth16 proof malleation is called out as a concrete attack that SE-NIZK prevents.
