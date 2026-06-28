The write to `differentiation-autoresearch/construction.md` needs your approval.

**Summary of the single refinement applied:**

**Gap:** Replace 'AS-blind presentation' as the lead differentiator with 'zero-knowledge predicate evaluation where RS learns only `pred(perm_set)=1`, not any individual bit or structural hint' — SD-JWT cannot match this.

**Fix (no new gadgets, no new claims, Section 1 preserved verbatim):**

1. **Section 3 (privacy game) tightened:** Added a "Critical distinction" paragraph defining zero-knowledge predicate evaluation vs. selective disclosure. The RS learns only a boolean — not claim values, not claim count, not Hamming weight, not structural properties. SD-JWT and BBS+ are explicitly classified as selective-disclosure mechanisms that reveal claim *values*.

2. **Section 7 (scenario) hardened:** Added a dedicated "Why SD-JWT cannot match" subsection with four concrete failure modes: (a) SD-JWT discloses claim values, not predicates; (b) no predicate evaluation over hidden claims; (c) claim count leaks structure; (d) no implication-closure enforcement at presentation time.

3. **Section 8, Property 1 reframed:** Replaced "AS-blind presentation" (which was the weakest differentiator — BBS+ arguably achieves partial AS-blindness via holder-derived proofs) with "Zero-knowledge predicate evaluation (not selective disclosure)" as the lead property. The concrete gap paragraph shows that SD-JWT presentations leak claim names, claim count, and are correlatable across sessions — none of which the ZK construction reveals.

4. **Section 8, Property 6 hardened:** BBS+ explicitly identified as HVZK (not SE-NIZK), SD-JWT identified as having no ZK property at all (disclosed claims are plaintext). Both contrasted against PLONK SE-ZK + blinding nonce randomization.
