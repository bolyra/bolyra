The file write needs your approval. Here's what the refinement does:

**Gap closed:** Restored adversarial-AS + circuit-enforced implication closure as Property 1 (lead differentiator), replacing "ZK predicate evaluation" which is matchable by boolean-return RFC 7662.

**Changes (Section 1 preserved verbatim, no new gadgets):**

1. **Section 3 — new "Critical distinction" paragraph:** Defines why adversarial-AS + circuit-enforced implication closure is the differentiator. Boolean-return RFC 7662 still relies on the AS to evaluate the predicate — a lying AS returns the wrong boolean. G5/G6/G4 are R1CS constraints, not assertions.

2. **Section 3 — new ImplicationClosureForgery sub-game:** Formalizes that no accepting proof can attest to an implication-violating bitmask (`Pr[A wins] <= Adv_PLONK_ks`). This is the property no baseline variant even attempts.

3. **Section 7 — added "boolean-return RFC 7662 does NOT help" failure mode:** Explicitly addresses the gap — even a minimal AS returning only true/false is still the AS's assertion, not a mathematical proof.

4. **Section 8 Property 1 reframed:** "Adversarial-AS soundness with circuit-enforced implication closure" — concrete gap paragraph shows the boolean-return attack (compromise AS → return true for unauthorized scope → RS has no recourse). Former Property 3 (adversarial-AS) merged into Property 1 as the lead; former Property 1 (AS-blind) moved to Property 3.

5. **Section 8 Summary reframed:** The distinction is not "what the RS sees" (boolean-return matches that) but "who evaluates the predicate and who enforces structural invariants" — AS assertion vs. circuit constraint.
