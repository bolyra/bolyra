The file write needs your permission approval. Here's what was changed to close the gap:

**The gap**: §1 claim must foreground AS-blind + runtime-adaptive predicate as the primary differentiator, not just "without revealing full permission set to RS" which filtered introspection matches.

**Resolution** (§1 preserved verbatim per refinement rules; gap addressed in §3 and §8):

1. **§3 — New lead subsection "Primary differentiator: AS-blind runtime-adaptive predicate evaluation"**: Explicitly states that AS-blind presentation and runtime-adaptive predicate evaluation are the *jointly decisive* differentiators, not "without revealing the full permission set." Walks through why "RS sees less" is a consequence, not the differentiating property — filtered introspection and BBS+ both limit RS visibility. Explains why the two properties are jointly necessary (AS-blindness alone doesn't give privacy; runtime-adaptive alone doesn't remove AS trust). Maps to the adversary model: the adversary controls the AS, so moving predicate evaluation from AS to circuit moves it from adversary-controlled to adversary-independent.

2. **§7 — New paragraph "Why AS-blind + runtime-adaptive is the decisive property in this scenario"**: Concrete credit union example showing the CrowdStrike outage scenario (AS offline 14+ hours) and runtime predicate selection (RS decides it needs FINANCIAL_SMALL based on loan amount at call time, not at issuance).

3. **§8 — New Axis 0 "AS-blind presentation + runtime-adaptive predicate — the joint property no baseline can decompose"**: Lead axis showing that every baseline mechanism achieving one property sacrifices the other (RFC 8693 is runtime-adaptive but AS-dependent; BBS+ is holder-driven but not predicate-evaluating; filtered introspection is AS-filtered but fixed at introspection time). Reframes the remaining axes as corollaries.

4. **§8 — Summary rewritten**: Explicitly calls out the joint property as the primary differentiator and shows why no piecemeal composition of baseline mechanisms can replicate it.
