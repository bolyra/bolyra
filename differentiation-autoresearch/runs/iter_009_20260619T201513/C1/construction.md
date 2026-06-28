The file write needs your approval. Here's what the refinement does:

**Gap closed:** Section 7 now contains a dedicated "Why SD-JWT (RFC 9635) does not close the gap" subsection with four concrete failure modes and a 6-row comparison table.

**Changes (Section 1 preserved verbatim, no new gadgets):**

1. **Section 7 — new subsection "Why SD-JWT (RFC 9635) does not close the gap":** Four detailed failure analyses: (a) SD-JWT discloses claim *values*, not predicate satisfaction — claim count leaks structure; (b) no predicate evaluation over hidden claims (RFC 9635 Section 5 is explicit); (c) selective disclosure and implication closure enforcement are *mutually exclusive* — the holder can hide claims OR the RS can verify structural invariants, but not both simultaneously; (d) SD-JWT remains issuer-dependent. Includes a 6-row comparison table.

2. **Section 7 — existing baseline analyses preserved:** Boolean-return RFC 7662, Client Attestation, WIMSE WPoP, and hardware-attested SPIRE subsections retained from prior iterations.

3. **Section 8 — SD-JWT added to baseline list in header and across all 6 properties.** Property 2 explicitly calls out SD-JWT's inability to evaluate predicates over hidden claims. Property 4 notes SD-JWT presentation size grows with disclosed claims + salt/value pairs. Property 6 identifies SD-JWT as having no ZK property (disclosed claims are plaintext).

4. **Section 3 — ImplicationClosureForgery sub-game and critical distinction paragraph preserved** from prior iterations.

The core argument against SD-JWT: hiding and implication-closure enforcement are mutually exclusive operations in SD-JWT. The holder can hide claims (selective disclosure) OR the RS can verify structural invariants (by requiring full disclosure) — never both. The `SelectiveScopeProof` achieves both in a single proof because G5 and G6 evaluate over the same hidden `permissionBitmask` witness.
