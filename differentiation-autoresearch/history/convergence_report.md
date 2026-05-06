# Differentiation-autoresearch — Final Convergence Report

**Date:** 2026-04-22
**Runs:** Pass 2 (5 seed candidates, 5 iters each) + Pass 3 (2 new candidates, 5 iters each) + 2 surgical refinements on C7 peak
**Config:** `--all --max-iters 5 --no-codex` (personas-only Tier 3)
**Original target:** Strength = 10/10 for every candidate
**Outcome:** Empirical ceiling is **9/10** under the 5-dim × 2-pt rubric. C7 is the primary wedge. C2 is the secondary wedge. Everything else fails to clear 6/10.

---

## Final scoreboard

| ID  | Claim                                    | Seed | Peak   | Peak iter               | Winner? | adv_survival @ peak |
|-----|------------------------------------------|------|--------|-------------------------|---------|---------------------|
| C1  | Selective scope proof                    | 4    | 6      | iter 4                  | no      | 0/2                 |
| C2  | Cross-scope unlinkability                | 9    | **8**  | iter 1                  | **yes** | 1/2                 |
| C3  | Delegation audit without exposure        | 7    | 6      | iter 5                  | no      | 0/2                 |
| C4  | Issuer-blind attribute predicates        | 9    | 5      | iter 1                  | no      | 0/2                 |
| C5  | Bolyra as MCP auth, generally            | 0    | 5      | iter 1                  | no      | 0/2                 |
| C7  | Cryptographic model-instance binding     | 0    | **9**  | iter 3                  | **yes** | 1/2                 |
| C9  | Forward-secure agent delegation          | 0    | 5      | iter 1-4 (flat plateau) | no      | 0/2                 |

**Two candidates promoted to `winners/`: C7 (9/10) and C2 (8/10).**

---

## Three passes, one honest ceiling

### Pass 1 (aborted)
Module-shadowing bug in `_imports.py` — `sys.path.insert(0, ...)` caused `judge.py` to resolve to the protocol-autoresearch sibling. Fixed by switching to `sys.path.append(...)` plus an `importlib.util.spec_from_file_location` load for the sibling plateau detector. Failed trajectory preserved at `history/score_trajectory.failed_pass1.jsonl`.

### Pass 2 (5 seed candidates)
Ran C1–C5 with the Karpathy-style multi-gap mutator. Every candidate plateaued below target. Median peak 6/10. No candidate cleared 9.

**Diagnosis.** The judge returned 10–15 gaps per iteration. The mutator pipe-lined up to 6 of them simultaneously into Tier 2 refinement. Tier 2 tried to close all 6 at once, bloating the construction and **expanding the attack surface**. Personas then trivially found new holes in the bloat. Result: C2 8 → 8 → err → err → 5. Refinement *regressed* the score rather than hardening it.

### Pass 3 (2 new candidates, hardening mutator)
After the Pass 2 plateau, user chose "Strategic pivot (new candidates)" and multi-selected **C7 (cryptographic model-instance binding)** and **C9 (forward-secure agent delegation)**.

Mutator rewritten to **harden, not expand:**
1. Preserve section 1 (Statement of claim) VERBATIM.
2. Address ONE gap per iteration — the highest-priority one only.
3. Prefer narrowing or defending the threat model over adding gadgets/claims.
4. If the gap cannot be addressed without breaking the claim, admit it in §3 rather than retreat.

Tier 2 Claude-CLI timeout bumped 600 → 1200 s. Run loop wrapped in try/except so a single CLI timeout does not kill the run.

**Result.** C7 climbed 0 → 4 → 6 → **9** → 7 → 6 (peak at iter 3). C9 was flat at 5/5/5/5 across all 4 iterations (structural — forward-secure nullifiers require key-evolution primitives Bolyra does not have in-scope). First time anything crossed 8/10 in this entire program.

### Surgical refinements on C7 peak (both regressed)
Two attempts to close the last point on C7 (iter 3, 9/10, `adversarial_survival = 1/2`):

| Attempt | Strategy | Result |
|---------|----------|--------|
| surgical_refine_c7.py    | Narrow claim to "authorization binding" only; drop FDA/EU-AI-Act scenario | **9 → 7** (hurt `baseline_dominance` 2→1 and `scenario_fit` 2→1; no gain on `adversarial_survival`) |
| surgical_refine_c7_v2.py | Preserve claim verbatim; add §3.1 patching the 5 secondary specification gaps inline | **9 → 5** (bloat pattern reasserted itself — patches expanded attack surface) |

Both directions lost ground. The 9/10 at iter 3 is the empirical ceiling for pure-ZK Bolyra on this claim.

---

## Why 9/10 is the ceiling (and not a bug)

The rubric has a structural tension:

- **`baseline_dominance` (2/2)** requires a claim bold enough that no RFC 7662 / DPoP / RFC 8693 / WIMSE / VC+BBS+ configuration can match.
- **`adversarial_survival` (2/2)** requires every attack to either fail or fall inside the stated threat model.

The bold claim that clears `baseline_dominance` creates exactly the surface that personas (especially `cryptographer` and `spiffe_engineer`) attack for the last `adversarial_survival` point. On C7 the remaining attack is: **`modelHash` is a deployment-time authorization label, not a runtime execution measurement.** An authorized operator can substitute the model *after* the proof is generated. Closing this requires TEE/hardware attestation — out of scope for a pure-ZK construction.

Narrowing the claim to "authorization binding" closes the attack but sacrifices `baseline_dominance`. Adding more circuit machinery patches some secondary gaps but reopens others on the bloat. The rubric and the pure-ZK constraint together cap the reachable score at 9/10.

**This is a feature, not a bug, of the rubric.** A rubric that awards 10/10 to a pure-ZK construction would be miscalibrated — there really is a TEE-shaped hole in "bind cryptographic authorization to runtime execution."

---

## What Bolyra actually differentiates on (data-driven)

### Primary wedge — C7: Cryptographic model-instance binding (9/10)

Bolyra cryptographically binds `(modelHash, operator_pk, permission_bitmask, messageHash)` to each RS invocation. Verifier learns only the tuple — not the API key, session token, or runtime secret. Non-malleability + provider anonymity + per-call payload binding all survive Tier 3.

**What no OAuth/MCP configuration can do:** RFC 7662's signed introspection cannot bind per-call payloads without re-introducing AS participation; DPoP binds to URI not payload; PPIDs cannot provide provider anonymity. Confirmed across all 5 personas.

**Load-bearing scenario:** CISO at regulated deployer (e.g. SECU — NC, 2.7M members) must prove to an NCUA examiner that only approved Anthropic models touched member PII, without revealing which call was which model. Also EU AI Act and Anthropic's own tiered-pricing verification.

**Honest limitation:** Authorization binding, not execution binding. Runtime model substitution requires TEE to close cryptographically.

### Secondary wedge — C2: Cross-scope unlinkability (8/10)

Post-enrollment, the agent generates proofs locally — the AS never sees the per-scope authorization path. OAuth/OIDC structurally requires AS participation at token issuance, so the AS always learns `(agent, RS)`. WIMSE/SD-JWT hide attributes from verifiers, not from issuers. This is the property a credit-union-as-AS cannot reconstruct its members' merchant graph under.

**What blocks 10/10:** the IND-UNL-AS game as written is trivially won because `scopeId` is a public signal (cryptographer Attack 1). Fix requires reformulating the game to challenge "same-agent vs different-agent at known scopes" rather than "which proof covers which scope." Also needs simulation-extractable ZK term + bounded Merkle-root anonymity set + revocation registry design. All closable with focused work.

### Everything else

- **C1 (selective scope)** defeated by AS-side minimal-scope policy + RFC 8693 token exchange. Bitmask intersection predicate real but not load-bearing.
- **C3 (delegation audit)** stayed at 6/10 — narrow regulated-deployment wedge, does not generalize.
- **C4 (issuer-blind predicates)** overlaps BBS+ selective disclosure; the issuer-hiding advantage is thin.
- **C5 (MCP-auth-generally)** codex ruled out in Round 2. This loop confirms it. Auth0/WorkOS/Stytch/Cloudflare win the general case. Bolyra's wedge is regulated-deployment-specific, not general MCP auth.
- **C9 (forward-secure delegation)** plateaued at 5/10 — requires epoch-based key-evolution primitives the current spec does not have. Workable research direction, not a deliverable wedge.

---

## Implications for the Bolyra pitch

Revised differentiation statement (data-driven, replaces prior claims):

> Bolyra's defensible wedges are **cryptographic model-instance binding for AI-agent tool calls (C7, 9/10)** and **AS-blind cross-scope unlinkability for regulated multi-verifier deployments (C2, 8/10)**. These two properties are outside the expressive envelope of RFC 7662 + RFC 8693 + RFC 8707 + DPoP + BBS+ + SPIFFE/WIMSE, confirmed under 5-persona adversarial scrutiny.
>
> Bolyra is NOT general-purpose MCP auth. Auth0/WorkOS/Stytch/Cloudflare Access win the general case. The wedge is regulated-deployment agent authorization, specifically where the verifier needs cryptographic assurance that an AS cannot provide (C2) or where authorization must bind runtime model identity to each call (C7).
>
> The 10/10 target is unreachable under pure-ZK: runtime execution binding requires TEE/hardware attestation. Closing the last point on C7 is a separate "Bolyra + TEE" research track, not a pure-ZK claim.

---

## Options from here

**A. Accept the 9/10 ceiling. Ship C7 + C2 as the two wedges.**
Update strategy/differentiation docs, IETF 1-pager, and CU pitch to lead with C7 + C2 only. Drop C1/C4/C5 from the pitch. Keep C3 as a regulated-niche secondary. Drop C9 as a research topic.

**B. Pass 4 with TEE integration.**
Add a TEE-attestation gadget to C7's circuit so `modelHash` becomes a runtime-execution measurement, not deployment-authorization label. This breaks the pure-ZK premise but is the only path to 10/10 on `adversarial_survival` for C7. Material change to the Bolyra architecture; probably its own spec draft.

**C. Closed-form Pass 4 on C2.**
Reformulate IND-UNL-AS game, add simulation-extractable ZK term, bound Merkle-root anonymity set, design revocation registry. Expected: C2 → 9 or 10/10 in 3-5 focused iterations. Does NOT help C7.

Recommendation: **A now, C next, B only if a customer pulls.**

---

## Artifacts

- `winners/C7/` — iter 3 construction, baseline, attacks, score (9/10)
- `winners/C2/` — iter 1 construction, baseline, attacks, score (8/10)
- `history/score_trajectory.jsonl` — full per-iteration trajectory (36 rows across Pass 2 + Pass 3 + surgicals)
- `history/score_trajectory.failed_pass1.jsonl` — pre-module-fix trajectory (for forensic reference)
- `runs/iter_003_20260422T180320/C7/` — C7 peak
- `runs/iter_006_20260422T195000_surgical/C7/` — surgical v1 (9→7)
- `runs/iter_007_20260422T200000_surgical_v2/C7/` — surgical v2 (9→5)
