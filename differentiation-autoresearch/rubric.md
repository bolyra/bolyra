# Differentiation Rubric — 0 to 10 (5 dims × 2 pts)

A construction earns Strength=10 only if **every** dimension scores 2. Any dim at 0 or 1 caps total at 9.

---

## Dim 1 — Baseline dominance (0–2)

- **2** — Construction does something the best non-ZK alternative (RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + DPoP, or W3C VC + BBS+, or SPIFFE/WIMSE) provably cannot. A specific capability is named and explicitly ruled out of the baseline.
- **1** — Construction is preferable to baseline but baseline can approximate with extra configuration.
- **0** — Baseline already does this.

## Dim 2 — Formal security argument (0–2)

- **2** — Explicit threat model (who is adversarial, what they see, what they control), named cryptographic assumption (e.g. discrete log in Baby Jubjub, Poseidon collision resistance, Groth16 knowledge soundness), stated reduction sketch even if informal.
- **1** — Threat model stated but assumption vague or reduction missing.
- **0** — No stated threat model.

## Dim 3 — Implementability in Bolyra (0–2)

- **2** — Construction maps to existing Bolyra primitives (Poseidon hash, Groth16 human circuit, PLONK agent circuit, BabyJubjub EdDSA, nullifier scheme) with stated circuit cost (constraints / proving time target) within Phase 1 budget.
- **1** — Maps to Bolyra primitives but cost unknown or exceeds budget.
- **0** — Requires new primitives or cost is clearly prohibitive.

## Dim 4 — Adversarial survival (0–2)

- **2** — Tier 3 codex adversary + 5 personas (rfc7662_advocate, auth0_pm, spiffe_engineer, cryptographer, cu_ciso) each tried to break the construction and either failed or their attack lies inside the stated threat model.
- **1** — Tier 3 surfaced a real attack that the construction mitigates but weakens the claim.
- **0** — Tier 3 found an attack the construction cannot answer.

## Dim 5 — Scenario fit (0–2)

- **2** — At least one concrete deployment named where this property is load-bearing (not nice-to-have), with named stakeholder or regulatory requirement.
- **1** — Scenario named but only hypothetical or niche.
- **0** — No concrete scenario.

---

## Judge rules

- The judge MUST award 0 on any dim it cannot positively justify from the construction.md and attacks.md contents. Absence of evidence is 0, not 1.
- The judge MUST NOT award 10 without explicit justification per dim.
- The judge MUST name the specific gap if any dim < 2, so the mutator knows what to fix.

## Promote / consider / drop

- **promote** (strength = 10): all dims at 2, survives Tier 3
- **consider** (strength 7–9): iterate with mutator
- **drop** (strength ≤ 6): construction fundamentally flawed; Tier 1 must reseed with a different approach

## Calibration anchors

- "Use ZK" with no construction → 0 (no dim evidence)
- "Groth16 proof of scope membership, no threat model" → 2 (only Dim 3)
- "Selective disclosure with threat model and scenario but RFC 7662 can match" → 6 (no Dim 1 or 2 full)
- Full construction + threat model + Bolyra circuit cost + codex survival + named CU deployment → 10
