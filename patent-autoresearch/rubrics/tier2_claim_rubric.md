# Tier 2 Claim Strength Rubric

Each dimension is scored 0-20. Total is summed to 100.

## alice_101 (0-20) — 35 USC 101 survival odds

Scoring:
- 0-4:  Pure abstract idea, "apply it on a computer" only, all primitives are well-understood/routine/conventional (WURC)
- 5-9:  Some technical recitation but result-oriented; functional claiming without concrete mechanism
- 10-14: Concrete mechanism recited with specific cryptographic operations (Poseidon hash, EdDSA, Merkle proof)
- 15-18: Specific machine + transformation; ties to circuit constraints (Num2Bits, LessThan) or specific hardware-level operations
- 19-20: Arity-specific hashes + integrated circuit constraints + specific data-structure invariants; reads as specific technology, not abstract idea

Reference case law: Alice Corp. v. CLS Bank, Electric Power Group v. Alsthom, Two-Way Media v. Comcast, BSG Tech v. BuySeasons, Prism Technologies v. T-Mobile, Credit Acceptance Corp. v. Westlake.

## obviousness_103 (0-20) — 35 USC 103 defense odds

Scoring:
- 0-4:  Every element present in a single prior-art reference (anticipated or trivially combined)
- 5-9:  Two-reference combination with clear motivation-to-combine
- 10-14: Three-or-four-reference combination required; motivation becomes strained
- 15-18: Specific integration pattern not taught by any combination; arity/topology differs
- 19-20: Genuinely novel primitive + unexpected technical result (e.g., new security property)

Reference case law: KSR v. Teleflex (motivation-to-combine framework).

## support_112 (0-20) — Written description + definiteness

Scoring:
- 0-4:  Key terms undefined, functional/negative language without spec support
- 5-9:  Partial support; claim scope broader than what spec enables
- 10-14: Adequate support for the main embodiment disclosed
- 15-18: Full support across all disclosed embodiments; all terms defined
- 19-20: Genus language fully anchored by multiple worked examples; negative limitations have explicit rationale in spec

Reference case law: LizardTech v. Earth Resource Mapping (can't claim genus with only one species), Ariad v. Eli Lilly (spec must show possession of full scope), Santarus v. Par (negative limitations need support), Nautilus v. Biosig (reasonable certainty for definiteness), Interval Licensing v. AOL (inconsistent terminology indefinite).

## design_around (0-20) — Competitor escape resistance

Scoring:
- 0-4:  One-line code change escapes (e.g., swap hash function, reorder hash inputs)
- 5-9:  Low-cost escape: hours of work with different primitive (e.g., substitute BBS+ for Poseidon)
- 10-14: Moderate-cost escape: days of work requiring redesign (e.g., move state off-chain)
- 15-18: High-cost escape: weeks of work requiring architectural change
- 19-20: Product-defining claim — escape means not building the product (e.g., the claim covers the only commercially viable topology)

## scope (0-20) — Commercial coverage breadth

Scoring:
- 0-4:  Narrow to a single trivial embodiment
- 5-9:  Narrow but covers the primary product
- 10-14: Covers primary product + one obvious extension
- 15-18: Covers product, foreseeable variations, common alternative implementations
- 19-20: Covers product, variations, and future CIP candidates (recursive SNARK, platform attestations, etc.)

## Verdicts

- `apply`:    total ≥ 80 AND no dimension ≤ 8
- `consider`: total 60-79
- `reject`:   total < 60 OR any dimension ≤ 4
