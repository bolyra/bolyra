# Tier 3 Adversarial Review Rubric

Codex-harness adversarial review for experiments promoted from Tier 2.
6 review axes. Each reviewer returns APPROVE / CONDITIONAL / REJECT with reasoning and concrete fixes.

---

## Review Axes

### 1. Circuit Correctness
**Reviewer focus:** ZK soundness, completeness, and zero-knowledge properties.

Checklist:
- [ ] All private inputs are constrained; no unconstrained signal paths
- [ ] Nullifier computation is deterministic and collision-resistant
- [ ] Merkle inclusion checks use the correct tree root (no root substitution)
- [ ] Delegation scope is monotonically narrowing (never expanding)
- [ ] No over/underflow in field arithmetic (prime field boundary respected)
- [ ] Output signals cannot be forced to arbitrary values by malformed witnesses
- [ ] New circuits do not break existing circuit interface contracts

### 2. Security
**Reviewer focus:** Cryptographic assumptions, attack surface, on-chain exploits.

Checklist:
- [ ] No weak randomness (block.timestamp, blockhash) used as entropy
- [ ] Reentrancy guards on all state-modifying contract functions
- [ ] Replay protection: nullifiers stored and checked before state changes
- [ ] No front-running opportunities in enrollment or verification flows
- [ ] Emergency pause / revocation path exists and is tested
- [ ] Trusted setup assumptions documented; ceremony type identified
- [ ] New attack surface introduced is bounded and documented

### 3. API Design
**Reviewer focus:** SDK ergonomics, type safety, error handling, versioning.

Checklist:
- [ ] Public API surface is minimal (no unnecessary exports)
- [ ] TypeScript types are strict (no `any`; no implicit nulls)
- [ ] Errors are typed and include actionable remediation hints
- [ ] Async/await patterns are consistent; no mixed callback/promise styles
- [ ] Breaking changes are flagged and versioned
- [ ] Hello-world example compiles and runs in ≤10 lines
- [ ] SDK does not bundle proving keys (must be loaded externally)

### 4. Spec Quality
**Reviewer focus:** RFC 2119 compliance, completeness, implementability.

Checklist:
- [ ] All normative requirements use MUST / MUST NOT / SHOULD / MAY
- [ ] Terminology section defines all domain-specific terms
- [ ] Wire format is fully specified (field names, types, encoding)
- [ ] Error conditions and recovery procedures are specified
- [ ] Security Considerations section present and substantive
- [ ] Test vectors cover all specified normative behaviors
- [ ] Spec is implementable without reference to source code

### 5. Integration
**Reviewer focus:** Framework compatibility, dependency hygiene, CI impact.

Checklist:
- [ ] LangChain/CrewAI/AutoGen integration does not pin conflicting deps
- [ ] No new runtime pip/npm installs required
- [ ] Experiment artifacts do not pollute the root package namespace
- [ ] Existing CI (104 unit + 7 integration tests) still passes
- [ ] New tests added to the test suite (not just in experiments/)
- [ ] Cross-chain paths have testnet evidence, not just code

### 6. Performance
**Reviewer focus:** Constraint count, proving time, gas cost, latency.

Checklist:
- [ ] Circuit constraint count ≤ 80k (hard budget)
- [ ] Proving time measured and reported (target: <5s on commodity hardware)
- [ ] On-chain verification gas measured (target: <300k gas per verify call)
- [ ] No O(n²) growth paths in witness generation
- [ ] Batching or off-chain paths considered for high-throughput scenarios
- [ ] Constraint delta vs. baseline reported (new constraints / feature)

---

## Verdict Format

Each reviewer returns a structured verdict:

```json
{
  "reviewer": "<axis-name>",
  "verdict": "APPROVE | CONDITIONAL | REJECT",
  "score": 0-10,
  "blocking_issues": ["<issue1>", "<issue2>"],
  "recommendations": ["<rec1>", "<rec2>"],
  "summary": "<one sentence>"
}
```

## Aggregate Verdict Rules

- **APPROVE:** All 6 reviewers return APPROVE or CONDITIONAL with no blocking issues.
- **CONDITIONAL:** 1-2 reviewers return CONDITIONAL with blocking issues; fixes are scoped and achievable in <1 day.
- **REJECT:** Any reviewer returns REJECT, OR 3+ reviewers return CONDITIONAL, OR any blocking issue is unresolvable without architectural change.

A CONDITIONAL experiment may be re-reviewed after fixes without consuming a loop iteration.
A REJECT experiment is archived to `history/` with its verdict and does not advance to production.
