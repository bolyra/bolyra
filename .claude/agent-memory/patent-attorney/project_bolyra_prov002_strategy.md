---
name: Bolyra PROV-002 Filing Strategy (Sybil v1)
description: Patent strategy for second Bolyra provisional covering pluggable IHumanAttester + provider-scoped nullifier registry; filing target 2026-05-15
type: project
---

Bolyra Sybil-Resistance v1 patent strategy finalized 2026-04-23 against rev 3 of `/Users/lordviswa/.claude/plans/lively-inventing-sonnet.md`.

**Why:** Rev 3 cut scope to humans-only Sybil resistance (agent side deferred to v1.1). Two novel claims survived the cut: (a) pluggable IHumanAttester with registry-side provider-level nullifier scoping and approval-time provider binding, (b) ZK-bridged proof-of-personhood via signal-binding to independent ZK identity tree. Plan calls for new provisional before any Phase A code lands.

**How to apply:**
- File new provisional (NOT CIP to 64/043,898) — cleaner separation, fresh 12-month clock, claim A is architecturally distinct from handshake/delegation in 64/043,898
- Target filing date 2026-05-15
- 3 independent claims (system, method, system-architecture for ZK-bridged PoP), 8 dependents = 11 total
- Closest prior art to address: EAS (pluggable schema/resolver pattern) — distinguish via (1) registry-mediated provider binding at owner-approval, (2) per-(providerId, rawNullifier) deduplication shared across attester contract versions, (3) attester reports only raw uniqueness token (no permission info)
- World ID's signal-binding pattern is the 102 anticipation risk for standalone Claim B; mitigation = fold Claim B as dependent under Claim A and add separate system-architecture independent claim 3 (independent ZK tree gated-not-derived by external PoP)
- Small entity provisional filing fee ~$130 (verify at filing); DIY drafting; ~$300-500 if 1-hour attorney review added
- Phase 0 = file first, no code parallelization. Public-disclosure risk via private-repo leak + on-chain bytecode disclosure outweighs the 2-3 week wait.
- Drop permanently: cross-chain ZK attestation claim, two-phase issuer attestation claim. Preserve: symmetric human/agent claim as future continuation (file separate provisional in 2026-Q4 once v1.1 BabyJub-keyed design locks)
- Docket: BOLYRA-PROV-002
- Title: "Pluggable Attester Registry with Provider-Scoped Uniqueness Enforcement for Zero-Knowledge Identity Systems"
- Draft claim language captured in conversation memo dated 2026-04-23
