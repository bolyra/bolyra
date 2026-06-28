---
title: ZKP vs RFC 7662 Differentiation
visibility: internal
sources:
  - strategy/zk-vs-rfc7662-differentiation.md
  - differentiation-autoresearch/history/convergence_report.md
  - differentiation-autoresearch/rubric.md
  - differentiation-autoresearch/winners/C7/construction.md
  - differentiation-autoresearch/winners/C2/construction.md
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [strategy, differentiation, zkp, rfc7662, oauth]
---

Bolyra's core strategic question: does ZKP actually beat plain OAuth token introspection (RFC 7662) for agent auth? The answer is yes -- but narrowly, on two properties, not the four originally claimed.

## Overview

RFC 7662 (OAuth 2.0 Token Introspection) is the baseline Bolyra must clear. It provides a simple primitive: agent presents opaque token, RS introspects with AS, AS returns metadata, RS decides. Extensions (JWT introspection response, DPoP, mTLS, RFC 8693 token exchange, RFC 8707 audience binding) significantly strengthen the baseline.

The differentiation-autoresearch loop ran 7 candidates through up to 7 iterations each with 5-persona adversarial scrutiny (rfc7662_advocate, auth0_pm, spiffe_engineer, cryptographer, cu_ciso) under a 5-dimension x 2-point rubric. Two candidates survived.

## Key Findings

### Empirical Scoreboard

| ID | Claim | Seed | Peak | Winner? |
|---|---|---|---|---|
| C7 | Cryptographic model-instance binding | 0 | **9/10** | **Primary** |
| C2 | Cross-scope unlinkability | 9 | **8/10** | **Secondary** |
| C4 | Issuer-blind attribute predicates | 9 | 5/10 | No |
| C1 | Selective scope proof | 4 | 6/10 | No |
| C3 | Delegation audit without exposure | 7 | 6/10 | No |
| C5 | Bolyra as MCP auth, generally | 0 | 5/10 | No |
| C9 | Forward-secure agent delegation | 0 | 5/10 | No |

### Primary Wedge: C7 -- Cryptographic Model-Instance Binding (9/10)

Bolyra binds `(modelHash, operator_pk, permission_bitmask, messageHash)` to each resource server invocation. The verifier learns only the tuple -- not the API key, session token, or runtime secret. Non-malleability + provider anonymity + per-call payload binding all survive adversarial review.

**Why RFC 7662 cannot match:** Signed introspection cannot bind per-call payloads without re-introducing AS participation. DPoP binds to URI, not payload. PPIDs cannot provide provider anonymity. WIMSE/SD-JWT hide attributes from verifiers, not from issuers.

**Load-bearing scenario:** CISO at a regulated deployer must prove to an NCUA examiner that only approved models touched member PII, without revealing which call used which model. Also EU AI Act model provenance and tiered-pricing verification.

**Honest limitation:** Authorization binding, not execution binding. Runtime model substitution requires TEE to close cryptographically. The 9/10 ceiling is structural -- 10/10 requires TEE integration.

### Secondary Wedge: C2 -- AS-Blind Cross-Scope Unlinkability (8/10)

Post-enrollment, the agent generates proofs locally. The AS never sees the per-scope authorization path. OAuth/OIDC structurally requires AS participation at token issuance, so the AS always learns `(agent, RS)`.

**Load-bearing scenario:** Credit union as AS -- GLBA Reg P requires that the CU cannot reconstruct the member's merchant graph.

**What blocks 10/10:** The IND-UNL-AS game formulation needs refinement (scopeId is a public signal). Fixable with focused cryptographic work.

### What Was Dropped

- **C1 (selective scope):** AS-side minimal-scope policy + RFC 8693 approximate it. "Just tweak your AS policy" rebuttal is too easy.
- **C4 (issuer-blind predicates):** Originally rated 9/10; dropped to 5/10 under adversarial scrutiny. Overlaps too heavily with W3C VC + BBS+ selective disclosure.
- **C5 (general MCP auth):** Auth0/WorkOS/Stytch/Cloudflare win the general case.
- **C9 (forward-secure delegation):** Requires epoch-based key-evolution primitives not in scope.

### Why 10/10 Is Unreachable

The rubric has a structural tension: `baseline_dominance` (2/2) requires a claim bold enough that no existing configuration can match, while `adversarial_survival` (2/2) requires every attack to fail. The bold claim creates exactly the surface that personas attack. For C7, the remaining attack is that `modelHash` is a deployment-time authorization label, not a runtime execution measurement. Closing this requires TEE/hardware attestation -- out of scope for pure-ZK.

## Current Status

Differentiation autoresearch completed April 2026. Recommendation: accept the 9/10 ceiling, ship C7 + C2 as the two wedges. Option to pursue C2 -> 9 or 10/10 via IND-UNL-AS game reformulation. TEE integration (C7 -> 10/10) only if a customer pulls.

## See Also

- `strategy/zk-vs-rfc7662-differentiation.md` -- full analysis with RFC 7662 baseline
- `differentiation-autoresearch/history/convergence_report.md` -- loop results and methodology
- `differentiation-autoresearch/winners/C7/` -- winning construction for model-instance binding
- `differentiation-autoresearch/winners/C2/` -- winning construction for unlinkability
- `wiki/strategy/competitive-landscape.md` -- broader competitive context
