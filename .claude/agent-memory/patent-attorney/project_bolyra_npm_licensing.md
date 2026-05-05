---
name: Bolyra npm licensing decision (sdk + mcp)
description: License/patent grant scheme decided 2026-04-25 for @bolyra/sdk and @bolyra/mcp ahead of @bolyra/mcp@0.1.0 publication
type: project
---

# Bolyra npm Licensing Decision — 2026-04-25

**Decision: Apache License 2.0 for both `@bolyra/sdk` and `@bolyra/mcp` (identical license).**

Why: MIT lacks express patent grant; implied license under Jacobsen v. Katzer is contested.
Apache 2.0 § 3 provides express RF perpetual patent grant + defensive termination.
LF/CNCF/IETF default — Anthropic/Google/Microsoft/Cursor legal teams pre-cleared.
Same license on both packages because mcp depends on sdk and patent reads on both.

How to apply:
- Both package.json: "license": "Apache-2.0"
- LICENSE file = canonical Apache 2.0 text, unmodified
- NOTICE file (Apache § 4(d)) identifies Provisional 64/043,898 + future continuations/CIPs/foreign counterparts as patents licensed under § 3
- NOTICE includes IETF RF intent-to-declare (not yet binding) and trademark carve-out
- NO separate PATENTS file — that was the React mistake; modifications to § 3 trigger interpretive conflicts
- CONTRIBUTING.md uses DCO v1.1 (Signed-off-by), NOT a CLA — DCO matches Linux/Kubernetes posture, minimizes friction for drive-by contributors
- DCO enforced via tim-actions/dco@v1.1.0 GitHub Action

## Trademark
- File USPTO TEAS Plus 1(b) ITU for BOLYRA, Classes 9 + 42, ~$500 self-filed
- Plus $200 Statement of Use later
- "Bolyra" is fanciful (Abercrombie ★★★★★), inherently distinctive
- TRADEMARKS.md at repo root with nominative-fair-use + no-fork-naming policy

## Defensive publication strategy (paired with publish)
- Publish defensive disclosure to IP.com (~$200) AND Technical Disclosure Commons (free) on same day as @bolyra/mcp@0.1.0
- Disclosure is broader than provisional: includes alt proving systems (Plonk, Halo2), alt hashes (Rescue, MiMC), alt curves (BLS12-381), alt scope serializations — kills picket fence
- Repo includes BOLYRA-PROTOCOL.md spec (git-attested publication date)
- Do NOT publish claim chart in README — Phillips v. AWH risk of intrinsic-evidence narrowing
- Single sentence on bolyra.ai/patents page: "Pending US 64/043,898; non-provisional by 2027-04-20" — § 287(a) marking presumption
- Consider Track One Prioritized Examination ($2,000 small entity) for non-provisional if competitor moves
- File continuation immediately on non-provisional grant; keep one continuation pending always

## Pre-publish blocking checklist (19 items)
See conversation 2026-04-25 for full ordered checklist. Critical items:
1. TM knockout search
2. File ITU TM application
3. Update both package.json to Apache-2.0
4. LICENSE + NOTICE in both packages, listed in package.json "files" array
5. TRADEMARKS.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, BOLYRA-PROTOCOL.md at repo root
6. SPDX-License-Identifier headers on every source file
7. license-checker audit — no GPL/AGPL/LGPL deps allowed
8. IP.com defensive disclosure published same day
9. npm publish sdk first, then mcp

## Items needing outside counsel before action
- TM clearance opinion ($300-600) — optional for coined mark but recommended
- § 102/103 self-estoppel opinion before publishing BOLYRA-PROTOCOL.md picket-fence ($1,500-3,000)
- IETF IPR disclosure form review at I-D submission
- Non-provisional drafting (already planned, deadline 2027-04-20)
