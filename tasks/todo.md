# Golden-corpus instance vectors — SCOPED, not started (Codex secondary, 2026-08-25)

Spec §4's last row ("golden corpus / conformance: new golden receipts with instance;
negative vectors") is partially satisfied: portable KATs live in
`integrations/receipts/test/fixtures/instance-vectors.json` (3 golden + 23 negative
PREIMAGE vectors) and the verify-cli/CLI paths have executable tests. What's MISSING is
whole-receipt golden fixtures: signed SignedReceipt JSON files (fixed test key) carrying
valid/forged instance blocks, usable by ANY implementation as a conformance corpus —
i.e. the receipts analog of spec/fixtures/host-conformance/. Outline:
- fixtures: valid-instance receipt · forged-ref (signer-issued, signature VALID) ·
  out-of-domain preimage · auth-kind-with-instance · chained log w/ one bad instance
- home: spec/fixtures/receipt-conformance/ + a MANIFEST.json (sha256s), synced pattern
  from evc-conformance's scripts/sync.js
- runner hook: extend conformance-runner.js with --type receipt_binding OR a tiny
  standalone checker; decide when picked up
- effort: ~half-day attended; no release required (test-side only)

# Receipt instance-binding — CORE implementation (Codex-ruled START PARTIAL, 2026-08-24)

Spec of record: `spec/receipt-instance-binding-v1.md` (double-Codex-APPROVED, `229a623`).
Scope ruling: design-proving core in `@bolyra/receipts` ONLY; defer @bolyra/mpp DecisionFacts,
x402 EVC profile wiring, and CLI verify behavior until the core passes its vectors or giskard09's
design read lands. Branch stays draft/internal until then.

## Tasks

- [x] 1. Branch `instance-binding-core` off main
- [x] 2. TESTS FIRST: `test/instance.test.ts` — red run confirmed (module missing), then green
- [x] 3. `src/instance.ts`: types, validateInstancePreimage, computeInstanceRef, verifyInstanceBinding
- [x] 4. `types.ts`: optional `instance?: ReceiptInstanceFields` (commerce-only v1, type-only import cycle)
- [x] 5. Golden + negative vectors: `test/fixtures/instance-vectors.json` (3 golden KATs pinned via
      independent node-crypto computation; 19 out-of-domain vectors)
- [x] 6. Exports; full suite 102→107 green (28 instance tests), tsc --noEmit clean
- [x] 7. Codex loop: round 1 BLOCK (non-object instance block → throw instead of malformed_ref; real
      parsed-JSON hole) → guard + 5 shape tests → round 2 CLEAN (Codex independently recomputed all
      3 golden refs + ran build/tests)
- [x] 8. Committed `493f9e9` on `instance-binding-core` (local draft, NOT pushed)

## Review

Core complete and Codex-clean in one blocking round. The one real finding was the classic
TS-types-vs-parsed-JSON gap: verifyInstanceBinding trusted the ReceiptInstanceFields type and
dereferenced `.ref` on a block that hostile JSON could make null. Fix = object-shape guard before
any dereference, after wrong_kind (order preserved). KATs were computed with node builtin crypto
BEFORE implementation existed, so tests assert against pinned hex, not a mirror of the code.
UNATTENDED BLOCK 2026-08-24 (Codex-directed, founder away): branch rebased onto b488771 and
PUSHED; **DRAFT PR #105 OPEN, 13/13 checks green**. §3.1.1 audience syntax pinned
(^[\x21-\x7E]{1,256}$, IN the verifier domain per Codex ruling) — spec + core + 4 negative
vectors in commit 2b89e19, suite 110/110. PR body Codex-approved after 2 blocking fixes
(tsx reproducibility caveat; vector count 19→23). Disclosure note for #3230 drafted +
Codex-APPROVED, HELD for founder approval (scratchpad/giskard09-disclosure-note-draft.md).
Dependabot sweep DEFERRED (Codex: lower leverage, runtime gate green).

## Wiring phase — state as of 2026-08-25 (Codex Option-C ruling)

**HOLD WINDOW on #105: until 2026-08-26 00:19Z (24h from the disclosure note) or giskard09
responds, whichever first. Then: merge #105 → release @bolyra/receipts 0.10.0 (tag push, TP)
→ bump consumer deps → gated wiring.** Rationale: mpp/cli/payment-protocols consume receipts
from the REGISTRY; 0.9.0 lacks instance.ts, and file:-shortcuts are banned (2026-08-22 lesson).
Branch `instance-binding-wiring` (stacked on core) is pushed with tonight's non-gated work.

- [x] Post the disclosure note to #3230 — POSTED 8/25 00:19Z (5403245411, links #105 per
      Codex Option-B)
- [x] Clock design DECIDED (Codex): optional `nowMs`, exactly-one-clock rule (reject now+nowMs
      both), derive each from the other; existing now injectors → .000Z timestamps
- [x] Wiring lands as a STACKED second PR off instance-binding-core (Codex; #105's public
      core-only contract stays truthful)
- [x] x402 profile requestNonce DOCS (non-gated): profile spec §4.1 + jsdoc + example README —
      `3cb877f`. No code needed profile-side: host already holds context.nonce
- [x] tsx devDep declared in @bolyra/receipts, lockfile regen'd in docker node:20, cold npm ci
      + 110/110 verified — `424443f`
- [x] GATED wiring COMPLETE + **PR #107 MERGED 2026-08-25 06:52Z** (main `a5d9cd2`+`060d765`,
      CI green). Review chain: 4 Codex rounds + bolyra-sdk-guardian BLOCK→fixed (blocking:
      receipts' own verify-cli bin lacked the instance check; also: instance-before-nonce
      ordering, single-sample clock for reservations, program non-empty-ASCII agreement,
      capabilities wording, §4.1 concrete path, README docs)

## Release cohort — SHIPPED 2026-08-25 (Codex-ruled plan, all 4 with provenance)
- [x] Reshape first (Codex ruling): DecisionReceiptFacts + DecisionInstanceFacts +
      instanceFactsFrom; deprecated DecisionFacts alias kept
- [x] `@bolyra/receipts@0.11.0` · `@bolyra/mpp@0.4.0` · `@bolyra/cli@0.9.0` ·
      `@bolyra/payment-protocols@0.8.0` — all published via TP tag-push, attestations
      verified (`npm audit signatures`: 23 verified), CHANGELOG entries incl. retroactive
      receipts 0.10.0
- [x] Post-publish battery: cold install, malformed_receipt smoke, forged-ref CLI smoke
      (nonzero + [ref_mismatch]), `npx bolyra --version` = 0.9.0, TS surface smoke — ALL PASS
- [x] **RELEASE-GATE BUG FOUND+FIXED (`57b4c67`)**: release.yml never installed the
      jest-source-mapped siblings (sdk/mpp src, receipts dist) → test gate failed with
      'Cannot find module ethers'. **This silently killed @bolyra/cli@0.8.0 on 7/24 —
      tagged, never published, registry sat at 0.7.0 unnoticed for a month.** CHANGELOG
      annotates 0.8.0 as never-published. Fix mirrors main-CI sibling prep + cli
      circuit-artifact materialization. Note: the registry-propagation check (30s) can
      false-fail — cli 0.9.0's run "failed" AFTER a successful publish; consider longer
      backoff (follow-up).

---

# x402 EVC authorization-evidence profile — reference integration (90-day plan, Days 0–30 deliverable)

Plan of record: ~/.claude/plans/how-do-i-get-keen-parnas.md (approved 2026-08-22; Codex-agreed).
Goal: the single next action — a narrow, working "optional authorization-evidence profile for x402
payments" that binds EVC evidence to resource/amount/nonce/expires_at/verifier identity, then ONE
question to warm maintainer `phdargen` (extension profile vs app-layer example vs ecosystem package).

Scout findings (2026-08-22): existing `integrations/payment-protocols/src/x402.ts` speaks the raw ZK
handshake, NOT the EVC wire — the profile is net-new and rides the `additionalProperties: true` seam
in EVC §2.2. Reuse: @bolyra/mpp types/evc/classical/nonces + gate/deny/receipts/issue/tiers;
example scaffold from examples/x402-agent-wallet/; two-gates prose in drafts/revettr-two-gates-note.md.

## Tasks

- [x] 1. Profile doc first (small, normative): `spec/x402-evc-profile-v0.md` — how an x402
      PAYMENT-REQUIRED flow carries EVC authorization evidence; new request-extension fields
      `x402: { resource, amount, nonce, expires_at, verifier }` layered via §2.2
      additionalProperties; verdict semantics unchanged (fail-closed, RFC 9457 on deny);
      receipt = gate-1→gate-2 handoff (mirrors revettr two-gates note).
- [x] 2. Bridge module: `integrations/payment-protocols/src/x402-evc.ts` — map
      `X402PaymentRequirements` + request context → EVC `VerifierRequest` (profile fields);
      dispatch via @bolyra/mpp verifier transports (classical | command | url); return
      allow/deny + RFC 9457 body; ES256K decision receipt via @bolyra/receipts. Export from
      `index.ts` barrel. NO changes to existing x402.ts (keep both paths; profile is additive).
- [x] 3. Tests: `integrations/payment-protocols/test/x402-evc.test.ts` — allow within mandate,
      deny over-amount (request_mismatch), deny expired, deny bad binding, nonce replay denied
      (reserve-before-act), verdict-schema fail-closed (hostile fixtures from spec/fixtures/).
      Red-green: write failing tests FIRST (workspace TDD rule).
- [x] 4. Runnable example: `examples/x402-evc-profile/` (scaffold copied from x402-agent-wallet)
      — $25 allow / $500 deny / replay deny, two-gates receipt handoff printed; README with
      scenario table + flow diagram per repo convention.
- [x] 5. Repo hygiene: `cd sdk && npm run typecheck` equivalent for touched packages
      (`tsc --noEmit`), full `npm test` in payment-protocols + mpp-payments; DCO sign-off
      (`git commit -s`); no CODEOWNERS crypto paths touched (verify before commit).
- [x] 6. Codex loop #1 (code): review bridge + tests + example; fix; re-pass until clean APPROVE.
- [x] 7. Codex loop #2 (words): the design-note + the upstream issue text for x402-foundation/x402
      asking phdargen the ONE question ("extension profile, app-layer example, or ecosystem
      package?"). Boundary rule: the WHY/spec, never the hosted-system build plan.
- [x] 8. FOUNDER ACTIONS (never automated): push branch + open the upstream issue + ping phdargen.
      Then: update bolyra-engagement-graph.md (new node state) + re-publish artifact; add
      MEMORY.md checkpoint line.

## Review / results

(fill in as tasks complete)

## Review / results (2026-08-22)

- Built: spec/x402-evc-profile-v0.md · src/x402-evc.ts (payment-protocols) · 15 profile tests
  (132/132 package total) · examples/x402-evc-profile (demo PASS) · barrel + deps + jest mapping.
- Codex code loop: REVISE (4 findings: default-store replay bug, payee/audience gap, x402 v2
  vocabulary, resource-binding overclaim) -> all fixed -> REVISE (nonce-store throw escaped
  fail-closed) -> fixed + 2 tests -> APPROVE.
- Codex words loop: issue draft APPROVE first pass (drafts/x402-evc-profile-issue.md).
  Non-blocker noted: demo uses 'base-sepolia'; v2 spec prefers CAIP-2 (eip155:84532) - fine to
  address if a maintainer asks.
- Remaining = task 8, FOUNDER: commit -s, push, open the issue (drop the draft's preamble),
  ping phdargen; then engagement-graph update + artifact re-publish.
- SENT 2026-08-22 (founder-delegated): commit 905b6ad pushed to main (DCO, canonical author,
  docker-regenerated lockfile), links verified live, issue OPENED:
  https://github.com/x402-foundation/x402/issues/3230 · engagement graph updated · artifact
  re-publish PENDING (visual one update behind).
