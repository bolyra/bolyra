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
