# 0.6.0 conformance/spec pre-build (Codex-picked 2026-08-26)

Branch: `conformance-0.6.0-registry-closure` — BUILT, held unreleased until
khandrew1/mcp-use-evc-example is harness-green on 0.5.0 (Codex T3 ruling).

- [x] 1. Map harness structure (fixtures/host-conformance, test-vectors.json,
      runner expectation checks, evc-conformance vendor sync via scripts/sync.js)
- [x] 2. Both reference hosts enforce the §9 registry (JS KNOWN_CODES;
      reference-host-rs lib.rs:445) — both pass the new vector
- [x] 3. Test-first: `host-deny-unknown-denial-code` fixture + vector.
      Reference JS host 28/28 · Rust host 28/28 · khandrew1's patched adapter
      FAILS exactly this vector (relays `quantum_flux_error`) — gap proven real
- [x] 4. Spec prose: §7.2 classification precedence (own kills → signal →
      nonzero exit → parse/schema; signal_death vs nonzero_exit must not
      collapse) · §9 closed-registry reconciliation (unknown code = host
      schema_invalid fail-closed, never a relayed verdict)
- [x] 5. Vector set 0.5.0 → 0.6.0 (111→112 vectors) · evc-conformance package
      0.1.0 → 0.2.0 · vendor sync + MANIFEST regenerated (sync:check OK) ·
      CHANGELOG entry marked UNRELEASED with the hold condition
- [x] 6. Full suite delta check: main baseline 89/10 FAIL/12 SKIP (pre-existing
      env: cli + receipts builds missing locally) · branch 90/10/12 — exactly
      +1 pass, no regressions. No hardcoded 111/0.5.0 references anywhere.

## Review

Codex verdict: APPROVE (after 2 REVISE rounds — doc currency: spec header/§15/
§16.1/§10 pseudocode, stale 27/104 counts in 6 files, CHANGELOG heading,
draft-00 handling). Full suite regenerated green from a fully-built env
(receipts + cli): CONFORMANCE.md now 0.6.0, 112 vectors, 107/0/5.

Design finding worth remembering: §9's old sentence ("MUST treat an
unrecognized future code as deny") was the exact text that licensed
khandrew1's relay behavior — the fix reconciles prose with §3.4's enum
closure; wire contract unchanged. draft-kondoju-evc-00.md is frozen archival
(datatracker mirror, comment blocks accidental rebuilds); the -01 outline
carries both changes with RFC 7942 implementation-status evidence.

Release is a single tag-push once khandrew1/mcp-use-evc-example is green on
0.5.0; do NOT tag before.
