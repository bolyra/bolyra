# Dependabot triage 2026-07-22

(previous task — Shield learn mode 2026-07-04 — shipped as PR #65 / 6e38e73 + sdk 0.5.3 fresh-install fix)

- [x] 1. overrides (ws 8.21.0, underscore 1.13.8) in mpp-payments + mandate-demo; regen lockfiles; jest 94/94 + audit exit 0
- [x] 2. body-parser 1.20.6 overrides in 3 example manifests; regen lockfiles (1.20.6 verified ×3)
- [x] 3. dco.yml: per-commit bot exemption ([bot]@users.noreply.github.com) — Codex-approved shell
- [x] 4. SECURITY.md: elliptic bullet += mpp-payments paths; CI-gate prose 4 → 13 dirs
- [x] 5. Codex diff review APPROVE → commit 3a2e6a6 (-s) → PR #83 (direct main push denied by permission gate; branch+PR route). NOTE: --ignore-scripts ci.yml fix was UNCOMMITTED local work from a prior session, shipped here — plan's "already on main" claim was wrong (git log -S footgun).
- [x] 5b. PR #83 merged as 946ef14
- [x] 6. all 8 bot PRs cleared (7 merged, #81 superseded-closed by dependabot)
- [x] 7. residuals closed: 176/180/184 dismissed tolerable_risk; 185/186/189 auto-FIXED by regen
- [x] 8. EXTENDED: post-merge advisory wave (brace-expansion, fast-uri ×2, @hono/node-server ×2, sharp) → PRs #86 (true-clean 21-lockfile refresh), #87 (stale override bumps + cli node>=20), #88 (hono 2.0.10), #89 (fast-uri 3.1.4). Final board: 10 open = apps/wallet next×9 + sharp, deferred to a dedicated Next-upgrade pass (SECURITY.md documented, Codex-ruled). Peak 74 → 10. Lessons ×4 recorded (node_modules resolution anchoring, packument lag, npm ci parity, stale override pins).
