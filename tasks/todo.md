# Reviewer evidence report (founder override 2026-10-10; 8h cap)

Spec: docs/superpowers/specs/2026-10-10-reviewer-evidence-report-design.md

- [ ] 0. Codex plan review → APPROVE
- [ ] 1. fixture: committed dry-run bundle under test/report-fixtures/dry-run
- [ ] 2. classify.test RED → src/report/classify.ts GREEN (clean, tampered, truncated, unlinked, wrong signer)
- [ ] 3. render.test RED → src/report/render.ts GREEN
- [ ] 4. cli.test RED → src/report/cli.ts GREEN; `npm run report` script
- [ ] 5. README section, CI job step, CHANGELOG
- [ ] 6. full suite in node:20 container; Codex code review → clean; DCO; PR; CI green
