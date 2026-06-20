# Plan: @bolyra/circuits Package

**Date:** 2026-06-19
**Pipeline:** pdlc-2026-06-19-circuit-artifacts
**Spec:** `docs/superpowers/specs/2026-06-19-circuit-artifacts-design.md`

## Tasks

| # | Task | Size | Type | Depends On |
|---|------|------|------|------------|
| 1 | Create circuits-package/ directory with package.json, tsconfig.json, .npmignore, .gitignore | S | parallel | -- |
| 2 | Create scripts/copy-artifacts.sh (copy, rename, checksum) | S | parallel | -- |
| 3 | Create src/index.ts TypeScript API (getCircuitArtifacts, getArtifactsDir, CIRCUITS, etc.) | M | sequential | 1 |
| 4 | Create test/index.test.ts + README.md | M | sequential | 2, 3 |
| 5 | Run copy-artifacts.sh, build, test, commit with DCO | S | sequential | 4 |

## Execution Notes

- Tasks 1 and 2 are independent and can run in parallel
- Task 3 needs the tsconfig from Task 1
- Task 4 needs both the copy script (to know artifact layout) and the API (to import)
- Task 5 is the verification/commit step
- Groth16-only in v0.1.0 per spec recommendation (PLONK vkeys included for verification)
- artifacts/ is gitignored but included in npm tarball via files array
