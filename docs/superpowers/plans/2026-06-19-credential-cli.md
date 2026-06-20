# Plan: @bolyra/cli — Credential Management CLI

**Date:** 2026-06-19
**Spec:** `docs/superpowers/specs/2026-06-19-credential-cli-design.md`
**Pipeline:** pdlc-2026-06-19-credential-cli

## Tasks

| # | Task | Size | Type | Depends On |
|---|------|------|------|------------|
| 1 | Package scaffolding (package.json, tsconfig, jest.config) | S | parallel | -- |
| 2 | Shared utilities: parse.ts + format.ts + store.ts | M | parallel | -- |
| 3 | CLI entry point (main.ts) + command routing | S | sequential | 1, 2 |
| 4 | Credential commands (cred create/inspect/revoke/list) | L | sequential | 2, 3 |
| 5 | Key commands (key generate/show) | S | sequential | 2, 3 |
| 6 | Receipt verify + dev commands | S | sequential | 2, 3 |
| 7 | Tests for all modules | L | sequential | 3, 4, 5, 6 |
| 8 | README.md with usage examples | S | sequential | 4, 5, 6 |

**Parallelization:** Tasks 1, 2 run concurrently. Tasks 4, 5, 6, 8 can run concurrently after task 3. Task 7 waits for all implementation.
**Estimated scope:** 8 tasks, 2 parallelizable in first wave.

## Constraints

- Node 18+ (built-in parseArgs, no commander/yargs)
- Zero external deps beyond @bolyra/sdk and @bolyra/receipts
- Duration string parsing (30d, 1y, 24h)
- Private key files 0o600
- BigInt serialization as decimal strings
- DCO sign-off on all commits
