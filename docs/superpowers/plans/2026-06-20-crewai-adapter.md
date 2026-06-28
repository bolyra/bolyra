# Plan: CrewAI Adapter for Bolyra

**PDLC ID:** pdlc-2026-06-20-crewai-adapter
**Date:** 2026-06-20
**Spec:** `docs/superpowers/specs/2026-06-20-crewai-adapter-design.md`

## Tasks

| # | Task | Size | Type | Depends On |
|---|------|------|------|------------|
| 1 | Remove old stub files | S | parallel | -- |
| 2 | Package scaffolding (pyproject.toml, LICENSE, NOTICE) | S | parallel | -- |
| 3 | Core modules (_compat, types, auth_tool, delegate_tool, sd_jwt_tool, guard, session, __init__) | L | sequential | 1 |
| 4 | Tests (conftest, test_auth, test_delegate, test_sd_jwt, test_guard, test_session, test_types) | L | sequential | 3 |
| 5 | README.md | S | sequential | 3 |
| 6 | Run tests, fix issues, commit | M | sequential | 4, 5 |

## Parallelization

Tasks 1, 2 run concurrently. Task 3 waits for 1. Tasks 4, 5 wait for 3. Task 6 waits for 4, 5.

## Estimated Scope

6 tasks, 2 parallelizable. ~15 new files.
