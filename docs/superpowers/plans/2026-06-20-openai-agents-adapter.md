# Plan: OpenAI Agents SDK Adapter (bolyra-agents)

**PDLC:** `pdlc-2026-06-20-openai-agents-adapter`
**Date:** 2026-06-20
**Spec:** `docs/superpowers/specs/2026-06-20-openai-agents-adapter-design.md`

## Tasks

| # | Task | Size | Type | Depends On |
|---|------|------|------|------------|
| 1 | Package scaffolding (pyproject.toml, __init__.py) | S | parallel | -- |
| 2 | Types module (AuthMode, AuthResult, BolyraAgentsConfig) | S | parallel | -- |
| 3 | Tracing module (_tracing.py) | S | parallel | -- |
| 4 | Auth context (BolyraAuthContext) | S | sequential | 2 |
| 5 | Verification logic (_verify.py) | M | sequential | 2, 3, 4 |
| 6 | Guardrail (BolyraAuthGuardrail) | M | sequential | 4, 5 |
| 7 | Tool wrapper (BolyraToolWrapper + bolyra_tool) | M | sequential | 4, 5 |
| 8 | MCP auth wrapper (bolyra_mcp_auth) | M | sequential | 4, 5 |
| 9 | Tests | L | sequential | 6, 7, 8 |
| 10 | README | S | sequential | 6, 7, 8 |

**Parallelization:** Tasks 1, 2, 3 run concurrently. Tasks 6, 7, 8 run concurrently after 5 completes.
**Estimated scope:** 10 tasks, 3 parallelizable in wave 1, 3 in wave 3.
**Test command:** `cd integrations/openai-agents && python3 -m pytest tests/ -v`
