---
title: CrewAI Integration
visibility: public
sources:
  - integrations/crewai/README.md
  - integrations/crewai/pyproject.toml
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [crewai, python, sd-jwt, zkp, delegation, multi-agent]
---

Bolyra authentication for CrewAI multi-agent workflows. Adds ZKP mutual auth, scoped delegation, and SD-JWT tools plus a `BolyraGuard` that enforces auth before tool execution.

## Overview

`bolyra-crewai` (v0.2.0, Alpha) provides five components:

| Component | Purpose |
|-----------|---------|
| `BolyraAuthTool` | Mutual ZKP handshake authentication |
| `BolyraDelegateTool` | Scoped ZKP permission delegation |
| `BolyraSDJWTTool` | Lightweight SD-JWT delegation (pure Python) |
| `BolyraGuard` | Pre-execution or post-execution auth enforcement |
| `BolyraSession` | Stateful session chaining auth -> delegate -> SD-JWT |

- **PyPI:** `bolyra-crewai`
- **Python:** >=3.10
- **Deps:** `bolyra>=0.5.0`, `crewai>=0.50.0`, `PyJWT[crypto]>=2.8.0`
- **License:** Apache-2.0

## Key Concepts

- **BolyraGuard:** The key differentiator from the LangChain integration. Two enforcement modes:
  - **Pre-execution (recommended):** `guard.guard_tools([...])` wraps tools so auth is checked before execution.
  - **Post-execution audit:** `step_callback=guard.step_callback` hooks into CrewAI's step callback, fires after each step.
  - Failure modes: `"raise"` (halt), `"warn"` (log), `"skip"` (silently drop).

- **Receipt vaulting:** Raw SD-JWT bearer credentials never appear in tool output (which flows through the LLM context). Only JTI references are returned. This prevents credential leakage through the agent's context window.

- **Scope narrowing:** Delegation enforces one-way narrowing at both the SDK and circuit level. A root agent with `FINANCIAL_UNLIMITED` can delegate down to `FINANCIAL_SMALL`, but never the reverse.

## How It Works

1. Create tools (`BolyraAuthTool`, `BolyraDelegateTool`, `BolyraSDJWTTool`).
2. Create a `BolyraSession` linking the tools.
3. Create a `BolyraGuard` with a failure policy.
4. Wrap tools via `guard.guard_tools(...)` for pre-execution enforcement.
5. Assign wrapped tools to CrewAI `Agent` instances.
6. Build `Crew` and run tasks.

### Security controls

- `BOLYRA_ENV=production` blocks dev-mode auto-generated identities.
- Canonical nonce format: `(unix_seconds << 64) | os.urandom(8)`.
- Every handshake commits to a fresh session nonce; replay requires rebinding.

## Current Status

v0.2.0 on PyPI. 99 tests passing. Three critical and four high security findings fixed in the v0.2.0 release. Per-agent scoping and proof envelope audit trail shipped.

## See Also

- [LangChain](langchain.md) -- same tool set without BolyraGuard
- [OpenAI Agents](openai-agents.md) -- guardrails for the OpenAI Agents SDK
