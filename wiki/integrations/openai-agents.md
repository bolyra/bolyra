---
title: OpenAI Agents SDK Integration
visibility: public
sources:
  - integrations/openai-agents/README.md
  - integrations/openai-agents/pyproject.toml
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [openai-agents, python, sd-jwt, guardrail, tool-wrapper, mcp]
---

Bolyra authentication adapter for the OpenAI Agents SDK. Three integration points: coarse-grained guardrail, fine-grained per-tool auth, and MCP server auth injection.

## Overview

`bolyra-agents` (v0.1.0, Alpha) adds Bolyra auth to OpenAI Agents SDK agents via:

| Component | Granularity | Purpose |
|-----------|-------------|---------|
| `BolyraAuthGuardrail` | Entire agent run | `InputGuardrail` that verifies credentials before an agent run starts |
| `BolyraToolWrapper` / `@bolyra_tool` | Per tool call | Checks permissions before each tool invocation |
| `bolyra_mcp_auth` | MCP connection | Wraps MCP server connections to inject Bolyra auth headers |

- **PyPI:** `bolyra-agents`
- **Python:** >=3.10
- **Deps:** `bolyra>=0.4.0`, `openai-agents>=0.1.0`, `PyJWT[crypto]>=2.8.0`
- **License:** Apache-2.0

## Key Concepts

### Auth modes

- **SD-JWT mode:** The agent holds an SD-JWT delegation receipt. On each operation, the adapter presents the receipt with a fresh KB-JWT (holder binding) and verifies locally. Pure Python, no infrastructure.
- **Gateway mode:** The agent has a pre-obtained auth token. The adapter injects `Authorization: Bearer <token>` headers and does a local JWT expiry check.

### Tracing

Auth operations emit custom spans in the OpenAI Agents SDK tracing system:

| Span | Fires on |
|------|----------|
| `bolyra.verify` | Credential verification |
| `bolyra.guardrail` | Guardrail check |
| `bolyra.tool_auth` | Per-tool auth check |
| `bolyra.mcp_auth` | MCP auth injection |

Spans include operation status but never include key material, receipts, or nonces.

## How It Works

**Guardrail path:** Create a `BolyraAuthContext`, wrap it in `BolyraAuthGuardrail`, pass `.as_input_guardrail()` to the `Agent`. If verification fails, the SDK raises `InputGuardrailTripwireTriggered` and halts the agent.

**Per-tool path:** Create a `BolyraToolWrapper` with required permissions, call `wrapper.wrap(tool)` for each sensitive tool. Or use the `@bolyra_tool(ctx, required_permissions=[...])` decorator.

**MCP path:** Wrap an `MCPServerSse` with `bolyra_mcp_auth(server, ctx)` to inject auth headers on every MCP call.

### Dev mode

Set `dev_mode=True` on `BolyraAuthContext` to bypass credential verification during development:

```python
ctx = BolyraAuthContext(mode=AuthMode.SD_JWT, dev_mode=True, agent_id="dev-agent")
```

## Current Status

v0.1.0, Alpha. Published to PyPI. Supports both SD-JWT and gateway auth modes. Includes a TypeScript delegation example (`delegation-example.ts`) alongside the Python package.

## See Also

- [CrewAI](crewai.md) -- `BolyraGuard` for CrewAI multi-agent workflows
- [LangChain](langchain.md) -- `BaseTool` subclasses for LangChain
- [MCP](mcp.md) -- server-side MCP middleware (what `bolyra_mcp_auth` talks to)
