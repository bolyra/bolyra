---
title: LangChain Integration
visibility: public
sources:
  - integrations/langchain/README.md
  - integrations/langchain/pyproject.toml
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [langchain, python, sd-jwt, zkp, delegation]
---

LangChain tools for Bolyra mutual ZKP authentication and SD-JWT delegation. Three `BaseTool` subclasses that plug into `create_react_agent`, `AgentExecutor`, LCEL chains, and LangGraph.

## Overview

`bolyra-langchain` (v0.1.0, Alpha) provides three tools:

| Tool | Auth path | Requires Node.js | Purpose |
|------|-----------|-------------------|---------|
| `BolyraAuthTool` | ZKP | Yes | Mutual ZKP handshake authentication |
| `BolyraDelegateTool` | ZKP | Yes | Scoped ZKP permission delegation |
| `BolyraSDJWTTool` | SD-JWT | No | Lightweight SD-JWT delegation |

- **PyPI:** `bolyra-langchain`
- **Python:** >=3.11
- **Deps:** `bolyra>=0.5.0`, `langchain-core>=0.2.0`, `PyJWT[crypto]>=2.8.0`
- **License:** Apache-2.0

## Key Concepts

- **Two auth paths:** ZKP tools (`BolyraAuthTool`, `BolyraDelegateTool`) run Groth16 proofs via a Node.js subprocess bridge. `BolyraSDJWTTool` is pure Python -- no Node.js, no circuit artifacts.
- **Dev mode:** When no keys are provided, tools auto-generate test credentials. `BolyraAuthTool` uses fixed-seed dev identities; `BolyraSDJWTTool` generates fresh Ed25519 keypairs per instance. Never for production.
- **BolyraSession:** Stateful session object that chains authenticate -> delegate -> SD-JWT flows, auto-injecting `session_nonce` and `scope_commitment` between steps.

## How It Works

1. Create tool instances with permissions and (optionally) operator keys.
2. Add tools to a LangChain agent via `create_react_agent` or LCEL.
3. The agent invokes tools as needed; each tool runs a ZKP handshake or SD-JWT flow and returns structured auth results.
4. Use `BolyraSession` to chain auth -> delegation without manually passing nonces.

### Non-monorepo setup

For standalone PyPI installs, point to the Node.js SDK:

```bash
export BOLYRA_NODE_SDK_PATH=/path/to/node_modules/@bolyra/sdk
```

### Source layout

```
integrations/langchain/
  bolyra_langchain/
    auth_tool.py       # BolyraAuthTool(BaseTool)
    delegate_tool.py   # BolyraDelegateTool(BaseTool)
    sd_jwt_tool.py     # BolyraSDJWTTool(BaseTool)
    session.py         # BolyraSession
    types.py           # AuthResult, DelegationResult, SDJWTResult
    _compat.py         # LangChain version shims
```

The SD-JWT module itself lives in the core Python SDK at `sdk-python/bolyra/sd_jwt.py` and is shared with the CrewAI integration.

## Current Status

v0.1.0, Alpha. Published to PyPI. All three tools work in dev mode. Production mode requires explicit operator keys and Node.js for ZKP tools.

## See Also

- [CrewAI](crewai.md) -- similar tool set with `BolyraGuard` enforcement
- [OpenAI Agents](openai-agents.md) -- guardrails + tool wrappers for the OpenAI Agents SDK
