# Bolyra LangChain Integration

LangChain tools for Bolyra mutual ZKP authentication and SD-JWT delegation.

**Status:** Alpha / Developer preview. Three tools as proper `BaseTool` subclasses.

## Install

```bash
pip install bolyra-langchain
```

For ZKP-based auth (BolyraAuthTool, BolyraDelegateTool), also install:

```bash
npm install @bolyra/sdk && npx bolyra setup  # circuit artifacts
```

SD-JWT auth (BolyraSDJWTTool) requires no Node.js.

## Quick Start

### SD-JWT Delegation (No ZKP, No Node.js)

```python
from bolyra_langchain import BolyraSDJWTTool
from langchain.agents import create_react_agent, AgentExecutor

# Dev mode -- auto-generates test credentials
sd_jwt_tool = BolyraSDJWTTool()

# Use in a LangChain agent
tools = [sd_jwt_tool]
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

result = executor.invoke({"input": "Authorize a $50 purchase at shop.example.com"})
```

### ZKP Mutual Authentication

```python
from bolyra_langchain import BolyraAuthTool

# Dev mode (fixed-seed dev identities -- never for production)
auth_tool = BolyraAuthTool()

# Production mode
auth_tool = BolyraAuthTool(
    agent_model_hash="gpt-4o",
    operator_key="0xdeadbeef...",
    permissions=["read_data", "write_data"],
    human_secret=12345,
)

result = auth_tool.invoke({
    "scope": "my-app",
    "required_permissions": ["read_data"],
})
```

### ZKP Delegation

```python
from bolyra_langchain import BolyraDelegateTool

delegate = BolyraDelegateTool(
    agent_permissions=["read_data", "write_data", "financial_small"],
)

result = delegate.invoke({
    "delegatee_id": "0xabc123...",
    "permissions": ["read_data"],
    "session_nonce": "nonce-from-handshake",
    "scope_commitment": "commitment-from-handshake",
})
```

### Session-Managed Chain

```python
from bolyra_langchain import BolyraAuthTool, BolyraDelegateTool, BolyraSession

auth = BolyraAuthTool(permissions=["read_data", "write_data"])
delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])
session = BolyraSession(auth_tool=auth, delegate_tool=delegate)

# Authenticate first
auth_result = session.authenticate(scope="my-app")

# Delegate -- session_nonce and scope_commitment auto-injected
del_result = session.delegate(
    delegatee_id="0xabc...",
    permissions=["read_data"],
)
```

## Tools

| Tool | Path | Requires Node.js | Description |
|------|------|-------------------|-------------|
| `BolyraAuthTool` | ZKP | Yes | Mutual ZKP handshake authentication |
| `BolyraDelegateTool` | ZKP | Yes | Scoped ZKP permission delegation |
| `BolyraSDJWTTool` | SD-JWT | No | Lightweight SD-JWT delegation |

All tools subclass `langchain_core.tools.BaseTool` and work with `create_react_agent`, `AgentExecutor`, LCEL chains, and LangGraph.

## Dev Mode

When no keys are provided, tools auto-generate test credentials:
- `BolyraAuthTool`: uses fixed-seed dev identities (deterministic)
- `BolyraSDJWTTool`: generates fresh Ed25519 keypairs per instance

Dev mode is never for production. In production, provide explicit operator keys, human secrets, or issuer keys.

## Non-Monorepo Setup

If using `bolyra` from PyPI (not the monorepo), set the Node.js SDK path:

```bash
export BOLYRA_NODE_SDK_PATH=/path/to/node_modules/@bolyra/sdk
```

Or via config:

```python
from bolyra.types import BolyraConfig
config = BolyraConfig(node_sdk_path="/path/to/node_modules/@bolyra/sdk")
```

## Architecture

```
integrations/langchain/
  pyproject.toml              # bolyra-langchain package
  README.md
  bolyra_langchain/
    __init__.py               # Public API
    auth_tool.py              # BolyraAuthTool(BaseTool)
    delegate_tool.py          # BolyraDelegateTool(BaseTool)
    sd_jwt_tool.py            # BolyraSDJWTTool(BaseTool)
    session.py                # BolyraSession
    types.py                  # AuthResult, DelegationResult, SDJWTResult
    _compat.py                # LangChain version shims
  tests/
    test_auth_tool.py
    test_delegate_tool.py
    test_sd_jwt_tool.py
    test_session.py
```

The SD-JWT module lives in the core `bolyra` SDK at `sdk-python/bolyra/sd_jwt.py` and is re-used by both the LangChain and CrewAI integrations.
