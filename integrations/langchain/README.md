# Bolyra LangChain Integration

> **Status: Working** — Requires Node.js >= 18 and `@bolyra/sdk` installed. Uses the Python SDK's subprocess bridge for ZKP proof generation.

Mutual ZKP authentication and delegation tools for LangChain agents.

## Install

```bash
pip install langchain-core pydantic
npm install @bolyra/sdk && npx bolyra setup  # circuit artifacts
```

## Usage

```python
from bolyra.integrations.langchain import BolyraAuthTool, BolyraDelegateTool

# Dev mode (uses fixed-seed dev identities -- never for production):
auth = BolyraAuthTool()
result = auth.invoke({"scope": "my-app", "required_permissions": ["read_data"]})

# Production mode:
auth = BolyraAuthTool(
    agent_model_hash="gpt-4o",
    operator_key="0xdeadbeef...",
    permissions=["read_data", "write_data"],
    human_secret=12345,
)
result = auth.invoke({"scope": "my-app", "required_permissions": ["read_data"]})

# Delegation (after successful handshake):
delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])
result = delegate.invoke({
    "delegatee_id": "0xabc...",
    "permissions": ["read_data"],
    "session_nonce": "nonce-from-handshake",
    "scope_commitment": "commitment-from-handshake",
})
```

Both tools support async via `ainvoke()`. Errors from missing Node.js or SDK are returned as structured dicts (never crash the LangChain agent).

## Non-Monorepo Setup

If you installed `bolyra` from PyPI (not from the monorepo checkout), the
Python SDK needs to know where the Node.js `@bolyra/sdk` package lives.
Set **one** of:

```bash
# Option 1: environment variable
export BOLYRA_NODE_SDK_PATH=/path/to/node_modules/@bolyra/sdk

# Option 2: pass via BolyraConfig
from bolyra.types import BolyraConfig

config = BolyraConfig(node_sdk_path="/path/to/node_modules/@bolyra/sdk")
```

Inside the monorepo, the SDK auto-discovers `../sdk` relative to the Python
package and no configuration is needed.
