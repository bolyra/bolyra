# Bolyra LangChain Integration

Mutual ZKP authentication and delegation tools for LangChain agents.

## Install

```bash
pip install langchain-core pydantic
npm install @bolyra/sdk && npx bolyra setup  # circuit artifacts
```

## Usage

```python
from bolyra.integrations.langchain import BolyraAuthTool, BolyraDelegateTool

auth = BolyraAuthTool(agent_model_hash="gpt-4o", permissions=["read_data"])
result = auth.invoke({"scope": "my-app", "required_permissions": ["read_data"]})

delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])
result = delegate.invoke({"delegatee_id": "0xabc...", "permissions": ["read_data"], "session_nonce": "nonce"})
```

Both tools support async via `ainvoke()`. Currently stubs pending `@bolyra/sdk` v0.2 circuit wiring.
