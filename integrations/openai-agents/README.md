# bolyra-agents -- Bolyra Auth for OpenAI Agents SDK

Python package that adds Bolyra authentication to [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) agents via three integration points:

1. **BolyraAuthGuardrail** -- coarse-grained InputGuardrail that verifies credentials before an agent run starts
2. **BolyraToolWrapper** / **bolyra_tool** -- fine-grained per-tool auth that checks permissions before each tool invocation
3. **bolyra_mcp_auth** -- wraps MCP server connections to inject Bolyra auth headers

Supports two auth paths:
- **SD-JWT mode** -- pure Python credential verification via `bolyra.sd_jwt` (no infrastructure needed)
- **Gateway mode** -- HTTP header injection with a pre-obtained token

## Install

```bash
pip install bolyra-agents
```

Dependencies: `openai-agents>=0.1.0`, `bolyra>=0.4.0`, `PyJWT[crypto]>=2.8.0`

## Quick Start

### 1. Guardrail (coarse-grained: entire agent run)

```python
from agents import Agent, Runner
from bolyra_agents import BolyraAuthGuardrail, BolyraAuthContext, AuthMode

ctx = BolyraAuthContext(
    mode=AuthMode.SD_JWT,
    receipt=receipt,
    holder_private_key=agent_key,
    issuer_public_key=operator_pub,
)
guardrail = BolyraAuthGuardrail(auth_context=ctx)
agent = Agent(
    name="my-agent",
    instructions="You are a helpful assistant.",
    input_guardrails=[guardrail.as_input_guardrail()],
)
result = await Runner.run(agent, "Hello")
```

If verification fails, the SDK raises `InputGuardrailTripwireTriggered` and halts the agent.

### 2. Per-tool auth (fine-grained: per tool call)

```python
from agents import Agent, function_tool
from bolyra_agents import BolyraToolWrapper, BolyraAuthContext, AuthMode

ctx = BolyraAuthContext(
    mode=AuthMode.SD_JWT,
    receipt=receipt,
    holder_private_key=agent_key,
    issuer_public_key=operator_pub,
)

# Class-based wrapping
wrapper = BolyraToolWrapper(
    auth_context=ctx,
    required_permissions=["FINANCIAL_SMALL"],
    required_action="purchase",
)

@function_tool
def purchase_item(sku: str, amount: float) -> str:
    return f"Purchased {sku} for ${amount}"

agent = Agent(
    name="shopping-agent",
    tools=[wrapper.wrap(purchase_item), search_tool],  # only purchase needs auth
)
```

Or use the decorator:

```python
from bolyra_agents import bolyra_tool

@bolyra_tool(ctx, required_permissions=["WRITE_DATA"])
@function_tool
def write_data(content: str) -> str:
    return f"Wrote: {content}"
```

### 3. MCP gateway auth

```python
from agents.mcp import MCPServerSse
from bolyra_agents import bolyra_mcp_auth, BolyraAuthContext, AuthMode

server = MCPServerSse(params={"url": "https://my-server.com/sse"})
authed = bolyra_mcp_auth(server, BolyraAuthContext(
    mode=AuthMode.GATEWAY,
    gateway_token="eyJ...",
))
agent = Agent(name="mcp-agent", mcp_servers=[authed])
```

## Auth Modes

### SD-JWT Mode

The agent holds an SD-JWT delegation receipt issued by a human/operator. On each operation, the adapter presents the receipt with a fresh KB-JWT (holder binding) and verifies it locally. Pure Python, no infrastructure needed.

```python
ctx = BolyraAuthContext(
    mode=AuthMode.SD_JWT,
    receipt=receipt,              # Issuer-form SD-JWT (from bolyra.sd_jwt.allow())
    holder_private_key=agent_key, # Agent's Ed25519 private key
    issuer_public_key=issuer_pub, # Issuer's Ed25519 public key
)
```

### Gateway Mode

The agent has a pre-obtained auth token. The adapter injects `Authorization: Bearer <token>` headers and does a local JWT expiry check.

```python
ctx = BolyraAuthContext(
    mode=AuthMode.GATEWAY,
    gateway_token="eyJ...",       # Pre-obtained JWT
)
```

## Permissions

The adapter supports Bolyra's 8-bit cumulative permission model:

| Permission | Implies |
|-----------|---------|
| READ_DATA | -- |
| WRITE_DATA | -- |
| FINANCIAL_SMALL | -- |
| FINANCIAL_MEDIUM | FINANCIAL_SMALL |
| FINANCIAL_UNLIMITED | FINANCIAL_SMALL, FINANCIAL_MEDIUM |
| SIGN_ON_BEHALF | -- |
| SUB_DELEGATE | -- |
| ACCESS_PII | -- |

## Dev Mode

For development and testing, set `dev_mode=True` to bypass credential verification:

```python
ctx = BolyraAuthContext(
    mode=AuthMode.SD_JWT,
    dev_mode=True,
    agent_id="dev-agent",
)
```

## Tracing

Auth operations emit custom spans in the OpenAI Agents SDK tracing system:
- `bolyra.verify` -- credential verification
- `bolyra.guardrail` -- guardrail check
- `bolyra.tool_auth` -- per-tool auth check
- `bolyra.mcp_auth` -- MCP auth injection

Spans include operation status but never include key material, receipts, or nonces.

## Testing

```bash
cd integrations/openai-agents
python3 -m pytest tests/ -v
```

## TypeScript Example

The existing `delegation-example.ts` shows the TypeScript delegation pattern. This Python package is the full-featured adapter.

## License

Apache-2.0
