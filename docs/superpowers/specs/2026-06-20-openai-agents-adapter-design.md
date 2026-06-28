# OpenAI Agents SDK Adapter for Bolyra -- Design Spec

**PDLC:** `pdlc-2026-06-20-openai-agents-adapter`
**Date:** 2026-06-20
**Status:** Draft

---

## 1. Problem

The existing `integrations/openai-agents/` directory contains only a TypeScript delegation example (`delegation-example.ts`) with mock Agent SDK types. There is no Python package, no guardrail integration, and no way for OpenAI Agents SDK users to add Bolyra auth to their agents.

The OpenAI Agents SDK (Python: `openai-agents` on PyPI) provides first-class extension points that map naturally to Bolyra's auth surface:

- **Guardrails** (`InputGuardrail`, `OutputGuardrail`): intercept agent runs before/after execution. Perfect for credential verification.
- **Tool wrapping**: tools are `FunctionTool` or `@function_tool` decorated callables. Wrapping them with auth checks is idiomatic.
- **MCP support**: `MCPServerStdio` and `MCPServerSse` connect agents to MCP servers. Adding auth headers to the MCP connection is the gateway path.
- **Tracing**: built-in tracing system with custom spans. Auth events should appear in traces.

## 2. Goals

1. **`BolyraAuthGuardrail`** -- an `InputGuardrail` that verifies agent credentials (SD-JWT or gateway token) before any tool execution begins. If verification fails, the agent run is halted with a `GuardrailTripwireTriggered` exception.
2. **`BolyraToolWrapper`** -- wraps existing tools to inject Bolyra auth verification per-tool-call. Finer-grained than the guardrail: different tools can require different permissions.
3. **`bolyra_mcp_auth()`** -- wraps an `MCPServerStdio` or `MCPServerSse` to inject Bolyra auth headers on every request. This is the gateway path.
4. **Tracing integration** -- auth events (verify start, verify pass/fail, guardrail trip) emit custom spans in the OpenAI Agents tracing system.
5. **Dual auth paths** -- SD-JWT delegation (pure Python, via `bolyra.sd_jwt`) and gateway (HTTP header injection with a pre-obtained token).
6. **Installable package** -- `pip install bolyra-agents` with `openai-agents` and `bolyra` as dependencies.

## 3. Non-Goals

- ZKP proving from within the adapter (ZKP stays in the core SDK's subprocess bridge)
- TypeScript version (the existing TS example stays; a full TS adapter would be a separate pipeline)
- Custom Agent subclass (we use the SDK's extension points, not inheritance)
- OpenAI Agents SDK internals modification (we only use public API)

## 4. Architecture

### 4.1 Package Structure

```
integrations/openai-agents/
  pyproject.toml              # bolyra-agents package
  README.md                   # Updated with Python examples
  delegation-example.ts       # Preserved (existing TS example)
  bolyra_agents/
    __init__.py               # Public API exports
    guardrail.py              # BolyraAuthGuardrail (InputGuardrail)
    tool_wrapper.py           # BolyraToolWrapper
    mcp_auth.py               # bolyra_mcp_auth()
    auth_context.py           # BolyraAuthContext (shared auth state)
    types.py                  # AuthMode, AuthResult, BolyraAgentConfig
    _tracing.py               # Custom tracing spans
    _verify.py                # Shared verification logic (SD-JWT + gateway)
  tests/
    __init__.py
    conftest.py               # Shared fixtures (keypairs, receipts)
    test_guardrail.py
    test_tool_wrapper.py
    test_mcp_auth.py
    test_auth_context.py
    test_verify.py
    test_tracing.py
  examples/
    basic_guardrail.py        # Agent with BolyraAuthGuardrail
    per_tool_auth.py          # Different permissions per tool
    mcp_gateway.py            # MCP server with gateway auth
```

### 4.2 Dependency Graph

```
bolyra-agents
  -> openai-agents (>=0.1.0, peer dependency)
  -> bolyra (>=0.4.0, for SD-JWT types and verification)
```

The `openai-agents` package pulls in `openai` and `pydantic`. The `bolyra` package pulls in `PyJWT[crypto]`. No additional direct dependencies needed.

### 4.3 Auth Modes

The adapter supports two auth modes, matching Bolyra's dual-path architecture:

#### SD-JWT Mode (Pure Python, No Infrastructure)

The agent holds an SD-JWT delegation receipt issued by a human/operator. On each tool call or agent run, the adapter:
1. Presents the receipt with a fresh KB-JWT (holder binding)
2. Verifies the presented receipt against expected audience/action
3. Checks permission claims against required permissions

This uses `bolyra.sd_jwt.present()` and `bolyra.sd_jwt.verify()` -- pure Python, no Node.js, no gateway.

#### Gateway Mode (HTTP Headers)

The agent has a pre-obtained auth token (e.g., from a Bolyra gateway). On each tool call or MCP request, the adapter injects an `Authorization: Bearer <token>` header. The gateway handles verification.

This is simpler but requires running infrastructure (the Bolyra auth gateway).

### 4.4 Core Components

#### 4.4.1 BolyraAuthContext

Shared auth state that the guardrail, tool wrapper, and MCP auth all read from:

```python
@dataclass
class BolyraAuthContext:
    """Holds auth state for a Bolyra-authenticated agent."""

    mode: AuthMode  # SD_JWT or GATEWAY

    # SD-JWT mode
    receipt: str | None = None              # Issuer-form SD-JWT
    holder_private_key: Ed25519PrivateKey | None = None
    issuer_public_key: Ed25519PublicKey | None = None

    # Gateway mode
    gateway_token: str | None = None
    gateway_url: str | None = None

    # Shared
    agent_id: str = "default-agent"
    default_audience: str = "bolyra-agents"
    required_permissions: list[str] = field(default_factory=lambda: ["READ_DATA"])
```

#### 4.4.2 BolyraAuthGuardrail

An `InputGuardrail` that runs before the agent processes any input. This is the coarse-grained auth check -- "is this agent allowed to run at all?"

```python
from agents import InputGuardrail, InputGuardrailTripwireTriggered, RunContextWrapper

class BolyraAuthGuardrail(InputGuardrail):
    """Verifies Bolyra credentials before agent execution.

    Usage:
        ctx = BolyraAuthContext(mode=AuthMode.SD_JWT, receipt=receipt, ...)
        guardrail = BolyraAuthGuardrail(auth_context=ctx)
        agent = Agent(
            name="my-agent",
            input_guardrails=[guardrail],
        )
    """

    def __init__(self, auth_context: BolyraAuthContext):
        super().__init__(guardrail_function=self._check_auth)
        self.auth_context = auth_context

    async def _check_auth(
        self,
        ctx: RunContextWrapper,
        agent: Agent,
        input: str | list,
    ) -> GuardrailFunctionOutput:
        # Verify credentials based on mode
        result = await verify_credentials(self.auth_context)
        if not result.ok:
            return GuardrailFunctionOutput(
                output_info=GuardrailResult(tripwire_triggered=True),
                tripwire_triggered=True,
            )
        # Store verification result in run context for downstream use
        ctx.context["bolyra_auth"] = result
        return GuardrailFunctionOutput(
            output_info=GuardrailResult(tripwire_triggered=False),
            tripwire_triggered=False,
        )
```

Key design choice: the guardrail stores the verification result in the `RunContext` so downstream tools can access it without re-verifying.

#### 4.4.3 BolyraToolWrapper

Wraps individual tools with per-tool permission checks:

```python
def bolyra_tool(
    auth_context: BolyraAuthContext,
    required_permissions: list[str] | None = None,
    required_action: str | None = None,
    audience: str | None = None,
):
    """Decorator that wraps a @function_tool with Bolyra auth verification.

    Usage:
        @bolyra_tool(ctx, required_permissions=["FINANCIAL_SMALL"], required_action="purchase")
        @function_tool
        def purchase_item(sku: str, amount: float) -> str:
            return f"Purchased {sku} for ${amount}"
    """
```

And the class-based wrapper for non-decorator usage:

```python
class BolyraToolWrapper:
    """Wraps an existing tool with Bolyra auth verification.

    Usage:
        wrapper = BolyraToolWrapper(auth_context=ctx, required_permissions=["WRITE_DATA"])
        wrapped_tool = wrapper.wrap(existing_tool)
    """

    def wrap(self, tool: Tool) -> Tool:
        original_fn = tool.on_invoke_tool

        async def authed_invoke(ctx: RunContextWrapper, input: str) -> str:
            result = await verify_credentials(
                self.auth_context,
                required_permissions=self.required_permissions,
                required_action=self.required_action,
                audience=self.audience,
            )
            if not result.ok:
                raise BolyraAuthError(f"Auth failed: {result.reason}")
            return await original_fn(ctx, input)

        tool.on_invoke_tool = authed_invoke
        return tool
```

#### 4.4.4 bolyra_mcp_auth()

Wraps an MCP server connection to inject auth headers:

```python
def bolyra_mcp_auth(
    server: MCPServerStdio | MCPServerSse,
    auth_context: BolyraAuthContext,
) -> MCPServerStdio | MCPServerSse:
    """Add Bolyra auth headers to an MCP server connection.

    For gateway mode: injects Authorization header on every request.
    For SD-JWT mode: presents a fresh receipt on every request.

    Usage:
        server = MCPServerSse(url="https://my-mcp-server.com/sse")
        authed_server = bolyra_mcp_auth(server, auth_context)
        agent = Agent(name="my-agent", mcp_servers=[authed_server])
    """
```

Implementation strategy: The OpenAI Agents SDK's MCP server classes accept custom headers. For `MCPServerSse`, we can pass headers directly. For `MCPServerStdio`, auth is injected via environment variables that the MCP server process reads.

### 4.5 Verification Logic (_verify.py)

Shared verification that both the guardrail and tool wrapper call:

```python
async def verify_credentials(
    auth_context: BolyraAuthContext,
    required_permissions: list[str] | None = None,
    required_action: str | None = None,
    audience: str | None = None,
) -> AuthResult:
    """Verify credentials based on auth mode.

    SD-JWT mode:
    1. Present the receipt with a fresh KB-JWT (nonce = uuid4)
    2. Verify the presented receipt
    3. Check permission claims

    Gateway mode:
    1. Validate token is present and not expired (local check)
    2. Optionally hit gateway /verify endpoint
    """
```

For SD-JWT mode, the verification is entirely local (pure Python). For gateway mode, we do a local JWT decode for expiry check but defer full verification to the gateway.

### 4.6 Tracing Integration

The OpenAI Agents SDK has a tracing system with custom spans. We integrate:

```python
from agents.tracing import custom_span

@contextmanager
def bolyra_auth_span(operation: str, agent_id: str):
    with custom_span(
        span_data=CustomSpanData(name=f"bolyra.{operation}"),
        disabled=False,
    ) as span:
        span.span_data.data["agent_id"] = agent_id
        yield span
```

Auth operations that emit spans:
- `bolyra.verify` -- credential verification (pass/fail, duration)
- `bolyra.guardrail` -- guardrail check (trip/pass)
- `bolyra.present` -- SD-JWT presentation (for timing)
- `bolyra.mcp_auth` -- MCP auth header injection

## 5. Public API Summary

```python
# 1. Guardrail (coarse-grained: entire agent run)
from bolyra_agents import BolyraAuthGuardrail, BolyraAuthContext, AuthMode

ctx = BolyraAuthContext(
    mode=AuthMode.SD_JWT,
    receipt=receipt,
    holder_private_key=agent_key,
    issuer_public_key=operator_pub,
)
agent = Agent(
    name="my-agent",
    instructions="You are a helpful assistant.",
    input_guardrails=[BolyraAuthGuardrail(auth_context=ctx)],
)
result = await Runner.run(agent, "Hello")

# 2. Per-tool auth (fine-grained: per tool call)
from bolyra_agents import BolyraToolWrapper

wrapper = BolyraToolWrapper(
    auth_context=ctx,
    required_permissions=["FINANCIAL_SMALL"],
    required_action="purchase",
)
agent = Agent(
    name="shopping-agent",
    tools=[wrapper.wrap(purchase_tool), search_tool],  # only purchase needs auth
)

# 3. MCP gateway auth
from bolyra_agents import bolyra_mcp_auth

server = MCPServerSse(url="https://my-server.com/sse")
authed = bolyra_mcp_auth(server, BolyraAuthContext(
    mode=AuthMode.GATEWAY,
    gateway_token="eyJ...",
))
agent = Agent(name="mcp-agent", mcp_servers=[authed])

# 4. Decorator style
from bolyra_agents import bolyra_tool
from agents import function_tool

@bolyra_tool(ctx, required_permissions=["WRITE_DATA"])
@function_tool
def write_data(content: str) -> str:
    return f"Wrote: {content}"
```

## 6. Security Considerations

1. **No key material in outputs** -- Auth results contain verification status and claim metadata, never private keys or raw receipts.
2. **Fresh nonce per presentation** -- Each SD-JWT presentation generates a fresh UUID nonce for the KB-JWT. No nonce reuse.
3. **Permission enforcement is pre-flight** -- Auth checks happen before tool execution, not after. A failed check never reaches the tool handler.
4. **Scope narrowing only** -- The adapter respects Bolyra's one-way scope narrowing. If a receipt grants `FINANCIAL_SMALL`, wrapping a tool with `required_permissions=["FINANCIAL_UNLIMITED"]` will always fail.
5. **Gateway token expiry** -- Gateway mode does a local expiry check (JWT decode) before sending requests. Expired tokens are rejected locally without hitting the network.
6. **Tracing redaction** -- Tracing spans include operation type and pass/fail status but never include key material, receipt contents, or nonces.

## 7. OpenAI Agents SDK API Surface Used

The adapter depends on these public APIs from `openai-agents`:

| API | Usage |
|-----|-------|
| `InputGuardrail` | Base class for `BolyraAuthGuardrail` |
| `GuardrailFunctionOutput` | Return type from guardrail check |
| `RunContextWrapper` | Access to run context for storing auth state |
| `Agent` | Used in type hints and examples |
| `Runner.run()` | Used in examples |
| `function_tool` / `FunctionTool` | Tool wrapping target |
| `Tool.on_invoke_tool` | Hook point for tool wrapper |
| `MCPServerStdio`, `MCPServerSse` | MCP server types for auth wrapping |
| `custom_span`, `CustomSpanData` | Tracing integration |

These are all documented public APIs in the OpenAI Agents SDK. We do not use any private/internal APIs.

## 8. Testing Strategy

- **Unit tests (no external deps):** Guardrail construction, tool wrapping mechanics, auth context validation, tracing span emission, SD-JWT verification (pure Python via `bolyra.sd_jwt`)
- **Integration tests (requires `openai-agents`):** Full agent run with guardrail, tool wrapper with real `function_tool`, MCP auth injection
- **Mock strategy:** Mock `Runner.run()` and `Agent` for unit tests. Use real `function_tool` for tool wrapper tests.
- **Skip markers:** Tests requiring a running MCP server or gateway are skip-marked when unavailable
- **Test command:** `cd integrations/openai-agents && pytest -v tests/`

## 9. Compatibility

- **Python:** >=3.10 (matches `openai-agents` requirement)
- **openai-agents:** >=0.1.0 (current PyPI version)
- **bolyra:** >=0.4.0 (for SD-JWT support)

The OpenAI Agents SDK is young and its API may evolve. We pin to `>=0.1.0` and document which exact APIs we depend on (section 7) so that breakage is easy to diagnose and fix.

## 10. Version and Release

- **Package name:** `bolyra-agents` (on PyPI)
- **Import name:** `bolyra_agents`
- **Initial version:** `0.1.0`
- **Dependencies:** `openai-agents>=0.1.0`, `bolyra>=0.4.0`
