# LangChain credential middleware with automatic scope-gated tool access

Build a LangChain CallbackHandler + BaseTool wrapper that intercepts tool invocations and requires a valid Bolyra AgentPolicy proof before execution. The middleware maps LangChain tool names to permission bitmask bits (e.g., SQLDatabaseTool → READ_DATA, StripeChargeTool → FINANCIAL_SMALL) via a declarative YAML config. On first call, it runs proveHandshake() and caches the proof for the session nonce lifetime. Publish as @bolyra/langchain on npm and bolyra-langchain on PyPI, with a 5-line quickstart that wraps an existing AgentExecutor.

## Status

Placeholder — awaiting implementation.
