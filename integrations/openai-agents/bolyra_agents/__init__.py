"""Bolyra OpenAI Agents SDK adapter -- auth guardrails, tool wrappers, and MCP auth.

Provides three integration points for adding Bolyra auth to OpenAI Agents SDK agents:

1. **BolyraAuthGuardrail** -- coarse-grained InputGuardrail that verifies credentials
   before an agent run starts.

2. **BolyraToolWrapper** / **bolyra_tool** -- fine-grained per-tool auth that checks
   permissions before each tool invocation.

3. **bolyra_mcp_auth** -- wraps MCP server connections to inject Bolyra auth headers.

Install: ``pip install bolyra-agents``

Example::

    from bolyra_agents import BolyraAuthGuardrail, BolyraAuthContext, AuthMode
    from agents import Agent, Runner

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
"""

from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.guardrail import BolyraAuthGuardrail
from bolyra_agents.mcp_auth import bolyra_mcp_auth
from bolyra_agents.tool_wrapper import BolyraToolWrapper, bolyra_tool
from bolyra_agents.types import AuthMode, AuthResult, BolyraAuthError, ToolPermission

__version__ = "0.1.0"

__all__ = [
    # Auth context
    "BolyraAuthContext",
    # Guardrail
    "BolyraAuthGuardrail",
    # Tool wrapper
    "BolyraToolWrapper",
    "bolyra_tool",
    # MCP auth
    "bolyra_mcp_auth",
    # Types
    "AuthMode",
    "AuthResult",
    "BolyraAuthError",
    "ToolPermission",
]
