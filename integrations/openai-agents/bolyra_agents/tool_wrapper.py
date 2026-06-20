"""BolyraToolWrapper -- per-tool auth verification for OpenAI Agents SDK.

Fine-grained auth: different tools can require different permissions.
Wraps a FunctionTool's ``on_invoke_tool`` to check credentials before
the tool handler runs.

Two usage patterns:

1. Class-based wrapping (for existing tools)::

    wrapper = BolyraToolWrapper(auth_context=ctx, required_permissions=["WRITE_DATA"])
    wrapped_tool = wrapper.wrap(existing_tool)

2. Decorator-based (for new tools)::

    @bolyra_tool(ctx, required_permissions=["FINANCIAL_SMALL"])
    @function_tool
    def purchase_item(sku: str, amount: float) -> str:
        return f"Purchased {sku} for ${amount}"
"""

from __future__ import annotations

import functools
import os
import warnings
from typing import Any, Callable

from agents import FunctionTool
from agents.tool import ToolContext

from bolyra_agents._tracing import bolyra_auth_span, record_auth_result
from bolyra_agents._verify import verify_credentials
from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthResult, BolyraAuthError


class BolyraToolWrapper:
    """Wraps an existing FunctionTool with Bolyra auth verification.

    On each tool invocation, verifies credentials against the required
    permissions before calling the original tool handler.

    Args:
        auth_context: Auth context with credentials.
        required_permissions: Permission labels required by this tool.
        required_action: Required action claim (SD-JWT only).
        audience: Required audience (overrides auth_context.default_audience).
    """

    def __init__(
        self,
        auth_context: BolyraAuthContext,
        required_permissions: list[str] | None = None,
        required_action: str | None = None,
        audience: str | None = None,
    ):
        self.auth_context = auth_context
        self.required_permissions = required_permissions
        self.required_action = required_action
        self.audience = audience

    def wrap(self, tool: FunctionTool) -> FunctionTool:
        """Wrap a FunctionTool with auth verification.

        Replaces the tool's ``on_invoke_tool`` with a version that checks
        credentials first. The original tool is mutated in place and returned.

        Args:
            tool: The FunctionTool to wrap.

        Returns:
            The same tool with auth-wrapped invocation.
        """
        original_fn = tool.on_invoke_tool

        async def authed_invoke(ctx: ToolContext, input_str: str) -> Any:
            with bolyra_auth_span(
                "tool_auth",
                agent_id=self.auth_context.agent_id,
                tool_name=tool.name,
            ) as span:
                # Dev mode bypass
                if self.auth_context.dev_mode:
                    if os.environ.get("BOLYRA_ENV") == "production":
                        raise BolyraAuthError("dev_mode=True is not allowed when BOLYRA_ENV=production")
                    warnings.warn("Bolyra: dev_mode is active. Do not use in production.", stacklevel=2)
                    record_auth_result(span, ok=True, reason="dev_mode")
                    return await original_fn(ctx, input_str)

                # Check if auth was already verified by guardrail
                cached_result = _get_cached_auth(ctx)
                if cached_result and cached_result.ok:
                    # Re-check permissions against this tool's requirements
                    if self.required_permissions:
                        from bolyra_agents.types import check_permissions
                        if not check_permissions(
                            cached_result.permissions,
                            self.required_permissions,
                        ):
                            record_auth_result(span, ok=False, reason="INSUFFICIENT_PERMISSIONS")
                            return (
                                f"Auth error: insufficient permissions for tool '{tool.name}'. "
                                f"Required: {self.required_permissions}, "
                                f"granted: {cached_result.permissions}"
                            )
                    record_auth_result(span, ok=True)
                    return await original_fn(ctx, input_str)

                # Full verification
                result = await verify_credentials(
                    self.auth_context,
                    required_permissions=self.required_permissions,
                    required_action=self.required_action,
                    audience=self.audience,
                )

                record_auth_result(span, ok=result.ok, reason=result.reason)

                if not result.ok:
                    return (
                        f"Auth error: {result.reason}. "
                        f"Tool '{tool.name}' requires Bolyra authentication. "
                        f"Detail: {result.detail or 'none'}"
                    )

                return await original_fn(ctx, input_str)

        tool.on_invoke_tool = authed_invoke
        return tool


def bolyra_tool(
    auth_context: BolyraAuthContext,
    required_permissions: list[str] | None = None,
    required_action: str | None = None,
    audience: str | None = None,
) -> Callable[[FunctionTool], FunctionTool]:
    """Decorator that wraps a FunctionTool with Bolyra auth verification.

    Apply this BEFORE ``@function_tool`` (i.e., outermost decorator) so it
    wraps the already-constructed FunctionTool.

    Usage::

        @bolyra_tool(ctx, required_permissions=["FINANCIAL_SMALL"])
        @function_tool
        def purchase_item(sku: str, amount: float) -> str:
            return f"Purchased {sku} for ${amount}"

    Args:
        auth_context: Auth context with credentials.
        required_permissions: Permission labels required by this tool.
        required_action: Required action claim (SD-JWT only).
        audience: Required audience.

    Returns:
        Decorator that wraps a FunctionTool.
    """
    wrapper = BolyraToolWrapper(
        auth_context=auth_context,
        required_permissions=required_permissions,
        required_action=required_action,
        audience=audience,
    )

    def decorator(tool: FunctionTool) -> FunctionTool:
        return wrapper.wrap(tool)

    return decorator


def _get_cached_auth(ctx: Any) -> AuthResult | None:
    """Retrieve cached auth result from run context.

    The guardrail stores its result in ``ctx.context["bolyra_auth"]``.
    """
    if hasattr(ctx, "context") and isinstance(ctx.context, dict):
        result = ctx.context.get("bolyra_auth")
        if isinstance(result, AuthResult):
            return result
    return None
