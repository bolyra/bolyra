"""Tests for BolyraToolWrapper and bolyra_tool decorator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from bolyra_agents.tool_wrapper import BolyraToolWrapper, bolyra_tool
from bolyra_agents.types import AuthResult


@dataclass
class MockToolContext:
    """Minimal ToolContext mock."""
    context: dict[str, Any] = field(default_factory=dict)
    tool_name: str = "test-tool"
    tool_call_id: str = "call-1"
    tool_arguments: str = "{}"


def _make_function_tool(name: str = "test-tool") -> MagicMock:
    """Create a mock FunctionTool."""
    tool = MagicMock()
    tool.name = name
    tool.on_invoke_tool = AsyncMock(return_value="tool result")
    return tool


@pytest.mark.asyncio
async def test_wrapper_sd_jwt_pass(sd_jwt_context):
    """Tool wrapper should allow invocation with valid SD-JWT."""
    wrapper = BolyraToolWrapper(
        auth_context=sd_jwt_context,
        required_permissions=["READ_DATA"],
    )
    tool = _make_function_tool()
    wrapped = wrapper.wrap(tool)

    ctx = MockToolContext()
    result = await wrapped.on_invoke_tool(ctx, '{"arg": "value"}')

    assert result == "tool result"


@pytest.mark.asyncio
async def test_wrapper_insufficient_permissions(sd_jwt_context):
    """Tool wrapper should deny invocation with insufficient permissions."""
    wrapper = BolyraToolWrapper(
        auth_context=sd_jwt_context,
        required_permissions=["FINANCIAL_UNLIMITED"],
    )
    tool = _make_function_tool()
    wrapped = wrapper.wrap(tool)

    ctx = MockToolContext()
    result = await wrapped.on_invoke_tool(ctx, '{}')

    assert isinstance(result, str)
    assert "Auth error" in result
    assert "INSUFFICIENT_PERMISSIONS" in result


@pytest.mark.asyncio
async def test_wrapper_dev_mode(dev_context):
    """Tool wrapper should bypass auth in dev mode."""
    wrapper = BolyraToolWrapper(auth_context=dev_context)
    tool = _make_function_tool()
    wrapped = wrapper.wrap(tool)

    ctx = MockToolContext()
    result = await wrapped.on_invoke_tool(ctx, '{}')

    assert result == "tool result"


@pytest.mark.asyncio
async def test_wrapper_uses_cached_auth(sd_jwt_context):
    """Tool wrapper should use cached auth result from guardrail."""
    wrapper = BolyraToolWrapper(
        auth_context=sd_jwt_context,
        required_permissions=["READ_DATA"],
    )
    tool = _make_function_tool()
    wrapped = wrapper.wrap(tool)

    # Pre-populate cached auth (as if guardrail ran)
    cached = AuthResult(
        ok=True,
        permissions=["READ_DATA", "WRITE_DATA"],
        agent_id="test-agent",
    )
    ctx = MockToolContext(context={"bolyra_auth": cached})
    result = await wrapped.on_invoke_tool(ctx, '{}')

    assert result == "tool result"


@pytest.mark.asyncio
async def test_wrapper_cached_insufficient_permissions(sd_jwt_context):
    """Tool wrapper should deny even with cached auth if permissions insufficient."""
    wrapper = BolyraToolWrapper(
        auth_context=sd_jwt_context,
        required_permissions=["FINANCIAL_UNLIMITED"],
    )
    tool = _make_function_tool()
    wrapped = wrapper.wrap(tool)

    cached = AuthResult(
        ok=True,
        permissions=["READ_DATA"],
        agent_id="test-agent",
    )
    ctx = MockToolContext(context={"bolyra_auth": cached})
    result = await wrapped.on_invoke_tool(ctx, '{}')

    assert isinstance(result, str)
    assert "insufficient permissions" in result


@pytest.mark.asyncio
async def test_wrapper_gateway_pass(gateway_context):
    """Tool wrapper should allow invocation with valid gateway token."""
    wrapper = BolyraToolWrapper(
        auth_context=gateway_context,
        required_permissions=["READ_DATA"],
    )
    tool = _make_function_tool()
    wrapped = wrapper.wrap(tool)

    ctx = MockToolContext()
    result = await wrapped.on_invoke_tool(ctx, '{}')

    assert result == "tool result"


def test_bolyra_tool_decorator(sd_jwt_context):
    """bolyra_tool decorator should return a decorator function."""
    decorator = bolyra_tool(
        sd_jwt_context,
        required_permissions=["READ_DATA"],
    )
    assert callable(decorator)

    tool = _make_function_tool()
    wrapped = decorator(tool)
    assert wrapped is tool  # mutates in place
