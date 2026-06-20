"""Tracing integration for Bolyra auth operations.

Emits custom spans in the OpenAI Agents SDK tracing system so that
auth events appear alongside agent execution traces.

Spans emitted:
- bolyra.verify: credential verification (pass/fail, duration)
- bolyra.guardrail: guardrail check (trip/pass)
- bolyra.present: SD-JWT presentation (timing)
- bolyra.mcp_auth: MCP auth header injection

Security: spans include operation type and pass/fail status but NEVER
include key material, receipt contents, or nonces.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator

from agents.tracing import custom_span


@contextmanager
def bolyra_auth_span(
    operation: str,
    agent_id: str = "",
    **extra: Any,
) -> Generator[Any, None, None]:
    """Create a custom tracing span for a Bolyra auth operation.

    Args:
        operation: Operation name (e.g. 'verify', 'guardrail', 'present', 'mcp_auth').
        agent_id: Agent identifier for the span metadata.
        **extra: Additional metadata to attach to the span.
    """
    _SAFE_KEYS = frozenset({"agent_id", "tool_name", "agent_name", "operation", "auth_ok", "auth_reason", "server_type", "mode", "permissions"})
    data: dict[str, Any] = {"agent_id": agent_id}
    # Only include allowlisted metadata -- redact everything else
    for key, value in extra.items():
        if key in _SAFE_KEYS:
            data[key] = value

    with custom_span(name=f"bolyra.{operation}", data=data) as span:
        yield span


def record_auth_result(span: Any, ok: bool, reason: str | None = None) -> None:
    """Record the result of an auth operation on a span.

    Args:
        span: The tracing span to update.
        ok: Whether the operation succeeded.
        reason: Failure reason code (omitted on success).
    """
    if hasattr(span, "span_data") and hasattr(span.span_data, "data"):
        span.span_data.data["auth_ok"] = ok
        if reason and not ok:
            span.span_data.data["auth_reason"] = reason
