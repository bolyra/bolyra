"""CrewAI guard for Bolyra authentication.

Two enforcement modes:

1. **Pre-execution (recommended):** ``guard.guard_tools(tools)`` wraps each
   tool's ``_run`` method so auth is checked *before* the tool executes.
   Unauthenticated calls are blocked and return an error JSON string.

2. **Post-execution audit:** ``step_callback=guard.step_callback`` hooks into
   CrewAI's step callback, which fires *after* each step completes. This
   catches violations but cannot prevent the tool from running.

Use ``guard_tools`` for enforcement; use ``step_callback`` for logging/audit.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class BolyraAuthError(Exception):
    """Raised when BolyraGuard blocks an unauthenticated tool invocation."""


class BolyraGuard:
    """Guard that verifies Bolyra auth around tool execution.

    Pre-execution enforcement (recommended)::

        from bolyra_crewai import BolyraGuard, BolyraSession, BolyraAuthTool

        auth_tool = BolyraAuthTool()
        session = BolyraSession(auth_tool=auth_tool)
        guard = BolyraGuard(session=session)

        # Wrap tools for pre-execution checking
        tools = guard.guard_tools([auth_tool, other_tool])

        agent = Agent(role="Analyst", tools=tools, ...)
        crew = Crew(agents=[agent], tasks=[...])

    Post-execution audit (weaker, for logging only)::

        crew = Crew(
            agents=[...],
            tasks=[...],
            step_callback=guard.step_callback,
        )

    Args:
        required_permissions: Permission flags to require (default: ["read_data"]).
        session: BolyraSession to check for auth state. If None, the guard
            will always trigger failure for non-allowlisted tools.
        allow_unauthenticated_tools: Tool names that bypass the auth check.
            Default: ["bolyra_authenticate"] (so the auth tool itself can run).
        on_failure: What to do when auth check fails:
            - ``"raise"`` (default): raise BolyraAuthError, stopping the crew
            - ``"warn"``: log a warning but allow execution to continue
            - ``"skip"``: silently skip the auth check (for dev/testing)
        session_ttl_seconds: Maximum session age before requiring re-auth.
            Default: None (no expiry check).
    """

    def __init__(
        self,
        required_permissions: list[str] | None = None,
        session: Any | None = None,
        allow_unauthenticated_tools: list[str] | None = None,
        on_failure: str = "raise",
        session_ttl_seconds: int | None = None,
    ) -> None:
        self.required_permissions = required_permissions or ["read_data"]
        self.session = session
        self.allow_unauthenticated_tools = allow_unauthenticated_tools or [
            "bolyra_authenticate"
        ]
        if on_failure not in ("raise", "warn", "skip"):
            raise ValueError(
                f"on_failure must be 'raise', 'warn', or 'skip', got '{on_failure}'"
            )
        self.on_failure = on_failure
        self.session_ttl_seconds = session_ttl_seconds
        self._auth_timestamp: float | None = None

    def _handle_failure(self, message: str) -> None:
        """Handle an auth check failure according to the configured policy."""
        if self.on_failure == "raise":
            raise BolyraAuthError(message)
        elif self.on_failure == "warn":
            logger.warning("BolyraGuard: %s", message)
        # "skip" does nothing

    def _is_session_expired(self) -> bool:
        """Check if the session has exceeded the TTL."""
        if self.session_ttl_seconds is None:
            return False
        if self._auth_timestamp is None:
            return True
        return (time.time() - self._auth_timestamp) > self.session_ttl_seconds

    def _check_auth(self, tool_name: str) -> str | None:
        """Check auth state for a tool invocation.

        Returns None if auth passes, or an error message string if it fails.
        """
        if self.on_failure == "skip":
            return None

        if tool_name in self.allow_unauthenticated_tools:
            return None

        if self.session is None:
            return (
                f"No BolyraSession configured. "
                f"Tool '{tool_name}' requires authentication."
            )

        if not self.session.is_authenticated:
            return (
                f"Tool '{tool_name}' requires Bolyra authentication. "
                "Call bolyra_authenticate first."
            )

        if self._is_session_expired():
            return (
                f"Bolyra session expired (TTL={self.session_ttl_seconds}s). "
                "Re-authenticate before using tools."
            )

        return None

    def guard_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap tools with pre-execution auth checking.

        Monkey-patches each tool's ``_run`` method to check auth before
        execution. Tools in ``allow_unauthenticated_tools`` are not wrapped.
        Returns the same list (tools are mutated in place).

        Args:
            tools: List of CrewAI BaseTool instances.

        Returns:
            The same list, with non-allowlisted tools wrapped.
        """
        for tool in tools:
            tool_name = getattr(tool, "name", None)
            if tool_name and tool_name not in self.allow_unauthenticated_tools:
                self._wrap_tool(tool)
        return tools

    def _wrap_tool(self, tool: Any) -> None:
        """Wrap a single tool's _run with a pre-execution auth check."""
        original_run = tool._run
        guard = self

        def guarded_run(**kwargs: Any) -> str:
            tool_name = getattr(tool, "name", "unknown")
            error = guard._check_auth(tool_name)
            if error is not None:
                guard._handle_failure(error)
                # If on_failure is "warn", execution continues past _handle_failure.
                # If on_failure is "raise", we never reach here.
                # Return error JSON so the LLM sees the issue.
                if guard.on_failure == "warn":
                    return json.dumps({
                        "error": True,
                        "message": error,
                        "tool": tool_name,
                    })
            return original_run(**kwargs)

        tool._run = guarded_run

    def step_callback(self, step_output: Any) -> None:
        """CrewAI step callback -- post-execution audit.

        Called after each step completes. Use for logging and audit.
        For pre-execution enforcement, use ``guard_tools()`` instead.

        Args:
            step_output: The CrewAI step output object. May have a
                ``tool`` attribute or similar indicating which tool ran.
        """
        if self.on_failure == "skip":
            return

        # Extract tool name from step output
        tool_name = self._extract_tool_name(step_output)
        if tool_name is None:
            # Not a tool step -- nothing to guard
            return

        # Track auth timestamp when auth tool runs
        if tool_name in self.allow_unauthenticated_tools:
            if tool_name == "bolyra_authenticate" and self.session is not None:
                if self.session.is_authenticated:
                    self._auth_timestamp = time.time()
            return

        error = self._check_auth(tool_name)
        if error is not None:
            self._handle_failure(error)

    @staticmethod
    def _extract_tool_name(step_output: Any) -> str | None:
        """Extract the tool name from a CrewAI step output.

        CrewAI step outputs vary by version. We check common attributes.
        """
        # CrewAI AgentAction has a .tool attribute
        if hasattr(step_output, "tool"):
            return str(step_output.tool)
        # Some versions wrap in a result dict
        if isinstance(step_output, dict):
            return step_output.get("tool")
        return None
