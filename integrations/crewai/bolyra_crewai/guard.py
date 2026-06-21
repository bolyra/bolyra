"""CrewAI step callback guard for Bolyra authentication.

Verifies that a valid Bolyra auth session exists before tool execution.
Hooks into CrewAI's ``step_callback`` mechanism on the Crew constructor.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)


class BolyraAuthError(Exception):
    """Raised when BolyraGuard blocks an unauthenticated tool invocation."""


class BolyraGuard:
    """Callback guard that verifies Bolyra auth before tool execution.

    Usage::

        from bolyra_crewai import BolyraGuard, BolyraSession

        session = BolyraSession(auth_tool=auth_tool)
        guard = BolyraGuard(session=session)

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

    def step_callback(self, step_output: Any) -> None:
        """CrewAI step callback -- verifies auth state.

        Called after each step. If the step involved a tool invocation
        and the session is not authenticated, takes the configured
        on_failure action.

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

        # Allow-listed tools bypass the check
        if tool_name in self.allow_unauthenticated_tools:
            # Track auth timestamp when auth tool runs
            if tool_name == "bolyra_authenticate" and self.session is not None:
                if self.session.is_authenticated:
                    self._auth_timestamp = time.time()
            return

        # Check session
        if self.session is None:
            self._handle_failure(
                f"No BolyraSession configured. Tool '{tool_name}' requires authentication."
            )
            return

        if not self.session.is_authenticated:
            self._handle_failure(
                f"Tool '{tool_name}' requires Bolyra authentication. "
                "Call bolyra_authenticate first."
            )
            return

        # Check session expiry
        if self._is_session_expired():
            self._handle_failure(
                f"Bolyra session expired (TTL={self.session_ttl_seconds}s). "
                "Re-authenticate before using tools."
            )
            return

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
