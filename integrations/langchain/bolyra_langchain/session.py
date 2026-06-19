"""Session management for Bolyra LangChain tools.

BolyraSession provides a stateful context that chains handshake -> delegate
flows, automatically injecting session_nonce and scope_commitment across
tool calls.
"""

from __future__ import annotations

from typing import Any, Optional


class BolyraSession:
    """Manages auth state across a chain of Bolyra tool calls.

    Provides a higher-level abstraction over the individual tools:
    authenticate first, then delegate with the session context
    automatically injected.

    Example::

        from bolyra_langchain import BolyraAuthTool, BolyraDelegateTool, BolyraSession

        auth = BolyraAuthTool(permissions=["read_data", "write_data"])
        delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])
        session = BolyraSession(auth_tool=auth, delegate_tool=delegate)

        # Authenticate
        auth_result = session.authenticate(scope="my-app")

        # Delegate (session_nonce and scope_commitment auto-injected)
        del_result = session.delegate(
            delegatee_id="0xabc...",
            permissions=["read_data"],
        )
    """

    def __init__(
        self,
        auth_tool: Any = None,
        delegate_tool: Any = None,
    ) -> None:
        self.auth_tool = auth_tool
        self.delegate_tool = delegate_tool
        self._auth_result: dict[str, Any] | None = None
        self._delegation_chain: list[dict[str, Any]] = []

    @property
    def is_authenticated(self) -> bool:
        """Whether a successful handshake has been performed."""
        return (
            self._auth_result is not None
            and self._auth_result.get("verified") is True
        )

    @property
    def session_nonce(self) -> str | None:
        """Session nonce from the last successful handshake."""
        if self._auth_result:
            return self._auth_result.get("session_nonce")
        return None

    @property
    def scope_commitment(self) -> str | None:
        """Scope commitment from the last successful handshake or delegation."""
        # If there are delegations, use the latest scope commitment
        if self._delegation_chain:
            return self._delegation_chain[-1].get("new_scope_commitment")
        if self._auth_result:
            return self._auth_result.get("scope_commitment")
        return None

    @property
    def auth_result(self) -> dict[str, Any] | None:
        """The full auth result dict, or None."""
        return self._auth_result

    @property
    def delegation_chain(self) -> list[dict[str, Any]]:
        """List of delegation results in chain order."""
        return list(self._delegation_chain)

    def authenticate(
        self,
        scope: str = "bolyra-handshake-v1",
        required_permissions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Perform mutual ZKP authentication.

        Args:
            scope: Authentication scope identifier.
            required_permissions: Required permission flags.

        Returns:
            Auth result dict.
        """
        if self.auth_tool is None:
            return {
                "verified": False,
                "status": "error",
                "message": "No auth_tool configured on this session",
                "tool": "bolyra_authenticate",
            }

        input_dict: dict[str, Any] = {"scope": scope}
        if required_permissions:
            input_dict["required_permissions"] = required_permissions

        result = self.auth_tool.invoke(input_dict)
        self._auth_result = result
        self._delegation_chain = []  # Reset delegation chain on new auth
        return result

    def delegate(
        self,
        delegatee_id: str,
        permissions: list[str],
        expiry_seconds: int = 3600,
    ) -> dict[str, Any]:
        """Delegate permissions using session context.

        Auto-injects session_nonce and scope_commitment from the session.

        Args:
            delegatee_id: Credential commitment of the delegatee.
            permissions: Subset of permissions to delegate.
            expiry_seconds: Delegation validity duration.

        Returns:
            Delegation result dict.
        """
        if self.delegate_tool is None:
            return {
                "delegated": False,
                "status": "error",
                "message": "No delegate_tool configured on this session",
                "tool": "bolyra_delegate",
            }

        if not self.is_authenticated:
            return {
                "delegated": False,
                "status": "error",
                "message": "Must authenticate before delegating. Call session.authenticate() first.",
                "tool": "bolyra_delegate",
            }

        input_dict = {
            "delegatee_id": delegatee_id,
            "permissions": permissions,
            "expiry_seconds": expiry_seconds,
            "session_nonce": self.session_nonce or "0",
            "scope_commitment": self.scope_commitment or "0",
        }

        result = self.delegate_tool.invoke(input_dict)
        if result.get("delegated"):
            self._delegation_chain.append(result)
        return result

    def reset(self) -> None:
        """Clear session state."""
        self._auth_result = None
        self._delegation_chain = []
