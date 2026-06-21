"""Session management for Bolyra CrewAI tools.

BolyraSession provides a stateful context that chains handshake -> delegate
-> SD-JWT flows, automatically injecting session_nonce and scope_commitment
across tool calls.

Thread-safe: uses a threading.Lock for state mutations.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Optional


class BolyraSession:
    """Manages auth state across a chain of Bolyra tool calls.

    Provides a higher-level abstraction over the individual tools:
    authenticate first, then delegate or authorize with the session
    context automatically injected.

    Thread-safe: all state mutations are protected by an internal lock.

    Example::

        from bolyra_crewai import (
            BolyraAuthTool, BolyraDelegateTool, BolyraSDJWTTool, BolyraSession,
        )

        auth = BolyraAuthTool(permissions=["read_data", "write_data"])
        delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])
        sd_jwt = BolyraSDJWTTool()
        session = BolyraSession(auth_tool=auth, delegate_tool=delegate, sd_jwt_tool=sd_jwt)

        # Authenticate
        auth_result = session.authenticate(scope="my-app")

        # Delegate (session_nonce and scope_commitment auto-injected)
        del_result = session.delegate(
            delegatee_id="0xabc...",
            permissions="read_data",
        )

        # Authorize via SD-JWT
        jwt_result = session.authorize(
            action="checkout.charge",
            audience="stripe.example.com",
        )
    """

    def __init__(
        self,
        auth_tool: Any = None,
        delegate_tool: Any = None,
        sd_jwt_tool: Any = None,
    ) -> None:
        self.auth_tool = auth_tool
        self.delegate_tool = delegate_tool
        self.sd_jwt_tool = sd_jwt_tool
        self._lock = threading.Lock()
        self._auth_result: dict[str, Any] | None = None
        self._delegation_chain: list[dict[str, Any]] = []

    @property
    def is_authenticated(self) -> bool:
        """Whether a successful handshake has been performed."""
        with self._lock:
            return (
                self._auth_result is not None
                and self._auth_result.get("verified") is True
            )

    @property
    def session_nonce(self) -> str | None:
        """Session nonce from the last successful handshake."""
        with self._lock:
            if self._auth_result:
                return self._auth_result.get("session_nonce")
            return None

    @property
    def scope_commitment(self) -> str | None:
        """Scope commitment from the last successful handshake or delegation."""
        with self._lock:
            if self._delegation_chain:
                return self._delegation_chain[-1].get("new_scope_commitment")
            if self._auth_result:
                return self._auth_result.get("scope_commitment")
            return None

    @property
    def auth_result(self) -> dict[str, Any] | None:
        """The full auth result dict, or None."""
        with self._lock:
            return self._auth_result

    @property
    def delegation_chain(self) -> list[dict[str, Any]]:
        """List of delegation results in chain order."""
        with self._lock:
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

        # CrewAI tools return strings -- parse JSON
        kwargs: dict[str, Any] = {"scope": scope}
        if required_permissions:
            kwargs["required_permissions"] = required_permissions

        raw = self.auth_tool._run(**kwargs)
        result = json.loads(raw) if isinstance(raw, str) else raw

        with self._lock:
            self._auth_result = result
            self._delegation_chain = []  # Reset delegation chain on new auth
        return result

    def delegate(
        self,
        delegatee_id: str,
        permissions: str,
        expiry_seconds: int = 3600,
    ) -> dict[str, Any]:
        """Delegate permissions using session context.

        Auto-injects session_nonce and scope_commitment from the session.

        Args:
            delegatee_id: Credential commitment of the delegatee.
            permissions: Comma-separated permissions to delegate.
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
                "message": (
                    "Must authenticate before delegating. "
                    "Call session.authenticate() first."
                ),
                "tool": "bolyra_delegate",
            }

        raw = self.delegate_tool._run(
            delegatee_id=delegatee_id,
            permissions=permissions,
            expiry_seconds=expiry_seconds,
            session_nonce=self.session_nonce or "0",
            scope_commitment=self.scope_commitment or "0",
        )
        result = json.loads(raw) if isinstance(raw, str) else raw

        if result.get("delegated"):
            with self._lock:
                self._delegation_chain.append(result)
        return result

    def authorize(
        self,
        action: str,
        audience: str,
        permission: str = "READ_DATA",
        max_amount: float | None = None,
        currency: str = "USD",
        nonce: str | None = None,
    ) -> dict[str, Any]:
        """Issue an SD-JWT delegation receipt.

        Args:
            action: Action to authorize.
            audience: Tool or service identifier.
            permission: Permission label.
            max_amount: Cap per invocation.
            currency: Currency for max_amount.
            nonce: Verifier challenge nonce.

        Returns:
            SD-JWT result dict.
        """
        if self.sd_jwt_tool is None:
            return {
                "success": False,
                "status": "error",
                "message": "No sd_jwt_tool configured on this session",
                "tool": "bolyra_authorize",
            }

        kwargs: dict[str, Any] = {
            "action": action,
            "audience": audience,
            "permission": permission,
        }
        if max_amount is not None:
            kwargs["max_amount"] = max_amount
            kwargs["currency"] = currency
        if nonce is not None:
            kwargs["nonce"] = nonce

        raw = self.sd_jwt_tool._run(**kwargs)
        return json.loads(raw) if isinstance(raw, str) else raw

    def reset(self) -> None:
        """Clear session state."""
        with self._lock:
            self._auth_result = None
            self._delegation_chain = []
