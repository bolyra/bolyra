"""Bolyra callback handler for LangChain.

Emits structured events on Bolyra auth operations. Integrates with
LangChain's callback protocol for observability and tracing.
"""

from __future__ import annotations

from typing import Any

from bolyra_langchain._compat import BaseCallbackHandler


class BolyraCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that logs Bolyra auth events.

    Extend this class to hook into Bolyra-specific events like
    handshake start/complete, delegation grant/verify, and SD-JWT
    issuance.

    Example::

        from bolyra_langchain import BolyraCallbackHandler

        class MyHandler(BolyraCallbackHandler):
            def on_bolyra_auth_complete(self, result, **kwargs):
                print(f"Auth complete: verified={result.get('verified')}")

        handler = MyHandler()
        auth_tool = BolyraAuthTool(callbacks=[handler])
    """

    def on_bolyra_auth_start(self, scope: str, **kwargs: Any) -> None:
        """Called when a mutual ZKP handshake begins."""

    def on_bolyra_auth_complete(self, result: dict[str, Any], **kwargs: Any) -> None:
        """Called when a mutual ZKP handshake completes (success or failure)."""

    def on_bolyra_auth_error(self, error: Exception, **kwargs: Any) -> None:
        """Called when a mutual ZKP handshake raises an exception."""

    def on_bolyra_delegate_start(self, delegatee: str, **kwargs: Any) -> None:
        """Called when a ZKP delegation begins."""

    def on_bolyra_delegate_complete(self, result: dict[str, Any], **kwargs: Any) -> None:
        """Called when a ZKP delegation completes."""

    def on_bolyra_sd_jwt_start(self, action: str, audience: str, **kwargs: Any) -> None:
        """Called when an SD-JWT issuance begins."""

    def on_bolyra_sd_jwt_complete(self, result: dict[str, Any], **kwargs: Any) -> None:
        """Called when an SD-JWT issuance completes."""
