"""Shared auth context for the Bolyra OpenAI Agents SDK adapter.

BolyraAuthContext holds the credential state that the guardrail, tool wrapper,
and MCP auth wrapper all read from. Create one context per agent and pass it
to all Bolyra components.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from bolyra_agents.types import AuthMode


@dataclass
class BolyraAuthContext:
    """Holds auth state for a Bolyra-authenticated agent.

    Supports two auth modes:

    **SD-JWT mode** (pure Python, no infrastructure):
        Provide ``receipt``, ``holder_private_key``, and ``issuer_public_key``.
        The adapter verifies the SD-JWT locally using ``bolyra.sd_jwt``.

    **Gateway mode** (HTTP headers):
        Provide ``gateway_token`` and optionally ``gateway_url``.
        The adapter injects an ``Authorization: Bearer <token>`` header
        and does a local JWT expiry check.

    Example::

        ctx = BolyraAuthContext(
            mode=AuthMode.SD_JWT,
            receipt=receipt_str,
            holder_private_key=agent_key,
            issuer_public_key=operator_pub,
            agent_id="my-agent",
        )
    """

    mode: AuthMode
    """Authentication mode: SD_JWT or GATEWAY."""

    # -- SD-JWT mode fields --
    receipt: str | None = field(default=None, repr=False)
    """Issuer-form SD-JWT receipt (ends with '~')."""

    holder_private_key: Ed25519PrivateKey | None = field(default=None, repr=False)
    """Agent's Ed25519 private key for KB-JWT signing (must match cnf.jwk in receipt)."""

    issuer_public_key: Ed25519PublicKey | None = None
    """Issuer's Ed25519 public key for receipt signature verification."""

    # -- Gateway mode fields --
    gateway_token: str | None = field(default=None, repr=False)
    """Pre-obtained auth token for gateway mode."""

    gateway_url: str | None = None
    """Optional gateway URL for online verification."""

    # -- Shared fields --
    agent_id: str = "default-agent"
    """Agent identifier for tracing and logging."""

    default_audience: str = "bolyra-agents"
    """Default audience for SD-JWT presentations and verifications."""

    required_permissions: list[str] = field(default_factory=lambda: ["READ_DATA"])
    """Default permissions required for this agent."""

    dev_mode: bool = False
    """When True, relax certain checks (e.g. auto-generate nonces). Never use in production."""

    def validate(self) -> list[str]:
        """Validate the auth context configuration.

        Returns:
            List of validation error messages (empty if valid).
        """
        errors: list[str] = []

        if self.mode == AuthMode.SD_JWT:
            if not self.receipt:
                errors.append("SD-JWT mode requires 'receipt'")
            if not self.holder_private_key:
                errors.append("SD-JWT mode requires 'holder_private_key'")
            if not self.issuer_public_key:
                errors.append("SD-JWT mode requires 'issuer_public_key'")
        elif self.mode == AuthMode.GATEWAY:
            if not self.gateway_token:
                errors.append("Gateway mode requires 'gateway_token'")
        else:
            errors.append(f"Unknown auth mode: {self.mode}")

        return errors
