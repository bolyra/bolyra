"""Shared types for the Bolyra CrewAI integration.

Mirrors the LangChain adapter types but with JSON string serialization
for CrewAI's string-return convention.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


# --- Permission parsing ---

# Canonical permission names (lowercase) matching the 8-bit encoding in the TS SDK.
VALID_PERMISSIONS = frozenset({
    "read_data",
    "write_data",
    "financial_small",
    "financial_medium",
    "financial_unlimited",
    "sign_on_behalf",
    "sub_delegate",
    "access_pii",
})


def parse_permissions(raw: str) -> list[str]:
    """Parse a comma-separated permission string into a validated list.

    Args:
        raw: Comma-separated permission names, e.g. "read_data, write_data"

    Returns:
        List of lowercase, stripped permission strings.

    Raises:
        ValueError: If any permission name is not recognized.
    """
    perms = [p.strip().lower() for p in raw.split(",") if p.strip()]
    invalid = [p for p in perms if p not in VALID_PERMISSIONS]
    if invalid:
        raise ValueError(
            f"Unknown permission(s): {invalid}. "
            f"Valid: {sorted(VALID_PERMISSIONS)}"
        )
    return perms


def is_dev_mode_allowed() -> bool:
    """Check whether dev mode is allowed in the current environment.

    Returns False if BOLYRA_ENV is set to 'production'.
    """
    return os.environ.get("BOLYRA_ENV", "").lower() != "production"


def make_canonical_nonce() -> int:
    """Generate a canonical nonce: (unix_seconds << 64) | random_8_bytes."""
    import time

    unix_seconds = int(time.time())
    random_bytes = int.from_bytes(os.urandom(8), "big")
    return (unix_seconds << 64) | random_bytes


# --- Result dataclasses ---


@dataclass
class AuthResult:
    """Result of a mutual ZKP handshake authentication."""

    verified: bool
    status: str
    human_nullifier: str = ""
    agent_nullifier: str = ""
    session_nonce: str = ""
    scope_commitment: str = ""
    scope: str = ""
    required_permissions: list[str] = field(default_factory=list)
    counterparty_type: str = "human"
    tool: str = "bolyra_authenticate"
    protocol_version: str = "0.5.0"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "verified": self.verified,
            "status": self.status,
            "tool": self.tool,
            "protocol_version": self.protocol_version,
        }
        if self.verified:
            d.update({
                "human_nullifier": self.human_nullifier,
                "agent_nullifier": self.agent_nullifier,
                "session_nonce": self.session_nonce,
                "scope_commitment": self.scope_commitment,
                "scope": self.scope,
                "required_permissions": self.required_permissions,
                "counterparty_type": self.counterparty_type,
            })
        if self.message:
            d["message"] = self.message
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class DelegationResult:
    """Result of a ZKP delegation."""

    delegated: bool
    status: str
    delegatee_id: str = ""
    permissions: list[str] = field(default_factory=list)
    expiry_seconds: int = 0
    new_scope_commitment: str = ""
    delegation_nullifier: str = ""
    tool: str = "bolyra_delegate"
    protocol_version: str = "0.5.0"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "delegated": self.delegated,
            "status": self.status,
            "tool": self.tool,
            "protocol_version": self.protocol_version,
        }
        if self.delegated:
            d.update({
                "delegatee_id": self.delegatee_id,
                "permissions": self.permissions,
                "expiry_seconds": self.expiry_seconds,
                "new_scope_commitment": self.new_scope_commitment,
                "delegation_nullifier": self.delegation_nullifier,
            })
        if self.message:
            d["message"] = self.message
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class SDJWTResult:
    """Result of an SD-JWT delegation operation."""

    success: bool
    status: str
    receipt_jti: str = ""
    action: str = ""
    audience: str = ""
    permission: str = ""
    expiry: int = 0
    tool: str = "bolyra_authorize"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "success": self.success,
            "status": self.status,
            "tool": self.tool,
        }
        if self.success:
            d.update({
                "receipt_jti": self.receipt_jti,
                "action": self.action,
                "audience": self.audience,
                "permission": self.permission,
                "expiry": self.expiry,
            })
        if self.message:
            d["message"] = self.message
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
