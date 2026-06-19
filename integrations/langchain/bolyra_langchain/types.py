"""Shared types for the Bolyra LangChain integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    protocol_version: str = "0.4.0"
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
    protocol_version: str = "0.4.0"
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


@dataclass
class SDJWTResult:
    """Result of an SD-JWT delegation operation."""

    success: bool
    status: str
    receipt: str = ""
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
