"""Types for the Bolyra OpenAI Agents SDK adapter."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class AuthMode(enum.Enum):
    """Authentication mode for the Bolyra adapter."""

    SD_JWT = "sd-jwt"
    GATEWAY = "gateway"


@dataclass
class AuthResult:
    """Result of a credential verification."""

    ok: bool
    """Whether verification succeeded."""

    claims: dict[str, Any] | None = None
    """Verified claims from the credential (SD-JWT claims or gateway token claims)."""

    reason: str | None = None
    """Failure reason code (e.g. 'EXPIRED', 'INVALID_SIGNATURE')."""

    detail: str | None = None
    """Human-readable detail for debugging."""

    permissions: list[str] = field(default_factory=list)
    """Resolved permissions from the credential."""

    agent_id: str = ""
    """Agent identifier from the credential."""


class ToolPermission(enum.Enum):
    """Bolyra permission labels (mirrors the 8-bit cumulative encoding)."""

    READ_DATA = "READ_DATA"
    WRITE_DATA = "WRITE_DATA"
    FINANCIAL_SMALL = "FINANCIAL_SMALL"
    FINANCIAL_MEDIUM = "FINANCIAL_MEDIUM"
    FINANCIAL_UNLIMITED = "FINANCIAL_UNLIMITED"
    SIGN_ON_BEHALF = "SIGN_ON_BEHALF"
    SUB_DELEGATE = "SUB_DELEGATE"
    ACCESS_PII = "ACCESS_PII"


# Permission implication map: higher tiers imply lower
_PERMISSION_IMPLIES: dict[str, set[str]] = {
    "FINANCIAL_MEDIUM": {"FINANCIAL_SMALL"},
    "FINANCIAL_UNLIMITED": {"FINANCIAL_SMALL", "FINANCIAL_MEDIUM"},
}


def check_permissions(
    granted: list[str] | str,
    required: list[str] | str,
) -> bool:
    """Check whether granted permissions satisfy required permissions.

    Respects cumulative-bit implication rules: FINANCIAL_MEDIUM implies
    FINANCIAL_SMALL, FINANCIAL_UNLIMITED implies both.

    Args:
        granted: Permission labels the credential grants.
        required: Permission labels the operation requires.

    Returns:
        True if all required permissions are satisfied.
    """
    if isinstance(granted, str):
        granted = [granted]
    if isinstance(required, str):
        required = [required]

    # Expand granted permissions with implied ones
    effective: set[str] = set()
    for perm in granted:
        effective.add(perm)
        for implied_by, implies in _PERMISSION_IMPLIES.items():
            if perm == implied_by:
                effective.update(implies)

    return all(r in effective for r in required)


class BolyraAuthError(Exception):
    """Raised when Bolyra auth verification fails in a tool wrapper."""

    def __init__(self, message: str, result: AuthResult | None = None):
        super().__init__(message)
        self.result = result
