"""Bolyra CrewAI integration -- mutual ZKP auth and SD-JWT delegation tools.

Provides three CrewAI tools as proper BaseTool subclasses:
- BolyraAuthTool: mutual ZKP handshake authentication
- BolyraDelegateTool: scoped ZKP permission delegation
- BolyraSDJWTTool: lightweight SD-JWT delegation (no ZKP/Node.js)

Plus BolyraGuard (step callback), BolyraSession, and shared types.

Install: pip install bolyra-crewai
"""

from bolyra_crewai.auth_tool import BolyraAuthTool, BolyraAuthInput
from bolyra_crewai.delegate_tool import BolyraDelegateTool, BolyraDelegateInput
from bolyra_crewai.sd_jwt_tool import BolyraSDJWTTool, BolyraSDJWTInput
from bolyra_crewai.guard import BolyraGuard, BolyraAuthError
from bolyra_crewai.session import BolyraSession
from bolyra_crewai.types import AuthResult, DelegationResult, SDJWTResult

__version__ = "0.1.0"

__all__ = [
    # Tools
    "BolyraAuthTool",
    "BolyraAuthInput",
    "BolyraDelegateTool",
    "BolyraDelegateInput",
    "BolyraSDJWTTool",
    "BolyraSDJWTInput",
    # Guard
    "BolyraGuard",
    "BolyraAuthError",
    # Session
    "BolyraSession",
    # Types
    "AuthResult",
    "DelegationResult",
    "SDJWTResult",
]
