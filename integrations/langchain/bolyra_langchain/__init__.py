"""Bolyra LangChain integration -- mutual ZKP auth and SD-JWT delegation tools.

Provides three LangChain tools as proper BaseTool subclasses:
- BolyraAuthTool: mutual ZKP handshake authentication
- BolyraDelegateTool: scoped ZKP permission delegation
- BolyraSDJWTTool: lightweight SD-JWT delegation (no ZKP/Node.js)

Plus session management and callback integration.

Install: pip install bolyra-langchain
"""

from bolyra_langchain.auth_tool import BolyraAuthTool, BolyraAuthInput
from bolyra_langchain.delegate_tool import BolyraDelegateTool, BolyraDelegateInput
from bolyra_langchain.sd_jwt_tool import BolyraSDJWTTool, BolyraSDJWTInput
from bolyra_langchain.session import BolyraSession
from bolyra_langchain.callbacks import BolyraCallbackHandler
from bolyra_langchain.types import AuthResult, DelegationResult, SDJWTResult

__version__ = "0.1.0"

__all__ = [
    # Tools
    "BolyraAuthTool",
    "BolyraAuthInput",
    "BolyraDelegateTool",
    "BolyraDelegateInput",
    "BolyraSDJWTTool",
    "BolyraSDJWTInput",
    # Session
    "BolyraSession",
    # Callbacks
    "BolyraCallbackHandler",
    # Types
    "AuthResult",
    "DelegationResult",
    "SDJWTResult",
]
