"""LangChain version compatibility shims.

Handles differences between langchain-core 0.2.x and 0.3.x.
"""

from __future__ import annotations

try:
    from langchain_core.tools import BaseTool
    from langchain_core.callbacks import (
        CallbackManagerForToolRun,
        AsyncCallbackManagerForToolRun,
    )

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseTool = None  # type: ignore[assignment, misc]
    CallbackManagerForToolRun = None  # type: ignore[assignment, misc]
    AsyncCallbackManagerForToolRun = None  # type: ignore[assignment, misc]

try:
    from langchain_core.callbacks import BaseCallbackHandler

    CALLBACKS_AVAILABLE = True
except ImportError:
    BaseCallbackHandler = object  # type: ignore[assignment, misc]
    CALLBACKS_AVAILABLE = False


def check_langchain_available() -> None:
    """Raise ImportError if langchain-core is not installed."""
    if not LANGCHAIN_AVAILABLE:
        raise ImportError(
            "langchain-core is required for Bolyra LangChain tools. "
            "Install with: pip install langchain-core>=0.2.0"
        )
