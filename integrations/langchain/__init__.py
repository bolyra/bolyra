"""Bolyra LangChain integration.

The actual package code is in bolyra_langchain/. This file provides
backward-compatible imports for code that used the old flat module layout.
"""

try:
    from bolyra_langchain import (
        BolyraAuthTool,
        BolyraAuthInput,
        BolyraDelegateTool,
        BolyraDelegateInput,
        BolyraSDJWTTool,
        BolyraSDJWTInput,
        BolyraSession,
    )

    __all__ = [
        "BolyraAuthTool",
        "BolyraAuthInput",
        "BolyraDelegateTool",
        "BolyraDelegateInput",
        "BolyraSDJWTTool",
        "BolyraSDJWTInput",
        "BolyraSession",
    ]
except ImportError:
    # langchain-core not installed -- imports will fail at use time
    pass
