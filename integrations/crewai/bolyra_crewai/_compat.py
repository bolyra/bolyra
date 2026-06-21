"""CrewAI version compatibility shims.

Handles graceful degradation when crewai is not installed.
"""

from __future__ import annotations

try:
    from crewai.tools import BaseTool

    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    BaseTool = None  # type: ignore[assignment, misc]


def check_crewai_available() -> None:
    """Raise ImportError if crewai is not installed."""
    if not CREWAI_AVAILABLE:
        raise ImportError(
            "crewai is required for Bolyra CrewAI tools. "
            "Install with: pip install crewai>=0.50.0"
        )
