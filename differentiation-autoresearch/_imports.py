"""Path setup to reuse _shared.py and plateau_detector.py from sibling loops.

Keeps this loop a sibling, not a fork. If the sibling loops move, fix this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # identityos/

# Reuse _shared (Claude CLI, JSON extraction) from protocol-autoresearch
# Reuse plateau_detector from patent-autoresearch
# APPEND — do not insert(0) — otherwise sibling modules (judge.py, tier3_adversarial.py)
# shadow our local ones. Keep local dir (sys.path[0]) as first-priority.
sys.path.append(str(ROOT / "protocol-autoresearch"))
sys.path.append(str(ROOT / "patent-autoresearch" / "history"))
