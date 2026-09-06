"""Board mutation helpers: append-only, update-if-higher, supersede-never-delete.

Applies Tier-1-promoted scout candidates (threat_update / adoption_target)
to the boards. Engagement-graph holds cap channel_state and set state=hold.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "output"

BOARD_FOR_TYPE = {"threat_update": "threat_board.json",
                  "adoption_target": "adoption_board.json"}
KIND_FOR_TYPE = {"threat_update": "threat", "adoption_target": "adoption_target"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load(board: str) -> list[dict]:
    path = OUTPUT / board
    return json.loads(path.read_text()) if path.exists() else []


def _save(board: str, cards: list[dict]) -> None:
    (OUTPUT / board).write_text(json.dumps(cards, indent=2) + "\n")


def apply_candidate(candidate: dict, score: dict, *, iter_num: int,
                    held_names: list[str]) -> str:
    """Apply one promoted scout candidate to its board. Returns the action."""
    ctype = candidate.get("type")
    board = BOARD_FOR_TYPE.get(ctype)
    if board is None:
        return "skipped_not_board_type"
    cards = _load(board)
    entity = candidate.get("entity") or {}
    name = (entity.get("name") or candidate.get("title", ""))[:80]
    held = any(h.lower() in name.lower() or name.lower() in h.lower()
               for h in held_names if h)

    dims = dict(score.get("dims", {}))
    if ctype == "adoption_target" and held:
        dims["channel_state"] = min(dims.get("channel_state", 0), 5)
    total = sum(v for v in dims.values() if isinstance(v, (int, float)))

    cid = candidate["id"]
    existing = next((c for c in cards if c["id"] == cid
                     or (name and c.get("entity", {}).get("name") == name
                         and c.get("kind") == KIND_FOR_TYPE[ctype])), None)
    if existing is not None:
        if existing.get("state") in ("terminal", "superseded"):
            return "skipped_terminal"  # terminal is terminal (rule 2g)
        if total > existing.get("scores", {}).get("total", -1):
            existing["scores"] = {"total": total, "dims": dims}
            existing.setdefault("history", []).append(
                {"ts": _now(), "iter": iter_num, "event": f"rescored -> {total}"})
            existing["evidence"] = (existing.get("evidence", [])
                                    + [{"url": u, "date": _now()[:10],
                                        "claim": candidate.get("claim", "")[:200],
                                        "verified_by": "websearch"}
                                       for u in candidate.get("evidence", [])
                                       if isinstance(u, str) and u.startswith("http")])
            _save(board, cards)
            return "rescored"
        return "unchanged_lower_score"

    card = {
        "id": cid,
        "kind": KIND_FOR_TYPE[ctype],
        "title": candidate.get("title", "")[:140],
        "entity": {"name": name, "repo": entity.get("repo"),
                   "tracked_id": entity.get("tracked_id"),
                   "urls": [u for u in candidate.get("evidence", [])
                            if isinstance(u, str) and u.startswith("http")]},
        "state": "hold" if held else "active",
        "hold_reason": "engagement-graph hold" if held else None,
        "evidence": [{"url": u, "date": _now()[:10],
                      "claim": candidate.get("claim", "")[:200],
                      "verified_by": "websearch"}
                     for u in candidate.get("evidence", [])
                     if isinstance(u, str) and u.startswith("http")],
        "scores": {"total": total, "dims": dims},
        "first_seen_iter": iter_num,
        "last_verified": _now(),
        "last_verified_method": "tier1",
        "history": [{"ts": _now(), "iter": iter_num, "event": "created"}],
        "superseded_by": None,
    }
    cards.append(card)
    _save(board, cards)
    return "created"


def apply_board_updates(board_entries: list[dict], *, iter_num: int,
                        held_names: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in board_entries:
        candidate = entry.get("candidate", entry)
        score = candidate.get("score", {})
        action = apply_candidate(candidate, score, iter_num=iter_num,
                                 held_names=held_names)
        counts[action] = counts.get(action, 0) + 1
    return counts


def new_cards_since(iter_num: int) -> int:
    n = 0
    for board in BOARD_FOR_TYPE.values():
        for c in _load(board):
            if c.get("first_seen_iter") == iter_num:
                n += 1
    return n
