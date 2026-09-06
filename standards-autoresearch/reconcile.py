"""Stage 0a: ground-truth reconciliation. NO LLM calls.

Runs FIRST, unconditionally, every iteration (program.md rule 2h). Verifies
every tracked entity and every board card against live state via gh api,
the IETF datatracker JSON API, and npm. Terminal states are terminal;
unreachable checks produce `stale` stubs, never exceptions. Every check is
logged to history/reconcile_log.jsonl. Board totals are recomputed from
reconciled truth, never accumulated.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "sources" / "tracked_entities.json"
OUTPUT = HERE / "output"
RECONCILE_LOG = HERE / "history" / "reconcile_log.jsonl"

BOARDS = ("threat_board.json", "adoption_board.json")
TERMINAL_STATES = {"terminal", "superseded"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log(row: dict[str, Any]) -> None:
    RECONCILE_LOG.parent.mkdir(parents=True, exist_ok=True)
    row["ts"] = _now()
    with RECONCILE_LOG.open("a") as f:
        f.write(json.dumps(row) + "\n")


def _run(cmd: list[str], *, timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"binary not found: {e}"


# ---------------------------------------------------------------- checkers

def check_gh_repo(entity: dict) -> dict:
    repo = entity["repo"]
    code, out, err = _run(["gh", "api", f"repos/{repo}",
                           "--jq", "{pushed_at, archived, stargazers_count, open_issues_count}"])
    if code != 0:
        return {"error": err.strip()[:300] or "gh api failed"}
    d = json.loads(out)
    state = "terminal" if d.get("archived") else "active"
    return {"state": state, "pushed_at": d.get("pushed_at"),
            "stars": d.get("stargazers_count"), "open_issues": d.get("open_issues_count")}


def check_gh_pr(entity: dict) -> dict:
    repo, num = entity["repo"], entity["number"]
    code, out, err = _run(["gh", "api", f"repos/{repo}/pulls/{num}",
                           "--jq", "{state, merged, updated_at}"])
    if code != 0:
        return {"error": err.strip()[:300] or "gh api failed"}
    d = json.loads(out)
    if d.get("merged"):
        return {"state": "terminal", "detail": "merged", "updated_at": d.get("updated_at")}
    if d.get("state") == "closed":
        return {"state": "terminal", "detail": "closed_unmerged", "updated_at": d.get("updated_at")}
    return {"state": "active", "updated_at": d.get("updated_at")}


def check_gh_issue(entity: dict) -> dict:
    repo, num = entity["repo"], entity["number"]
    code, out, err = _run(["gh", "api", f"repos/{repo}/issues/{num}",
                           "--jq", "{state, comments, updated_at}"])
    if code != 0:
        return {"error": err.strip()[:300] or "gh api failed"}
    d = json.loads(out)
    state = "terminal" if d.get("state") == "closed" else "active"
    return {"state": state, "comments": d.get("comments"), "updated_at": d.get("updated_at")}


def check_datatracker(entity: dict) -> dict:
    name = entity["name"]
    url = f"https://datatracker.ietf.org/api/v1/doc/document/{name}/?format=json"
    code, out, err = _run(["curl", "-sf", "--max-time", "20", url])
    if code != 0:
        return {"error": err.strip()[:300] or f"datatracker unreachable ({code})"}
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return {"error": "datatracker returned non-JSON"}
    # Terminal classification (program.md rule 2g): an expired or replaced
    # draft is terminal, not active.
    state, detail = "active", None
    expires = d.get("expires")
    if expires:
        try:
            exp_dt = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < datetime.now(timezone.utc):
                state, detail = "terminal", "expired"
        except ValueError:
            pass  # unparseable expiry: leave active, surface the raw value
    states_field = " ".join(str(s) for s in (d.get("states") or []))
    if "repl" in states_field or d.get("rfc"):
        state, detail = "terminal", "replaced_or_published"
    result = {"state": state, "rev": d.get("rev"), "expires": expires,
              "pages": d.get("pages")}
    if detail:
        result["detail"] = detail
    return result


def check_npm(entity: dict) -> dict:
    pkg = entity["name"]
    code, out, err = _run(["npm", "view", pkg, "version"], timeout=45)
    if code != 0:
        return {"error": err.strip()[:300] or "npm view failed"}
    return {"state": "active", "version": out.strip()}


CHECKERS = {
    "gh_repo": check_gh_repo,
    "gh_pr": check_gh_pr,
    "gh_issue": check_gh_issue,
    "datatracker": check_datatracker,
    "npm": check_npm,
}


# ---------------------------------------------------------------- reconcile

def reconcile_entities() -> list[dict]:
    """Check every tracked entity; return result rows (also logged)."""
    data = json.loads(SOURCES.read_text())
    rows: list[dict] = []
    for group, entities in data.items():
        for entity in entities:
            method = entity.get("check", "")
            checker = CHECKERS.get(method)
            if checker is None:
                result = {"error": f"unknown check method: {method}"}
            else:
                result = checker(entity)
            row = {"group": group, "id": entity["id"], "method": method, "result": result}
            _log(row)
            rows.append(row)
    return rows


def reconcile_boards(entity_rows: list[dict]) -> dict[str, Any]:
    """Update board cards from reconciled entity truth. Recompute totals."""
    by_id = {r["id"]: r for r in entity_rows}
    summary: dict[str, Any] = {}
    for board_name in BOARDS:
        path = OUTPUT / board_name
        if not path.exists():
            summary[board_name] = {"cards": 0}
            continue
        cards = json.loads(path.read_text())
        changed = 0
        for card in cards:
            if card.get("state") in TERMINAL_STATES:
                continue  # terminal is terminal (rule 2g)
            ent_id = card.get("entity", {}).get("tracked_id")
            row = by_id.get(ent_id) if ent_id else None
            if row is None:
                continue
            result = row["result"]
            if "error" in result:
                if card.get("state") != "stale":
                    card["state"] = "stale"
                    card.setdefault("history", []).append(
                        {"ts": _now(), "event": f"stale: {result['error'][:120]}"})
                    changed += 1
                continue
            live_state = result.get("state", "active")
            if live_state == "terminal" and card.get("state") != "terminal":
                card["state"] = "terminal"
                card.setdefault("history", []).append(
                    {"ts": _now(), "event": f"terminal: {result.get('detail', 'live check')}"})
                changed += 1
            elif live_state == "active" and card.get("state") == "stale":
                card["state"] = "active"
                card.setdefault("history", []).append({"ts": _now(), "event": "recovered from stale"})
                changed += 1
            card["last_verified"] = _now()
            card["last_verified_method"] = row["method"]
        path.write_text(json.dumps(cards, indent=2) + "\n")
        summary[board_name] = {
            "cards": len(cards),
            "active": sum(1 for c in cards if c.get("state") == "active"),
            "hold": sum(1 for c in cards if c.get("state") == "hold"),
            "stale": sum(1 for c in cards if c.get("state") == "stale"),
            "terminal": sum(1 for c in cards if c.get("state") in TERMINAL_STATES),
            "changed": changed,
        }
    return summary


def run_reconcile(output_dir: Path | None = None) -> dict[str, Any]:
    entity_rows = reconcile_entities()
    board_summary = reconcile_boards(entity_rows)
    errors = [r for r in entity_rows if "error" in r["result"]]
    result = {
        "entities_checked": len(entity_rows),
        "entities_stale": len(errors),
        "boards": board_summary,
        "entity_rows": entity_rows,
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "reconcile.json").write_text(json.dumps(result, indent=2))
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Stage 0a: ground-truth reconciliation")
    ap.add_argument("--dry-run", action="store_true",
                    help="Check entities and print results; do not touch boards")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args()

    if args.dry_run:
        rows = reconcile_entities()
        for r in rows:
            status = "STALE" if "error" in r["result"] else r["result"].get("state", "?")
            print(f"{status:9} {r['group']}/{r['id']:22} via {r['method']}: "
                  f"{json.dumps(r['result'])[:120]}")
        stale = sum(1 for r in rows if "error" in r["result"])
        print(f"\n{len(rows)} entities checked, {stale} stale")
        return 0

    out = run_reconcile(Path(args.output_dir) if args.output_dir else None)
    print(json.dumps({k: v for k, v in out.items() if k != "entity_rows"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
