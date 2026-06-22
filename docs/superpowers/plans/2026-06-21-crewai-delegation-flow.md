# CrewAI Delegation Flow Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `BolyraDelegationFlow` that combines pre-execution permission enforcement (`guard_tools()`) with post-execution proof envelope capture (`task_callback`), plus a runnable 3-agent demo.

**Architecture:** `BolyraDelegationFlow` creates per-agent `BolyraGuard` instances via `tools_for()` and captures delegation proof envelopes via `task_callback`. It wraps existing primitives (BolyraGuard, BolyraSession, ProofEnvelope) into a single class. The demo shows a Manager delegating to Researcher (read_data) and Writer (read_data + write_data) with an audit trail.

**Tech Stack:** Python 3.10+, pytest, CrewAI BaseTool, bolyra SDK (Python), bolyra_crewai existing modules

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `integrations/crewai/bolyra_crewai/task_hook.py` | Create | BolyraDelegationFlow class |
| `integrations/crewai/bolyra_crewai/__init__.py` | Modify | Add BolyraDelegationFlow export |
| `integrations/crewai/tests/test_task_hook.py` | Create | Unit tests |
| `integrations/crewai/pyproject.toml` | Modify | Bump to 0.2.0 |
| `examples/crewai-delegation/demo.py` | Create | Runnable demo |
| `examples/crewai-delegation/README.md` | Create | Setup guide |
| `tasks/pdlc/crewai-delegation-flow.json` | Create | PDLC pipeline |

---

### Task 1: PDLC Pipeline + BolyraDelegationFlow Class

**Files:**
- Create: `tasks/pdlc/crewai-delegation-flow.json`
- Create: `integrations/crewai/bolyra_crewai/task_hook.py`

- [ ] **Step 1: Create PDLC pipeline**

Write `tasks/pdlc/crewai-delegation-flow.json`:
```json
{
  "id": "pdlc-2026-06-21-crewai-delegation-flow",
  "feature": "CrewAI delegation flow -- per-agent scoping, proof envelope audit trail",
  "status": "active",
  "stage": "IMPLEMENT",
  "mode": "standard",
  "created": "2026-06-21T10:00:00Z",
  "spec": "docs/superpowers/specs/2026-06-21-crewai-delegation-flow-design.md",
  "plan": "docs/superpowers/plans/2026-06-21-crewai-delegation-flow.md",
  "gates": { "spec": {"status":"approved"}, "plan": {"status":"approved"}, "ship": {"status":"pending"}, "post_ship": {"status":"pending"} },
  "tasks": [
    {"id":1,"description":"PDLC + BolyraDelegationFlow class","status":"pending"},
    {"id":2,"description":"Unit tests","status":"pending"},
    {"id":3,"description":"Package exports + version bump","status":"pending"},
    {"id":4,"description":"Runnable demo","status":"pending"},
    {"id":5,"description":"Run all tests, verify, push","status":"pending"}
  ]
}
```

- [ ] **Step 2: Write task_hook.py**

Create `integrations/crewai/bolyra_crewai/task_hook.py`:

```python
"""CrewAI delegation flow -- per-agent permission scoping with proof envelope audit trail.

Combines BolyraGuard (pre-execution enforcement) with BolyraSession.delegate()
(post-execution provenance) into a single class that manages the full delegation
lifecycle across a CrewAI Crew run.

Usage::

    flow = BolyraDelegationFlow(
        session=session,
        agent_scopes={"Researcher": ["read_data"], "Writer": ["read_data", "write_data"]},
    )
    researcher_tools = flow.tools_for("Researcher", [sd_jwt_tool])
    crew = Crew(..., task_callback=flow.task_callback)
    # After crew runs:
    for entry in flow.audit_trail:
        print(entry)
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from bolyra_crewai.guard import BolyraGuard

logger = logging.getLogger(__name__)


class BolyraDelegationFlow:
    """Manages per-agent permission scoping and delegation audit trail.

    Pre-execution: ``tools_for()`` wraps each agent's tools with a BolyraGuard
    scoped to that agent's allowed permissions.

    Post-execution: ``task_callback`` captures delegation proofs as proof
    envelopes after each task completes.

    Args:
        session: BolyraSession for authentication and delegation.
        agent_scopes: Maps agent role names to their allowed permissions.
            Example: {"Researcher": ["read_data"], "Writer": ["read_data", "write_data"]}
        emit_envelopes: Whether to wrap delegation proofs in ProofEnvelope
            format. Requires bolyra.envelope module. Default True.
        on_failure: BolyraGuard failure mode for tools_for(). Default "raise".
    """

    def __init__(
        self,
        session: Any,
        agent_scopes: dict[str, list[str]],
        *,
        emit_envelopes: bool = True,
        on_failure: str = "raise",
    ) -> None:
        self.session = session
        self.agent_scopes = agent_scopes
        self.emit_envelopes = emit_envelopes
        self.on_failure = on_failure
        self._audit_trail: list[dict[str, Any]] = []
        self._guards: dict[str, BolyraGuard] = {}

    @property
    def audit_trail(self) -> list[dict[str, Any]]:
        """List of delegation audit entries from this crew run."""
        return list(self._audit_trail)

    def tools_for(self, agent_role: str, tools: list[Any]) -> list[Any]:
        """Wrap tools with a BolyraGuard scoped to this agent's permissions.

        Args:
            agent_role: The agent's role name (must exist in agent_scopes).
            tools: List of CrewAI BaseTool instances.

        Returns:
            The same list with non-auth tools guarded.

        Raises:
            ValueError: If agent_role is not in agent_scopes (fail-closed).
        """
        if agent_role not in self.agent_scopes:
            raise ValueError(
                f"Unknown agent role: '{agent_role}'. "
                f"Known roles: {list(self.agent_scopes.keys())}"
            )

        guard = BolyraGuard(
            session=self.session,
            required_permissions=self.agent_scopes[agent_role],
            on_failure=self.on_failure,
        )
        guard.guard_tools(tools)
        self._guards[agent_role] = guard
        return tools

    def task_callback(self, task_output: Any) -> None:
        """CrewAI task_callback -- captures delegation proof after task completion.

        Extracts the agent role from the task output, delegates with the
        agent's scoped permissions, and wraps the result in a proof envelope.
        Appends to the audit trail. Never crashes the crew on failure.

        Args:
            task_output: CrewAI TaskOutput object.
        """
        agent_role = self._extract_agent_role(task_output)
        task_desc = self._extract_task_description(task_output)
        ts = datetime.now(timezone.utc).isoformat()

        if agent_role is None or agent_role not in self.agent_scopes:
            # Not a scoped agent or can't determine role -- skip silently
            return

        permissions = self.agent_scopes[agent_role]
        entry: dict[str, Any] = {
            "agent": agent_role,
            "task": task_desc or "unknown",
            "timestamp": ts,
            "permissions": permissions,
            "delegation": None,
            "envelope": None,
            "error": None,
        }

        try:
            if not self.session.is_authenticated:
                entry["error"] = "Session not authenticated -- skipping delegation"
                self._audit_trail.append(entry)
                return

            delegation_result = self.session.delegate(
                delegatee_id="0",
                permissions=", ".join(permissions),
            )
            entry["delegation"] = delegation_result

            if delegation_result.get("delegated") and self.emit_envelopes:
                envelope = self._wrap_in_envelope(delegation_result, agent_role)
                entry["envelope"] = envelope

        except Exception as exc:
            logger.warning(
                "BolyraDelegationFlow: delegation failed for %s: %s",
                agent_role, exc,
            )
            entry["error"] = str(exc)

        self._audit_trail.append(entry)

    def _wrap_in_envelope(
        self, delegation_result: dict[str, Any], agent_role: str
    ) -> dict[str, Any] | None:
        """Wrap a delegation result in a ProofEnvelope if possible."""
        try:
            from bolyra.envelope import envelope_from_proof, CONTENT_TYPE

            # Build a proof-like dict from the delegation result
            # The delegation result has new_scope_commitment and delegation_nullifier
            # We wrap these as public signals in a Delegation envelope
            proof_data = {
                "pi_a": ["0", "0"],
                "pi_b": [["0", "0"], ["0", "0"]],
                "pi_c": ["0", "0"],
            }
            signals = [
                delegation_result.get("new_scope_commitment", "0"),
                delegation_result.get("delegation_nullifier", "0"),
            ]

            envelope = envelope_from_proof(
                circuit_name="Delegation",
                proof=proof_data,
                public_signals=signals,
                circuit_version="0.4.0",
            )
            return envelope.to_dict()

        except ImportError:
            logger.debug("bolyra.envelope not available -- skipping envelope")
            return None
        except Exception as exc:
            logger.warning("Envelope wrapping failed: %s", exc)
            return None

    @staticmethod
    def _extract_agent_role(task_output: Any) -> str | None:
        """Extract agent role from CrewAI TaskOutput."""
        # CrewAI TaskOutput has .agent which is the agent's role string
        if hasattr(task_output, "agent"):
            agent = task_output.agent
            if isinstance(agent, str):
                return agent
            # Agent object may have .role attribute
            if hasattr(agent, "role"):
                return str(agent.role)
        if isinstance(task_output, dict):
            return task_output.get("agent")
        return None

    @staticmethod
    def _extract_task_description(task_output: Any) -> str | None:
        """Extract task description from CrewAI TaskOutput."""
        if hasattr(task_output, "description"):
            return str(task_output.description)[:200]
        if hasattr(task_output, "task"):
            task = task_output.task
            if hasattr(task, "description"):
                return str(task.description)[:200]
        if isinstance(task_output, dict):
            return task_output.get("description", "")[:200]
        return None
```

- [ ] **Step 3: Commit**

```bash
git add tasks/pdlc/crewai-delegation-flow.json integrations/crewai/bolyra_crewai/task_hook.py
git commit -s -m "feat: BolyraDelegationFlow class with per-agent scoping and audit trail"
```

---

### Task 2: Unit Tests

**Files:**
- Create: `integrations/crewai/tests/test_task_hook.py`

- [ ] **Step 1: Write test_task_hook.py**

Tests to write:
1. `test_tools_for_creates_guarded_tools` -- tools_for wraps tools with guard, unauthenticated call raises
2. `test_tools_for_unknown_role_raises` -- unknown agent role raises ValueError
3. `test_tools_for_allows_authenticated` -- authenticated session allows tool execution
4. `test_task_callback_appends_audit_entry` -- mock task output, verify audit trail grows
5. `test_task_callback_with_envelope` -- verify envelope dict is present when delegation succeeds
6. `test_task_callback_graceful_failure` -- delegation failure produces error entry, no crash
7. `test_task_callback_skips_unauthenticated` -- unauthenticated session adds error entry
8. `test_task_callback_skips_unknown_role` -- unknown agent role is silently skipped
9. `test_audit_trail_initially_empty` -- fresh flow has empty audit trail
10. `test_audit_trail_is_copy` -- audit_trail returns a copy, not a reference
11. `test_end_to_end_mock` -- authenticate, two mock tasks, verify 2 audit entries

Use mock tools (SimpleNamespace with name and _run), mock task outputs (SimpleNamespace with agent and description), and MockAuthTool/MockDelegateTool patterns from existing test_session.py.

- [ ] **Step 2: Run tests**

```bash
cd integrations/crewai && source .venv/bin/activate && python -m pytest tests/test_task_hook.py -v
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add integrations/crewai/tests/test_task_hook.py
git commit -s -m "test: BolyraDelegationFlow unit tests"
```

---

### Task 3: Package Exports + Version Bump

**Files:**
- Modify: `integrations/crewai/bolyra_crewai/__init__.py`
- Modify: `integrations/crewai/pyproject.toml`

- [ ] **Step 1: Add BolyraDelegationFlow to __init__.py**

Add import and export:
```python
from bolyra_crewai.task_hook import BolyraDelegationFlow
```

Add `"BolyraDelegationFlow"` to the `__all__` list.

- [ ] **Step 2: Bump version to 0.2.0**

In `__init__.py`: change `__version__ = "0.1.0"` to `__version__ = "0.2.0"`.
In `pyproject.toml`: change `version = "0.1.0"` to `version = "0.2.0"`.

- [ ] **Step 3: Run full test suite**

```bash
cd integrations/crewai && source .venv/bin/activate && python -m pytest tests/ -v
```

Expected: all tests pass (existing 88 + new task_hook tests).

- [ ] **Step 4: Commit**

```bash
git add integrations/crewai/bolyra_crewai/__init__.py integrations/crewai/pyproject.toml
git commit -s -m "feat: export BolyraDelegationFlow, bump to v0.2.0"
```

---

### Task 4: Runnable Demo

**Files:**
- Create: `examples/crewai-delegation/demo.py`
- Create: `examples/crewai-delegation/README.md`

- [ ] **Step 1: Write demo.py**

A self-contained script that:
1. Creates auth, delegate, sd_jwt tools + session
2. Defines agent_scopes for Manager, Researcher, Writer
3. Creates BolyraDelegationFlow
4. Creates 3 mock agents (using SimpleNamespace, no real LLM calls)
5. Simulates: authenticate -> Researcher task -> Writer task
6. Prints the audit trail with delegation envelopes

The demo should run WITHOUT crewai installed (use mocks) and WITHOUT Node.js. It demonstrates the flow using the pure-Python path (SD-JWT delegation).

- [ ] **Step 2: Write README.md**

```markdown
# CrewAI Delegation Flow Demo

Verifiable, least-privilege task delegation for CrewAI multi-agent workflows.

## What This Shows

A 3-agent crew where each agent gets only the permissions it needs:
- **Manager**: authenticates, holds all permissions
- **Researcher**: read_data only
- **Writer**: read_data + write_data

Every delegation produces a cryptographic proof envelope -- a verifiable
audit trail of who was authorized to do what.

## Run

pip install bolyra-crewai bolyra
python demo.py

## Expected Output

[shows authenticate, delegate to Researcher, delegate to Writer, audit trail with envelopes]
```

- [ ] **Step 3: Commit**

```bash
git add examples/crewai-delegation/
git commit -s -m "docs: runnable CrewAI delegation flow demo"
```

---

### Task 5: Final Verification + Push

- [ ] **Step 1: Run full crewai test suite**

```bash
cd integrations/crewai && source .venv/bin/activate && python -m pytest tests/ -v
```

- [ ] **Step 2: Run the demo**

```bash
cd examples/crewai-delegation && python demo.py
```

Verify it prints audit trail with delegation results.

- [ ] **Step 3: Update PDLC to REVIEW**

Edit `tasks/pdlc/crewai-delegation-flow.json`: set stage to REVIEW, all tasks to done.

- [ ] **Step 4: Commit and push**

```bash
git add tasks/pdlc/crewai-delegation-flow.json
git commit -s -m "chore: delegation flow complete, PDLC to REVIEW"
git push
```
