# CrewAI Delegation Flow -- Design Document

**Date:** 2026-06-21
**Author:** PDLC Orchestrator + Codex review
**Status:** APPROVED

## 1. Motivation

CrewAI crews delegate tasks between agents, but there's no way to enforce
that Agent B only gets the permissions it needs for its task, or to produce
a cryptographic audit trail of what was delegated and when. The existing
`BolyraDelegateTool` and `BolyraGuard` handle individual tool calls, but
don't address the task-level delegation flow.

`BolyraDelegationFlow` wires together three existing primitives:
- `BolyraGuard.guard_tools()` -- pre-execution permission enforcement
- `BolyraSession.delegate()` -- ZKP/SD-JWT scope narrowing
- `ProofEnvelope` -- standardized wire format for proof provenance

The result: one class that gives a CrewAI crew verifiable, least-privilege
task delegation with a proof envelope audit trail.

## 2. API

```python
from bolyra_crewai import (
    BolyraAuthTool, BolyraDelegateTool, BolyraSDJWTTool,
    BolyraGuard, BolyraSession, BolyraDelegationFlow,
)

# 1. Create tools + session
auth = BolyraAuthTool(permissions=["read_data", "write_data", "financial_small"])
delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data", "financial_small"])
sd_jwt = BolyraSDJWTTool()
session = BolyraSession(auth_tool=auth, delegate_tool=delegate, sd_jwt_tool=sd_jwt)

# 2. Define per-agent permission scopes
agent_scopes = {
    "Researcher": ["read_data"],
    "Writer": ["read_data", "write_data"],
    "Accountant": ["read_data", "financial_small"],
}

# 3. Create the delegation flow
flow = BolyraDelegationFlow(
    session=session,
    agent_scopes=agent_scopes,
)

# 4. Wire into crew
manager_tools = flow.tools_for("Manager", [auth, sd_jwt])
researcher_tools = flow.tools_for("Researcher", [sd_jwt])
writer_tools = flow.tools_for("Writer", [sd_jwt])

crew = Crew(
    agents=[manager, researcher, writer],
    tasks=[...],
    task_callback=flow.task_callback,
)

# 5. After crew runs, get the audit trail
for entry in flow.audit_trail:
    print(entry["agent"], entry["task"], entry["envelope"]["circuit"]["name"])
```

## 3. Components

### 3.1 `BolyraDelegationFlow` class

**Constructor:**
- `session: BolyraSession` -- authenticated session for delegation
- `agent_scopes: dict[str, list[str]]` -- maps agent role names to their
  allowed permissions. The flow enforces that each agent's tools are guarded
  to only these permissions.
- `emit_envelopes: bool = True` -- whether to wrap delegation proofs in
  proof envelopes (requires bolyra.envelope)

**Methods:**

- `tools_for(agent_role: str, tools: list) -> list` -- wraps the given tools
  with a `BolyraGuard` scoped to the agent's permissions from `agent_scopes`.
  Returns the guarded tool list. If the agent_role is not in agent_scopes,
  raises ValueError (fail-closed).

- `task_callback(task_output) -> None` -- CrewAI task_callback. After each
  task completes:
  1. Extracts the agent role from the task output
  2. Looks up the agent's scope in `agent_scopes`
  3. Calls `session.delegate()` with those permissions (scope narrowing)
  4. If `emit_envelopes` is True, wraps the delegation result in a
     `ProofEnvelope` and appends to the audit trail
  5. If delegation fails (SDK not available, dev mode, etc.), logs a warning
     and appends an error entry to the audit trail -- does NOT crash the crew

- `audit_trail: list[dict]` -- property returning the list of audit entries.
  Each entry has: `agent` (str), `task` (str), `timestamp` (str),
  `delegation` (dict or None), `envelope` (dict or None), `error` (str or None)

### 3.2 Integration with existing primitives

- `BolyraGuard`: `tools_for()` creates a new BolyraGuard per agent with
  `required_permissions` matching that agent's scope, then calls
  `guard.guard_tools()` on the tools. Pre-execution enforcement.

- `BolyraSession`: `task_callback` calls `session.delegate()` with the
  agent's scope. Post-execution provenance.

- `ProofEnvelope`: if `emit_envelopes=True` and the delegation produces a
  proof, wraps it via `envelope_from_proof()` from `bolyra.envelope`.
  If the envelope module is not available, falls back to raw delegation dict.

### 3.3 Runnable demo

`examples/crewai-delegation/demo.py`:

- 3 agents: Manager (all permissions), Researcher (read_data), Writer (read_data + write_data)
- 3 tasks: authenticate, research a topic, write a report
- Manager authenticates first, then tasks are delegated with scope narrowing
- Uses dev mode (no real ZKP circuits, auto-generated identities)
- Prints the audit trail at the end showing each delegation envelope
- `README.md` with install steps and expected output

## 4. Files

| File | Action |
|---|---|
| `integrations/crewai/bolyra_crewai/task_hook.py` | Create -- BolyraDelegationFlow class |
| `integrations/crewai/bolyra_crewai/__init__.py` | Modify -- add BolyraDelegationFlow export |
| `integrations/crewai/tests/test_task_hook.py` | Create -- unit tests |
| `integrations/crewai/pyproject.toml` | Modify -- bump to 0.2.0 |
| `examples/crewai-delegation/demo.py` | Create -- runnable demo |
| `examples/crewai-delegation/README.md` | Create -- setup guide |

## 5. Tests

- `tools_for` creates guarded tools that block unauthenticated calls
- `tools_for` with unknown agent role raises ValueError
- `task_callback` appends audit entry with delegation result
- `task_callback` wraps delegation in envelope when emit_envelopes=True
- `task_callback` gracefully handles delegation failure (error entry, no crash)
- `audit_trail` is empty initially, grows with each task
- End-to-end: authenticate, run two mock tasks, verify 2 audit entries with envelopes

## 6. Out of Scope

- Automatic permission inference from task descriptions (future LLM classification)
- Real ZKP proving in the demo (uses dev mode)
- CrewAI Flow API integration (newer API, separate adapter)
- Publishing to PyPI as v0.2.0 (separate /ship run)
