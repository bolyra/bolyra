# CrewAI Delegation Flow Demo

Runnable demo of **BolyraDelegationFlow** — verifiable, least-privilege task
delegation for multi-agent CrewAI workflows.

Each agent in the crew receives only the permissions its task requires. Every
delegation is recorded as a cryptographic proof entry in an audit trail.

This is the outreach artifact for verifiable agent delegation: a single
`python demo.py` invocation shows the full flow without needing CrewAI
installed, a running Node.js process, or any external service.

## What the demo shows

1. A Manager session authenticated with three permissions
   (`read_data`, `write_data`, `financial_small`).
2. A Researcher agent delegated only `read_data`.
3. A Writer agent delegated `read_data` + `write_data`.
4. A printed audit trail — agent, task, permissions granted, timestamp, and
   delegation status for each entry.

Scope narrowing is one-way: delegated credentials can only drop permissions,
never expand them. That invariant is enforced by the `Delegation` Circom
circuit when running with a full Bolyra node.

## Install

```bash
pip install bolyra-crewai bolyra
```

Or run directly from the repo (no install needed):

```bash
cd examples/crewai-delegation
python demo.py
```

The script adds `../../integrations/crewai` and `../../sdk-python` to
`sys.path` automatically.

## Expected output

```
============================================================
  Bolyra CrewAI Delegation Flow Demo
  Verifiable least-privilege task delegation
============================================================

[1] Creating tools and session...
   Agent scopes:
     Manager: ['read_data', 'write_data', 'financial_small']
     Researcher: ['read_data']
     Writer: ['read_data', 'write_data']

[2] Authenticating as Manager...
   Auth result: mock
   (Dev mode -- continuing with mock session)

[3] Simulating crew task execution...

   --- Task: Research market data ---
   Agent: Researcher (read_data only)
   Task completed. Delegation recorded.

   --- Task: Write Q3 report ---
   Agent: Writer (read_data + write_data)
   Task completed. Delegation recorded.

[4] Delegation Audit Trail:
============================================================

  Entry 1:
    Agent:       Researcher
    Task:        Research market data for Q3 report
    Permissions: ['read_data']
    Timestamp:   2026-...
    Delegated:   True
    Status:      ok

  Entry 2:
    Agent:       Writer
    Task:        Write the Q3 market analysis report
    Permissions: ['read_data', 'write_data']
    Timestamp:   2026-...
    Delegated:   True
    Status:      ok

============================================================
  Total delegations: 2
  Each entry is a cryptographic record of what was authorized.
============================================================
```

## Going further

- `integrations/crewai/` — full `bolyra-crewai` package source
- `integrations/crewai/README.md` — CrewAI integration guide with real crew wiring
- `sdk-python/` — pure-Python SDK used by the tools
- `circuits/src/Delegation.circom` — on-chain enforcement of scope narrowing
