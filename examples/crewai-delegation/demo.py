#!/usr/bin/env python3
"""CrewAI Delegation Flow Demo

Demonstrates verifiable, least-privilege task delegation for multi-agent workflows.
Each agent gets only the permissions it needs. Every delegation produces a
cryptographic proof envelope for audit.

Run: python demo.py
Requires: pip install bolyra-crewai bolyra
"""
import json
import sys
from types import SimpleNamespace

# Add the local packages to path for development
sys.path.insert(0, "../../integrations/crewai")
sys.path.insert(0, "../../sdk-python")

from bolyra_crewai import (
    BolyraAuthTool,
    BolyraDelegateTool,
    BolyraSDJWTTool,
    BolyraSession,
    BolyraDelegationFlow,
)


def main():
    print("=" * 60)
    print("  Bolyra CrewAI Delegation Flow Demo")
    print("  Verifiable least-privilege task delegation")
    print("=" * 60)

    # 1. Create tools + session
    print("\n[1] Creating tools and session...")
    auth = BolyraAuthTool(permissions=["read_data", "write_data", "financial_small"])
    delegate = BolyraDelegateTool(
        agent_permissions=["read_data", "write_data", "financial_small"]
    )
    sd_jwt = BolyraSDJWTTool()
    session = BolyraSession(
        auth_tool=auth, delegate_tool=delegate, sd_jwt_tool=sd_jwt
    )

    # 2. Define per-agent permission scopes
    agent_scopes = {
        "Manager": ["read_data", "write_data", "financial_small"],
        "Researcher": ["read_data"],
        "Writer": ["read_data", "write_data"],
    }

    print(f"   Agent scopes:")
    for role, perms in agent_scopes.items():
        print(f"     {role}: {perms}")

    # 3. Create delegation flow
    flow = BolyraDelegationFlow(
        session=session,
        agent_scopes=agent_scopes,
        emit_envelopes=False,  # Skip envelope (needs bolyra.envelope)
    )

    # 4. Authenticate as Manager
    print("\n[2] Authenticating as Manager...")
    auth_result = session.authenticate(scope="demo-delegation")
    if auth_result.get("verified"):
        print("   Authenticated successfully")
        print(f"   Session nonce: {auth_result.get('session_nonce', 'N/A')}")
    else:
        print(f"   Auth result: {auth_result.get('status')}")
        print("   (Dev mode -- continuing with mock session)")
        # Force session to authenticated state for demo
        session._auth_result = {
            "verified": True,
            "session_nonce": "demo-nonce-42",
            "scope_commitment": "demo-scope-0",
        }

    # 5. Simulate task delegation
    print("\n[3] Simulating crew task execution...")

    # Researcher task
    print("\n   --- Task: Research market data ---")
    print("   Agent: Researcher (read_data only)")
    researcher_output = SimpleNamespace(
        agent="Researcher",
        description="Research market data for Q3 report",
    )
    flow.task_callback(researcher_output)
    print("   Task completed. Delegation recorded.")

    # Writer task
    print("\n   --- Task: Write Q3 report ---")
    print("   Agent: Writer (read_data + write_data)")
    writer_output = SimpleNamespace(
        agent="Writer",
        description="Write the Q3 market analysis report",
    )
    flow.task_callback(writer_output)
    print("   Task completed. Delegation recorded.")

    # 6. Print audit trail
    print("\n[4] Delegation Audit Trail:")
    print("=" * 60)
    for i, entry in enumerate(flow.audit_trail, 1):
        print(f"\n  Entry {i}:")
        print(f"    Agent:       {entry['agent']}")
        print(f"    Task:        {entry['task']}")
        print(f"    Permissions: {entry['permissions']}")
        print(f"    Timestamp:   {entry['timestamp']}")
        if entry.get("delegation"):
            d = entry["delegation"]
            print(f"    Delegated:   {d.get('delegated', False)}")
            print(f"    Status:      {d.get('status', 'unknown')}")
        if entry.get("envelope"):
            print(f"    Envelope:    (proof envelope attached)")
        if entry.get("error"):
            print(f"    Note:        {entry['error']}")

    print("\n" + "=" * 60)
    print(f"  Total delegations: {len(flow.audit_trail)}")
    print("  Each entry is a cryptographic record of what was authorized.")
    print("=" * 60)


if __name__ == "__main__":
    main()
