# Bolyra CrewAI Integration

> **Status: Working** — Requires Node.js >= 18 and `@bolyra/sdk` installed. Uses the Python SDK's subprocess bridge for ZKP proof generation.

Mutual ZKP authentication and delegation tools for CrewAI multi-agent workflows.

## Install

```bash
pip install crewai
npm install @bolyra/sdk && npx bolyra setup  # circuit artifacts
```

## Usage

```python
from bolyra.integrations.crewai import BolyraAuthTool, BolyraDelegateTool

# Dev mode (uses fixed-seed dev identities -- never for production):
auth = BolyraAuthTool(permissions=["read_data", "write_data"])
delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])

agent = Agent(
    role="Authenticated Analyst",
    tools=[auth, delegate],
    goal="Authenticate before accessing sensitive data"
)
```

CrewAI tools use the `_run()` interface. Errors from missing Node.js or SDK are returned as human-readable strings (never crash the CrewAI agent).
