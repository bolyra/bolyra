# Bolyra CrewAI Integration

Mutual ZKP authentication and delegation tools for CrewAI multi-agent workflows.

## Install

```bash
pip install crewai
npm install @bolyra/sdk && npx bolyra setup  # circuit artifacts
```

## Usage

```python
from bolyra.integrations.crewai import BolyraAuthTool, BolyraDelegateTool

auth = BolyraAuthTool(permissions=["read_data", "write_data"])
delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])

agent = Agent(
    role="Authenticated Analyst",
    tools=[auth, delegate],
    goal="Authenticate before accessing sensitive data"
)
```

CrewAI tools use `_run()` interface. Currently stubs pending `@bolyra/sdk` v0.2 circuit wiring.
