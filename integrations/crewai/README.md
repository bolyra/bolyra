# Bolyra CrewAI Integration

> **Status: Alpha (0.1.0)** -- Mutual ZKP authentication, scoped delegation, and SD-JWT tools for CrewAI multi-agent workflows.

## Install

```bash
pip install bolyra-crewai

# For ZKP tools (auth + delegate), also need Node.js bridge:
npm install @bolyra/sdk && npx bolyra setup
```

## Quick Start

```python
from crewai import Agent, Crew, Task
from bolyra_crewai import (
    BolyraAuthTool,
    BolyraDelegateTool,
    BolyraSDJWTTool,
    BolyraGuard,
    BolyraSession,
)

# 1. Create tools
auth = BolyraAuthTool(permissions=["read_data", "write_data"])
delegate = BolyraDelegateTool(agent_permissions=["read_data", "write_data"])
sd_jwt = BolyraSDJWTTool()

# 2. Create session + guard
session = BolyraSession(auth_tool=auth, delegate_tool=delegate, sd_jwt_tool=sd_jwt)
guard = BolyraGuard(session=session, on_failure="raise")

# 3. Wrap tools with pre-execution auth enforcement
analyst_tools = guard.guard_tools([auth, sd_jwt])
delegator_tools = guard.guard_tools([delegate])

# 4. Build agents
analyst = Agent(
    role="Authenticated Data Analyst",
    goal="Analyze data only after mutual ZKP authentication",
    tools=analyst_tools,
)

delegator = Agent(
    role="Delegation Manager",
    goal="Delegate scoped permissions to sub-agents",
    tools=delegator_tools,
)

# 5. Build crew
crew = Crew(
    agents=[analyst, delegator],
    tasks=[
        Task(
            description="Authenticate and analyze the dataset",
            expected_output="Analysis report",
            agent=analyst,
        ),
    ],
)
```

## Tools

### BolyraAuthTool

Mutual ZKP handshake authentication. Returns a JSON string with session nonce, scope commitment, and nullifiers.

```python
auth = BolyraAuthTool(
    permissions=["read_data", "write_data"],
    agent_model_hash="gpt-4o",        # optional
    operator_key="0xdeadbeef...",       # optional (dev mode if omitted)
    human_secret=12345,                # optional (dev mode if omitted)
    expiry_seconds=86400,              # credential validity
)
```

### BolyraDelegateTool

Scoped permission delegation with cryptographic scope narrowing. Permissions are passed as a comma-separated string.

```python
delegate = BolyraDelegateTool(
    agent_permissions=["read_data", "write_data", "financial_small"],
)

# CrewAI agent calls with:
# permissions="read_data, write_data"  (comma-separated string)
```

### BolyraSDJWTTool

Lightweight SD-JWT delegation (pure Python, no Node.js). Raw receipts are vaulted internally -- only JTI references appear in tool output.

```python
tool = BolyraSDJWTTool(dev_mode=True)  # auto-generates Ed25519 keys

# Production mode:
from bolyra.sd_jwt import generate_ed25519_keypair
issuer_priv, _ = generate_ed25519_keypair()
tool = BolyraSDJWTTool(
    issuer_private_key=issuer_priv,
    issuer_kid="my-key-1",
    dev_mode=False,
)
```

## BolyraGuard

Two enforcement modes:

**Pre-execution (recommended):** wraps tools so auth is checked *before* execution:

```python
guard = BolyraGuard(
    session=session,
    on_failure="raise",      # "raise" | "warn" | "skip"
    session_ttl_seconds=3600, # optional session expiry
)

# Wrap tools for pre-execution enforcement
tools = guard.guard_tools([auth, sd_jwt, delegate])

analyst = Agent(role="Analyst", tools=tools, ...)
crew = Crew(agents=[analyst], tasks=[...])
```

**Post-execution audit:** hooks into CrewAI's step callback (fires *after* each step):

```python
crew = Crew(..., step_callback=guard.step_callback)
```

## BolyraSession

Stateful session that chains handshake -> delegate -> SD-JWT flows. Thread-safe.

```python
session = BolyraSession(auth_tool=auth, delegate_tool=delegate, sd_jwt_tool=sd_jwt)

# Authenticate
result = session.authenticate(scope="my-app")

# Delegate (session_nonce + scope_commitment auto-injected)
result = session.delegate(delegatee_id="0xabc", permissions="read_data")

# Authorize via SD-JWT
result = session.authorize(action="read", audience="api.example.com")

# Reset
session.reset()
```

## Security

- **Receipt vaulting**: Raw SD-JWT bearer credentials never appear in tool output (which flows through the LLM context). Only JTI references are returned.
- **Dev mode guard**: Set `BOLYRA_ENV=production` to block dev-mode auto-generated identities.
- **Scope narrowing**: Delegation enforces one-way narrowing at both the SDK and circuit level.
- **Nonce binding**: Every handshake commits to a fresh session nonce. Replay requires rebinding.
- **Canonical nonce format**: `(unix_seconds << 64) | os.urandom(8)` for dev-mode SD-JWT nonces.

## Non-Monorepo Setup

If you installed `bolyra` from PyPI (not from the monorepo checkout), the Python SDK needs to know where the Node.js `@bolyra/sdk` package lives:

```bash
export BOLYRA_NODE_SDK_PATH=/path/to/node_modules/@bolyra/sdk
```

Inside the monorepo, the SDK auto-discovers `../sdk` and no configuration is needed.

## License

Apache-2.0. See [LICENSE](LICENSE).
