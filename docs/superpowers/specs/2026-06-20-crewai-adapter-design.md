# CrewAI Adapter for Bolyra -- Design Document

**PDLC ID:** pdlc-2026-06-20-crewai-adapter
**Date:** 2026-06-20
**Author:** PDLC Orchestrator
**Status:** DRAFT

## 1. Motivation

CrewAI is a popular Python multi-agent framework where Agents have roles, goals, and tools, and Crews orchestrate multiple agents cooperatively. The Bolyra monorepo already has a bare-bones stub at `integrations/crewai/` with `BolyraAuthTool` and `BolyraDelegateTool`, but these are plain Python classes -- not proper CrewAI `BaseTool` subclasses. They lack SD-JWT support, have no guard/callback mechanism, no proper package structure, and cannot be published to PyPI.

This adapter brings CrewAI to the same maturity level as:
- `bolyra-langchain` (0.1.0) -- 3 BaseTool subclasses + BolyraSession + types
- `bolyra-agents` (0.1.0) -- BolyraAuthGuardrail + BolyraToolWrapper + MCP auth

## 2. Scope

### In Scope

1. **`BolyraAuthTool(BaseTool)`** -- CrewAI BaseTool subclass for mutual ZKP handshake
2. **`BolyraDelegateTool(BaseTool)`** -- CrewAI BaseTool subclass for scoped delegation
3. **`BolyraSDJWTTool(BaseTool)`** -- SD-JWT delegation (pure Python, no Node.js)
4. **`BolyraGuard`** -- CrewAI step callback that verifies auth before any tool execution
5. **`BolyraSession`** -- Stateful session bridging handshake -> delegate flows
6. **Shared types** -- `AuthResult`, `DelegationResult`, `SDJWTResult` dataclasses
7. **Compat shim** -- Graceful handling of CrewAI import availability
8. **`pyproject.toml`** -- Hatchling build, PyPI-ready as `bolyra-crewai`
9. **Tests** -- Unit tests with pytest, matching the LangChain/agents adapter patterns
10. **README.md** -- Usage examples with Agent/Crew/Task patterns

### Out of Scope

- MCP server auth integration for CrewAI (CrewAI does not have a native MCP transport)
- CrewAI Flow integration (newer API, separate future adapter)
- Async `_arun` -- CrewAI uses sync tool execution via `_run()` only (as of crewai 0.x)

## 3. Architecture

### 3.1 Package Structure

```
integrations/crewai/
  bolyra_crewai/
    __init__.py          # Public API exports
    _compat.py           # CrewAI import shim (BaseTool, etc.)
    types.py             # AuthResult, DelegationResult, SDJWTResult
    auth_tool.py         # BolyraAuthTool(BaseTool)
    delegate_tool.py     # BolyraDelegateTool(BaseTool)
    sd_jwt_tool.py       # BolyraSDJWTTool(BaseTool)
    guard.py             # BolyraGuard (step callback)
    session.py           # BolyraSession (stateful auth -> delegate chaining)
  tests/
    __init__.py
    conftest.py          # Shared fixtures
    test_auth_tool.py
    test_delegate_tool.py
    test_sd_jwt_tool.py
    test_guard.py
    test_session.py
    test_types.py
  pyproject.toml
  README.md
  LICENSE                # Apache-2.0
  NOTICE
```

The existing stub files (`bolyra_auth_tool.py`, `bolyra_delegate_tool.py`, `test_crewai_tools.py`, `__init__.py`) will be **replaced** by the new package structure. The old import path `integrations.crewai.bolyra_auth_tool` is dead code (not used by any other module in the monorepo).

### 3.2 CrewAI BaseTool Integration

CrewAI tools extend `crewai.tools.BaseTool` which requires:
- `name: str` class attribute
- `description: str` class attribute
- `args_schema: type[BaseModel]` -- Pydantic v2 model for tool inputs
- `_run(self, **kwargs) -> str` -- synchronous execution (CrewAI convention: returns string)

Key difference from LangChain: CrewAI tools return **strings** (not dicts). The LLM agent reads the string output directly. Our tools will return structured JSON strings via `json.dumps()` on the result dataclass `.to_dict()` output. This matches what CrewAI expects while preserving structured data.

### 3.3 BolyraAuthTool

Mirrors the LangChain `BolyraAuthTool` but adapted for CrewAI:

```python
class BolyraAuthInput(BaseModel):
    scope: str = Field(default="bolyra-handshake-v1", ...)
    required_permissions: list[str] = Field(default_factory=lambda: ["read_data"], ...)

class BolyraAuthTool(BaseTool):
    name: str = "bolyra_authenticate"
    description: str = "Perform mutual ZKP authentication..."
    args_schema: type[BaseModel] = BolyraAuthInput

    # Config fields
    agent_model_hash: str = "default"
    operator_key: str | None = None
    permissions: list[str] = ["read_data"]
    expiry_seconds: int = 86400
    human_secret: int | None = None

    def _run(self, scope: str = ..., required_permissions: list[str] | None = ...) -> str:
        # Same logic as LangChain auth_tool._run, but returns json.dumps(result.to_dict())
```

### 3.4 BolyraDelegateTool

```python
class BolyraDelegateInput(BaseModel):
    delegatee_id: str = Field(...)
    permissions: str = Field(description="Comma-separated permissions to delegate")
    expiry_seconds: int = Field(default=3600, ...)
    session_nonce: str = Field(default="0", ...)
    scope_commitment: str = Field(default="0", ...)

class BolyraDelegateTool(BaseTool):
    name: str = "bolyra_delegate"
    description: str = "Delegate a subset of permissions..."
    args_schema: type[BaseModel] = BolyraDelegateInput

    agent_permissions: list[str] = ["read_data"]
    operator_key: str | None = None

    def _run(self, ...) -> str:
        # Scope escalation check, then delegate + verify
```

Note: `permissions` input is a comma-separated string (not list) because CrewAI LLM agents are more reliable at producing single string arguments than JSON arrays. The tool splits on commas internally.

### 3.5 BolyraSDJWTTool

Pure-Python SD-JWT delegation. No Node.js or ZKP circuit required. Mirrors the LangChain `BolyraSDJWTTool`:

```python
class BolyraSDJWTInput(BaseModel):
    action: str = Field(description="Action to authorize")
    audience: str = Field(description="Tool or service identifier")
    permission: str = Field(default="READ_DATA", ...)
    max_amount: float | None = Field(default=None, ...)
    currency: str = Field(default="USD", ...)
    nonce: str | None = Field(default=None, ...)

class BolyraSDJWTTool(BaseTool):
    name: str = "bolyra_authorize"
    description: str = "Issue SD-JWT delegation receipt..."
    args_schema: type[BaseModel] = BolyraSDJWTInput

    # Same security pattern as LangChain: vault receipts, return JTI only
    _receipt_vault: dict[str, str] = {}

    def _run(self, action, audience, ...) -> str:
        # Uses bolyra.sd_jwt.allow() + present()
        # Vault the bearer credential, return JTI reference
```

Security invariant: raw SD-JWT receipts never appear in tool output (which flows through the LLM context). Only a JTI reference is returned. `get_receipt(jti)` provides out-of-band retrieval.

### 3.6 BolyraGuard

CrewAI's callback mechanism. CrewAI provides `step_callback` on the `Crew` constructor and `before_tool` / `after_tool` callbacks. The `BolyraGuard` hooks into the step callback to verify that a valid Bolyra auth session exists before any tool execution in the crew.

```python
class BolyraGuard:
    """Callback guard that verifies Bolyra auth before tool execution.

    Usage:
        guard = BolyraGuard(required_permissions=["read_data"])
        crew = Crew(
            agents=[...],
            tasks=[...],
            step_callback=guard.step_callback,
        )
    """

    def __init__(
        self,
        required_permissions: list[str] | None = None,
        session: BolyraSession | None = None,
        allow_unauthenticated_tools: list[str] | None = None,
        on_failure: str = "raise",  # "raise" | "warn" | "skip"
    ):
        self.required_permissions = required_permissions or ["read_data"]
        self.session = session
        self.allow_unauthenticated_tools = allow_unauthenticated_tools or ["bolyra_authenticate"]
        self.on_failure = on_failure

    def step_callback(self, step_output) -> None:
        """CrewAI step callback -- verifies auth state.

        Called after each step. If the step involved a tool invocation
        and the session is not authenticated, takes the configured
        on_failure action.
        """
        # Check if step involved a tool call
        # If tool is in allow_unauthenticated_tools, skip check
        # If session is not authenticated, trigger failure action
```

The guard distinguishes between:
- `"raise"` -- raises `BolyraAuthError`, stopping the crew
- `"warn"` -- logs a warning but allows execution to continue
- `"skip"` -- silently skips auth check (for dev/testing)

### 3.7 BolyraSession

Same pattern as the LangChain `BolyraSession` -- stateful auth context that chains handshake -> delegate flows:

```python
class BolyraSession:
    def __init__(self, auth_tool, delegate_tool=None, sd_jwt_tool=None): ...

    @property
    def is_authenticated(self) -> bool: ...
    @property
    def session_nonce(self) -> str | None: ...
    @property
    def scope_commitment(self) -> str | None: ...

    def authenticate(self, scope="bolyra-handshake-v1", ...) -> dict: ...
    def delegate(self, delegatee_id, permissions, ...) -> dict: ...
    def authorize(self, action, audience, ...) -> dict: ...  # SD-JWT
    def reset(self) -> None: ...
```

### 3.8 Compat Shim

```python
# _compat.py
try:
    from crewai.tools import BaseTool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    BaseTool = None

def check_crewai_available() -> None:
    if not CREWAI_AVAILABLE:
        raise ImportError("crewai is required. Install with: pip install crewai")
```

### 3.9 Types

Reuse the same `AuthResult`, `DelegationResult`, `SDJWTResult` dataclass pattern from the LangChain adapter. The `to_dict()` method provides the structured output; the tools wrap it with `json.dumps()` for CrewAI string return.

## 4. Package Configuration

```toml
[project]
name = "bolyra-crewai"
version = "0.1.0"
description = "CrewAI tools for Bolyra mutual ZKP authentication and SD-JWT delegation"
license = "Apache-2.0"
requires-python = ">=3.10"
authors = [{ name = "Bolyra", email = "sdk@bolyra.ai" }]
dependencies = [
    "bolyra>=0.5.0",
    "crewai>=0.50.0",
    "PyJWT[crypto]>=2.8.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "ruff>=0.4"]
```

`crewai` is a hard dependency (not peer) because pip does not have peer dependencies. The `>=0.50.0` floor matches the version when `BaseTool` stabilized with Pydantic v2 `args_schema`.

## 5. Differences from LangChain Adapter

| Aspect | LangChain | CrewAI |
|--------|-----------|--------|
| Base class | `langchain_core.tools.BaseTool` | `crewai.tools.BaseTool` |
| Return type | `dict[str, Any]` | `str` (JSON-serialized) |
| Async | `_arun()` supported | Sync-only `_run()` |
| Callbacks | `run_manager: CallbackManagerForToolRun` | `step_callback` on Crew |
| Guard pattern | N/A (no built-in guardrail) | `BolyraGuard.step_callback` |
| Session | `BolyraSession` (same) | `BolyraSession` (same pattern) |
| Permissions input | `list[str]` field | `str` comma-separated (LLM reliability) |

## 6. Security Considerations

1. **SD-JWT receipt vaulting** -- raw bearer credentials never in tool output
2. **Dev mode isolation** -- dev mode uses fixed-seed identities; production requires explicit operator keys
3. **Scope narrowing enforcement** -- delegation tools enforce one-way narrowing at the SDK level and the circuit level
4. **Nonce binding** -- every handshake commits to a fresh session nonce; replaying proofs without rebinding fails verification
5. **BolyraGuard failure mode** -- default is `"raise"` (fail-closed). `"warn"` and `"skip"` must be explicitly opted into.

No new auth, nonce, or payment surfaces are introduced. The adapter wraps existing Bolyra SDK functions.

## 7. Testing Strategy

- **Unit tests** -- mock the bolyra SDK imports, test tool metadata, input validation, scope escalation rejection, missing SDK graceful errors
- **Integration tests** -- require Node.js + @bolyra/sdk, marked with `@pytest.mark.skipif` when unavailable
- **Guard tests** -- test all three failure modes (raise, warn, skip), test allow-list bypass
- **Session tests** -- test auth -> delegate chaining, test reset, test unauthenticated delegation rejection

Test command: `cd ~/Projects/bolyra/integrations/crewai && python -m pytest tests/ -v`

## 8. Migration from Existing Stub

The existing files at `integrations/crewai/` will be replaced:
- `__init__.py` -- replaced with new package init
- `bolyra_auth_tool.py` -- logic migrated into `bolyra_crewai/auth_tool.py`
- `bolyra_delegate_tool.py` -- logic migrated into `bolyra_crewai/delegate_tool.py`
- `test_crewai_tools.py` -- replaced with `tests/` directory

No other modules in the monorepo import from `integrations.crewai`, so this is a clean replacement.
