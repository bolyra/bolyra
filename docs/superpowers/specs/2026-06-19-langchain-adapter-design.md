# LangChain Adapter for Bolyra -- Design Spec

**PDLC:** `pdlc-2026-06-19-langchain-adapter`
**Date:** 2026-06-19
**Status:** Draft

---

## 1. Problem

The existing code at `integrations/langchain/` has working `BolyraAuthTool` and `BolyraDelegateTool` classes, but they are not real LangChain tools. They mimic the interface with custom `invoke`/`ainvoke` methods instead of subclassing `BaseTool`. They lack:

- Proper LangChain `BaseTool` inheritance (`_run`/`_arun` protocol)
- The SD-JWT delegation path (`@bolyra/delegation` allow/present/verify)
- LangChain callback integration (`run_manager`, `CallbackManagerForToolRun`)
- Installable package structure (`pip install bolyra-langchain`)
- Session state management for auth-then-delegate chains
- True async support (current `ainvoke` wraps sync)
- Middleware for automatic auth injection on agent executor chains

## 2. Goals

1. **Drop-in LangChain tools** -- subclass `BaseTool`, work with `create_react_agent`, `AgentExecutor`, LCEL chains, and LangGraph
2. **Dual auth paths** -- ZKP (via Python SDK subprocess bridge) and SD-JWT delegation (via `@bolyra/delegation` through a new Python wrapper)
3. **Installable package** -- `pip install bolyra-langchain` with `bolyra` and `langchain-core` as dependencies
4. **Session management** -- `BolyraSession` context manager that chains handshake -> delegate flows with state persistence across tool calls
5. **Callback integration** -- emit LangChain callbacks on auth events (handshake start/complete, delegation grant/verify)
6. **Async-first** -- proper `asyncio` subprocess calls for `_arun`, not just sync wrappers

## 3. Non-Goals

- Reimplementing ZKP proving in Python (stays as subprocess bridge)
- On-chain verification from Python (use the Node bridge or Solidity contracts)
- CrewAI adapter (separate package, separate pipeline)
- LangGraph-specific nodes (the tools work with LangGraph via standard tool protocol)

## 4. Architecture

### 4.1 Package Structure

```
integrations/langchain/
  pyproject.toml              # bolyra-langchain package
  README.md                   # Updated with real examples
  bolyra_langchain/
    __init__.py               # Public API exports
    auth_tool.py              # BolyraAuthTool(BaseTool)
    delegate_tool.py          # BolyraDelegateTool(BaseTool)
    sd_jwt_tool.py            # BolyraSDJWTTool(BaseTool) -- SD-JWT delegation
    session.py                # BolyraSession context manager
    callbacks.py              # BolyraCallbackHandler
    types.py                  # Shared types (AuthResult, DelegationResult, etc.)
    _compat.py                # LangChain version compatibility shims
  tests/
    __init__.py
    test_auth_tool.py
    test_delegate_tool.py
    test_sd_jwt_tool.py
    test_session.py
    test_callbacks.py
    conftest.py               # Shared fixtures (dev identities, skip markers)
  examples/
    basic_auth.py             # Minimal: agent with auth tool
    delegation_chain.py       # Auth -> delegate -> sub-agent
    sd_jwt_receipt.py         # SD-JWT delegation without ZKP
```

### 4.2 Dependency Graph

```
bolyra-langchain
  -> bolyra (Python SDK, >=0.4.0)
  -> langchain-core (>=0.2.0)
  -> pyjwt[crypto] (>=2.8.0, for SD-JWT path)
```

`langchain-core` (not `langchain`) is the minimal dependency. This gives us `BaseTool`, `CallbackManagerForToolRun`, and the Pydantic integration without pulling in the full LangChain stack.

### 4.3 Tool Design

#### 4.3.1 BolyraAuthTool (ZKP Mutual Handshake)

```python
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

class BolyraAuthInput(BaseModel):
    scope: str = Field(default="bolyra-handshake-v1")
    required_permissions: list[str] = Field(default_factory=lambda: ["read_data"])

class BolyraAuthTool(BaseTool):
    name: str = "bolyra_authenticate"
    description: str = (
        "Perform mutual ZKP authentication with a human or AI agent. "
        "Returns nullifiers and scope commitment for downstream delegation."
    )
    args_schema: type[BaseModel] = BolyraAuthInput

    # Configuration (set at init, not per-invocation)
    agent_model_hash: str = "default"
    operator_key: str | None = None
    permissions: list[str] = ["read_data"]
    expiry_seconds: int = 86400
    human_secret: int | None = None

    # Internal state
    _session: BolyraSession | None = None

    def _run(self, scope: str = "bolyra-handshake-v1",
             required_permissions: list[str] | None = None,
             run_manager: CallbackManagerForToolRun | None = None) -> dict:
        ...

    async def _arun(self, scope: str = "bolyra-handshake-v1",
                    required_permissions: list[str] | None = None,
                    run_manager: AsyncCallbackManagerForToolRun | None = None) -> dict:
        ...
```

Key changes from stub:
- Subclasses `BaseTool` with `_run`/`_arun`
- Pydantic v2 model fields for configuration
- `run_manager` callback integration
- Returns structured `AuthResult` (converted to dict for LangChain)

#### 4.3.2 BolyraDelegateTool (ZKP Delegation)

Same pattern as auth tool but wraps `bolyra.delegation.delegate()`. The key improvement is session binding: the tool reads `session_nonce` and `scope_commitment` from a shared `BolyraSession` if one is active, instead of requiring them as explicit inputs every time.

#### 4.3.3 BolyraSDJWTTool (SD-JWT Delegation -- NEW)

This is the new tool that provides the simpler SD-JWT delegation path without requiring the full ZKP circuit machinery:

```python
class BolyraSDJWTInput(BaseModel):
    action: str = Field(description="Action to authorize, e.g. 'checkout.charge'")
    audience: str = Field(description="Tool or service identifier")
    permission: str = Field(default="READ_DATA")
    max_amount: float | None = Field(default=None, description="Cap per invocation")
    currency: str = Field(default="USD")

class BolyraSDJWTTool(BaseTool):
    name: str = "bolyra_authorize"
    description: str = (
        "Issue an SD-JWT delegation receipt authorizing this agent to perform "
        "a specific action. Lighter weight than ZKP auth -- no circuit proving "
        "required. Use for tool authorization in trusted environments."
    )
```

This tool wraps the `@bolyra/delegation` package's `allow()` / `present()` / `verify()` functions. Since the delegation package is TypeScript, this requires a new subprocess bridge in the Python SDK (or a standalone Node.js script). The design choice:

**Option A: Node subprocess bridge (like the ZKP path)**
- Pro: Reuses the existing bridge pattern from `bolyra._bridge`
- Pro: No Python JWT reimplementation
- Con: Requires Node.js even for the "simple" path

**Option B: Pure Python SD-JWT using PyJWT**
- Pro: No Node.js dependency for SD-JWT path
- Pro: Faster (no subprocess overhead)
- Con: Must reimplement the SD-JWT issuance/verification logic
- Con: Must maintain two implementations (TS + Python) in sync

**Decision: Option B (Pure Python) for SD-JWT, Option A (Bridge) for ZKP.**

The SD-JWT path is intentionally the "lightweight" alternative. Requiring Node.js for it defeats the purpose. PyJWT + Ed25519 (via `cryptography` lib) gives us everything needed:
- `allow()`: Sign a JWS with EdDSA, add `cnf` claim, append `~` (issuer-form SD-JWT)
- `present()`: Add KB-JWT with holder binding
- `verify()`: Verify issuer signature, check claims, verify KB-JWT binding

The Python implementation follows the same spec as the TS version but is standalone.

### 4.4 Session Management

```python
class BolyraSession:
    """Manages auth state across a chain of tool calls."""

    def __init__(self, auth_tool: BolyraAuthTool):
        self.auth_tool = auth_tool
        self.handshake_result: HandshakeResult | None = None
        self.delegation_chain: list[DelegationResult] = []

    @property
    def is_authenticated(self) -> bool: ...

    @property
    def scope_commitment(self) -> int | None: ...

    @property
    def session_nonce(self) -> int | None: ...

    async def authenticate(self, scope: str = "bolyra-handshake-v1") -> AuthResult: ...

    async def delegate(self, delegatee_id: str,
                       permissions: list[str],
                       expiry_seconds: int = 3600) -> DelegationResult: ...
```

The session is optional. Tools work standalone (pass explicit nonce/commitment) or session-bound (read from shared session). This matches how LangChain agents work: tools are typically stateless, but a session can be injected for multi-step flows.

### 4.5 Callback Integration

```python
class BolyraCallbackHandler(BaseCallbackHandler):
    """Emits LangChain callbacks on Bolyra auth events."""

    def on_bolyra_auth_start(self, scope: str, **kwargs) -> None: ...
    def on_bolyra_auth_complete(self, result: AuthResult, **kwargs) -> None: ...
    def on_bolyra_auth_error(self, error: Exception, **kwargs) -> None: ...
    def on_bolyra_delegate_start(self, delegatee: str, **kwargs) -> None: ...
    def on_bolyra_delegate_complete(self, result: DelegationResult, **kwargs) -> None: ...
```

These extend LangChain's callback protocol. The tools emit these via `run_manager.on_tool_start` / `on_tool_end` metadata, plus custom events for Bolyra-specific state transitions.

### 4.6 SD-JWT Python Implementation

A new module in the `bolyra` Python SDK (not in `bolyra-langchain`) provides the SD-JWT primitives:

```
sdk-python/bolyra/
  sd_jwt.py    # allow(), present(), verify() -- pure Python
```

This mirrors `@bolyra/delegation`'s API surface:
- `allow(opts, issuer_key)` -> `str` (SD-JWT issuer-form: `jws~`)
- `present(receipt, holder_private_key, opts)` -> `str` (presented: `jws~~kbjwt`)
- `verify(receipt, opts)` -> `VerifyResult`

Uses `PyJWT[crypto]` (which pulls in `cryptography` for Ed25519). The JWS format, claim names, `_sd_alg`, `typ` header, and KB-JWT binding all match the TS implementation exactly.

## 5. Public API Summary

```python
# Minimal usage (ZKP path)
from bolyra_langchain import BolyraAuthTool
tools = [BolyraAuthTool(permissions=["read_data"])]
agent = create_react_agent(llm, tools)

# SD-JWT delegation (no ZKP, no Node.js)
from bolyra_langchain import BolyraSDJWTTool
tools = [BolyraSDJWTTool(issuer_key=key)]
agent = create_react_agent(llm, tools)

# Session-managed chain
from bolyra_langchain import BolyraAuthTool, BolyraDelegateTool, BolyraSession
auth = BolyraAuthTool(permissions=["read_data", "write_data"])
delegate = BolyraDelegateTool()
session = BolyraSession(auth)
# Session auto-injects nonce/commitment into delegate tool
```

## 6. Security Considerations

1. **Dev mode is explicit** -- Tools use dev identities only when no operator key AND no human secret are provided. Production requires explicit key material.
2. **No key material in tool output** -- Auth results contain nullifiers and commitments (public values), never secrets or private keys.
3. **SD-JWT holder binding** -- The SD-JWT tool enforces KB-JWT holder binding. A receipt without a matching holder key fails verification.
4. **Scope narrowing** -- Delegation can only narrow permissions, enforced both by the Python pre-flight checks and the circuit/SD-JWT claim checks.
5. **Session isolation** -- Each `BolyraSession` instance is isolated. No shared global state between agent instances.

## 7. Testing Strategy

- **Unit tests (no Node.js):** Tool metadata, input validation, permission mapping, error paths, callback emission, SD-JWT issuance/verification (pure Python)
- **Integration tests (requires Node.js + @bolyra/sdk):** End-to-end ZKP handshake, delegation chain, session management
- **Skip markers:** Tests requiring Node.js are skip-marked when unavailable (existing pattern from the stub)
- **Test command:** `cd integrations/langchain && pytest -v tests/`

## 8. Migration from Stub

The existing stub files (`bolyra_auth_tool.py`, `bolyra_delegate_tool.py`, `test_langchain_tools.py`) will be replaced entirely. The new package structure under `bolyra_langchain/` supersedes the flat module layout. The `__init__.py` re-exports maintain the same public names (`BolyraAuthTool`, `BolyraDelegateTool`, `BolyraAuthInput`, `BolyraDelegateInput`) for any downstream code.

Old stub files will be deleted as part of the migration task.

## 9. Version and Release

- **Package name:** `bolyra-langchain` (on PyPI)
- **Import name:** `bolyra_langchain`
- **Initial version:** `0.1.0`
- **Dependencies:** `bolyra>=0.4.0`, `langchain-core>=0.2.0`, `PyJWT[crypto]>=2.8.0`
