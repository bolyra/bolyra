# LangChain Adapter Implementation Plan

**PDLC:** `pdlc-2026-06-19-langchain-adapter`
**Spec:** `docs/superpowers/specs/2026-06-19-langchain-adapter-design.md`
**Date:** 2026-06-19

---

## Task Breakdown

### Task 1: Pure-Python SD-JWT Module (Parallel)
**Size:** M
**Type:** parallel | **Depends on:** none
**Files to create:** `sdk-python/bolyra/sd_jwt.py`
**Files to read:** `delegation/src/allow.ts`, `delegation/src/present.ts`, `delegation/src/verify.ts`, `delegation/src/types.ts`, `delegation/src/verify-kb.ts`

Implement `allow()`, `present()`, `verify()` in pure Python using PyJWT + cryptography:
- `allow(opts, issuer_private_key, issuer_kid)` -> SD-JWT issuer-form (`jws~`)
- `present(receipt, holder_private_key, opts)` -> presented form (`jws~~kbjwt`)
- `verify(receipt, opts)` -> `VerifyResult`
- Wire format must match TS exactly: `typ: "bolyra-delegation+sd-jwt"`, `alg: "EdDSA"`, `_sd_alg: "sha-256"`, `cnf` claim with Ed25519 JWK, KB-JWT with `typ: "kb+jwt"`
- Dev mode: `generate_ed25519_keypair()` helper

### Task 2: SD-JWT Tests (Sequential, depends on 1)
**Size:** S
**Type:** sequential | **Depends on:** 1
**Files to create:** `sdk-python/tests/test_sd_jwt.py`
**Test command:** `cd ~/Projects/bolyra/sdk-python && python -m pytest tests/test_sd_jwt.py -v`

Test: roundtrip allow/present/verify, holder binding enforcement, expiry, wrong key rejection, wire format assertions (typ, alg, _sd_alg, cnf structure).

### Task 3: LangChain Tools Package (Sequential, depends on 1)
**Size:** L
**Type:** sequential | **Depends on:** 1
**Files to create:**
- `integrations/langchain/bolyra_langchain/__init__.py`
- `integrations/langchain/bolyra_langchain/types.py`
- `integrations/langchain/bolyra_langchain/auth_tool.py`
- `integrations/langchain/bolyra_langchain/delegate_tool.py`
- `integrations/langchain/bolyra_langchain/sd_jwt_tool.py`
- `integrations/langchain/bolyra_langchain/session.py`
- `integrations/langchain/bolyra_langchain/callbacks.py`
- `integrations/langchain/bolyra_langchain/_compat.py`

All tools subclass `BaseTool` from `langchain_core.tools`. Session management via `BolyraSession`. Callback integration via `BolyraCallbackHandler`.

### Task 4: Package Setup (Parallel)
**Size:** S
**Type:** parallel | **Depends on:** none
**Files to create:** `integrations/langchain/pyproject.toml`
**Files to modify:** (cleanup old stub files)
**Files to delete:** `integrations/langchain/bolyra_auth_tool.py`, `integrations/langchain/bolyra_delegate_tool.py`, `integrations/langchain/__init__.py` (replaced by bolyra_langchain/)

### Task 5: LangChain Tools Tests (Sequential, depends on 3, 4)
**Size:** M
**Type:** sequential | **Depends on:** 3, 4
**Files to create:**
- `integrations/langchain/tests/__init__.py`
- `integrations/langchain/tests/conftest.py`
- `integrations/langchain/tests/test_auth_tool.py`
- `integrations/langchain/tests/test_delegate_tool.py`
- `integrations/langchain/tests/test_sd_jwt_tool.py`
- `integrations/langchain/tests/test_session.py`
**Test command:** `cd ~/Projects/bolyra/integrations/langchain && python -m pytest tests/ -v`

### Task 6: README (Sequential, depends on 3)
**Size:** S
**Type:** sequential | **Depends on:** 3
**Files to create:** `integrations/langchain/README.md` (replace existing)

### Task 7: Integration Test Run + Commit (Sequential, depends on 2, 5, 6)
**Size:** S
**Type:** sequential | **Depends on:** 2, 5, 6
Run all tests, fix any failures, commit with DCO sign-off.

---

## Parallelization

Tasks 1 and 4 run concurrently (no dependencies).
Tasks 2, 3 wait for Task 1.
Task 5 waits for Tasks 3 and 4.
Task 6 waits for Task 3.
Task 7 waits for Tasks 2, 5, and 6.

## Estimated Scope

7 tasks total, 2 parallelizable at start.
