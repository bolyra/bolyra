# Vercel AI SDK Adapter — Implementation Plan

**Date:** 2026-06-20
**Spec:** `docs/superpowers/specs/2026-06-20-vercel-ai-adapter-design.md`
**Pipeline:** `pdlc-2026-06-20-vercel-ai-adapter`

## Tasks

### Task 1: Package scaffolding + types (S, parallel)

**Description:** Create `integrations/ai/` with package.json, tsconfig.json, jest.config.js, LICENSE, NOTICE, and `src/types.ts` with all config interfaces.

**Input files:**
- `integrations/gateway/package.json` (pattern reference)
- `integrations/gateway/tsconfig.json` (pattern reference)
- `integrations/gateway/jest.config.js` (pattern reference)
- `sdk/src/types.ts` (SDK types to reference)
- `integrations/mcp/src/types.ts` (MCP types to reference)

**Output files:**
- `integrations/ai/package.json`
- `integrations/ai/tsconfig.json`
- `integrations/ai/jest.config.js`
- `integrations/ai/LICENSE`
- `integrations/ai/NOTICE`
- `integrations/ai/src/types.ts`

**Test:** `cd integrations/ai && npx tsc --noEmit` (types compile)

---

### Task 2: Utility helpers (S, depends on 1)

**Description:** Create `src/utils.ts` with proof bundle encoding/decoding, header construction, and nonce generation helpers.

**Input files:**
- `integrations/mcp/src/client.ts` (bundle encoding pattern)
- `integrations/ai/src/types.ts` (from Task 1)

**Output files:**
- `integrations/ai/src/utils.ts`

**Test:** `cd integrations/ai && npx tsc --noEmit`

---

### Task 3: withBolyraAuth middleware (M, depends on 1, 2)

**Description:** Implement `src/middleware.ts` — wraps a LanguageModelV1 using `wrapLanguageModel()` from the `ai` package. Intercepts tool calls to inject Bolyra proof bundles. Supports direct mode (generates proofs) and gateway mode (routes through gateway URL). Dev mode uses createDevIdentities().

**Input files:**
- `integrations/ai/src/types.ts`
- `integrations/ai/src/utils.ts`
- `integrations/mcp/src/client.ts` (proof attachment pattern)
- `sdk/src/dev.ts` (dev mode pattern)

**Output files:**
- `integrations/ai/src/middleware.ts`

**Test:** `cd integrations/ai && npx jest test/middleware.test.ts`

---

### Task 4: bolyraAuthMiddleware server middleware (M, depends on 1, 2)

**Description:** Implement `src/server-middleware.ts` — Express/Next.js compatible server-side verification. Extracts Authorization header, calls verifyBundle() from @bolyra/mcp, checks tool policy. Returns structured BolyraVerifyResult.

**Input files:**
- `integrations/ai/src/types.ts`
- `integrations/mcp/src/verify.ts` (verification pattern)
- `integrations/mcp/src/types.ts` (BolyraAuthContext shape)

**Output files:**
- `integrations/ai/src/server-middleware.ts`

**Test:** `cd integrations/ai && npx jest test/server-middleware.test.ts`

---

### Task 5: createBolyraTools (M, depends on 1)

**Description:** Implement `src/tools.ts` — creates Vercel AI SDK tool() definitions with zod schemas. Tools: bolyra_authenticate, bolyra_delegate, bolyra_check_permissions, bolyra_credential_info.

**Input files:**
- `integrations/ai/src/types.ts`
- `sdk/src/types.ts` (Permission enum, credential types)
- `sdk/src/dev.ts` (createDevIdentities for tool execute)

**Output files:**
- `integrations/ai/src/tools.ts`

**Test:** `cd integrations/ai && npx jest test/tools.test.ts`

---

### Task 6: Index exports + tests + README (M, depends on 1-5)

**Description:** Create `src/index.ts` with clean public API exports. Write all test files. Write README.md with Next.js examples.

**Input files:**
- All src files from Tasks 1-5
- `integrations/mcp/src/index.ts` (export pattern)

**Output files:**
- `integrations/ai/src/index.ts`
- `integrations/ai/test/middleware.test.ts`
- `integrations/ai/test/server-middleware.test.ts`
- `integrations/ai/test/tools.test.ts`
- `integrations/ai/test/integration.test.ts`
- `integrations/ai/README.md`

**Test:** `cd integrations/ai && npx jest`

---

## Dependency Graph

```
Task 1 (scaffolding + types)
  |
  +---> Task 2 (utils) --+
  |                       |
  |                       +--> Task 3 (withBolyraAuth middleware)
  |                       |
  |                       +--> Task 4 (server middleware)
  |
  +---> Task 5 (tools)
  |
  +---> Task 6 (index + tests + README) [depends on ALL above]
```

## Parallelization

- Task 1 runs first (foundation)
- Tasks 2, 5 can run in parallel after Task 1
- Tasks 3, 4 can run in parallel after Task 2
- Task 6 waits for all others

## Estimated scope

6 tasks total, 2 parallelizable pairs. Single-agent sequential execution is practical given the dependency chain.
