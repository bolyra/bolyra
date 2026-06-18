# MCP Auth Gateway -- Implementation Plan

**Date:** 2026-06-18
**Pipeline:** pdlc-2026-06-18-mcp-auth-gateway
**Spec:** `docs/superpowers/specs/2026-06-18-mcp-auth-gateway-design.md`
**Status:** Pending Gate 2 approval

## Overview

Build `@bolyra/gateway` as a new package at `integrations/gateway/`. The gateway is a standalone Node.js reverse proxy that verifies Bolyra proof bundles on MCP `tools/call` requests before forwarding them to an upstream server. It reuses `@bolyra/mcp` for all verification logic -- no new crypto.

11 tasks total. Tasks 1-5 are parallelizable (no interdependencies). Tasks 6-11 are sequential with explicit dependency chains.

---

## Task Dependency Graph

```
  [1] Scaffold ──────────────────────────┐
  [2] Config loader ─────────────────────┤
  [3] Header injection ──────────────────┤
  [4] Receipt writer ────────────────────┤
  [5] Health check ──────────────────────┤
                                         │
  [6] Auth middleware ◄── [1]            │
  [7] Proxy core ◄── [1,3,5,6]          │
  [8] CLI entry ◄── [2,4,7]             │
  [9] Library exports ◄── [all 1-8]     │
  [10] Integration test ◄── [9]         │
  [11] Documentation ◄── [9]            │
                                         │
  [10,11] run in parallel ◄─────────────┘
```

---

## Tasks

### Task 1: Package Scaffolding (S, parallel)

**What:** Create the `integrations/gateway/` directory with `package.json`, `tsconfig.json`, `jest.config.js`, `src/types.ts`, and a placeholder `src/index.ts`.

**Input files:**
- `integrations/mcp/package.json` (pattern reference)
- `integrations/mcp/tsconfig.json` (pattern reference)
- `integrations/mcp/jest.config.js` (pattern reference)

**Output files:**
- `integrations/gateway/package.json` -- `@bolyra/gateway@0.1.0`, deps on `@bolyra/mcp ^0.6.0`, `@bolyra/receipts ^0.6.0`, `yaml` for config, peer dep on `@bolyra/sdk >=0.5.0`. `bin` field: `bolyra-gateway: dist/cli.js`. Scripts: build, test, typecheck.
- `integrations/gateway/tsconfig.json` -- extends same pattern as `@bolyra/mcp`
- `integrations/gateway/jest.config.js` -- ts-jest preset
- `integrations/gateway/src/types.ts` -- `GatewayConfig`, `GatewayMiddlewareOptions`, `ToolPolicyEntry`, `ReceiptOutputConfig`, `CredentialSource`, `NonceConfig`, `HealthConfig`
- `integrations/gateway/src/index.ts` -- empty placeholder (finalized in Task 9)

**Test:** `cd integrations/gateway && npx tsc --noEmit`
**Expected:** Compiles clean.

---

### Task 2: Config Loader (M, parallel)

**What:** YAML/JSON config file parser with environment variable substitution (`${VAR}` syntax), schema validation, and CLI flag merge logic.

**Output files:**
- `integrations/gateway/src/config.ts` -- `loadConfig(filePath)`, `mergeCliFlags(config, flags)`, `validateConfig(config)`, `substituteEnvVars(obj)`
- `integrations/gateway/test/config.test.ts`

**Tests cover:**
- Load valid YAML config
- Load valid JSON config
- Environment variable substitution in string values
- Missing required fields throw descriptive error
- CLI flags override config values
- Default values applied correctly (port 4100, dev false, receipts enabled)

**Test:** `cd integrations/gateway && npx jest config.test`

---

### Task 3: Header Injection (S, parallel)

**What:** Build `X-Bolyra-*` headers from a `BolyraAuthContext`. Optionally HMAC-sign all injected headers with a shared secret.

**Output files:**
- `integrations/gateway/src/headers.ts` -- `injectBolyraHeaders(authCtx): Record<string, string>`, `computeHmac(headers, secret): string`, `verifyHmac(headers, secret, hmac): boolean`
- `integrations/gateway/test/headers.test.ts`

**Headers produced:**
- `X-Bolyra-Verified: true`
- `X-Bolyra-DID: did:bolyra:{network}:{commitment}`
- `X-Bolyra-Score: {score}`
- `X-Bolyra-Permissions: {bitmask decimal}`
- `X-Bolyra-Chain-Depth: {depth}`
- `X-Bolyra-Receipt-ID: {receiptId}`
- `X-Bolyra-HMAC: {hmac}` (only if shared secret configured)

**HMAC:** HMAC-SHA256 over sorted `X-Bolyra-*` header key=value pairs (excluding the HMAC header itself). Uses `@noble/hashes` (already a transitive dep via `@bolyra/receipts`).

**Test:** `cd integrations/gateway && npx jest headers.test`

---

### Task 4: Receipt Writer (M, parallel)

**What:** Async, non-blocking receipt output with three modes: file (day-rotated subdirs), stdout (NDJSON), webhook (HTTP POST).

**Output files:**
- `integrations/gateway/src/receipts.ts` -- `createReceiptWriter(config): ReceiptWriter`, `ReceiptWriter.write(receipt)`, interface for pluggable outputs
- `integrations/gateway/test/receipts.test.ts`

**Behavior:**
- **File mode:** Writes `{receiptDir}/{YYYY-MM-DD}/{timestamp}-{receiptId}.json`. Creates subdirs as needed.
- **Stdout mode:** Writes one JSON line per receipt (NDJSON format) to `process.stdout`.
- **Webhook mode:** HTTP POST to configured URL with optional auth headers. Fire-and-forget with error logging.
- All modes are non-blocking: `write()` returns immediately, failures are logged but never throw.

**Test:** `cd integrations/gateway && npx jest receipts.test`

---

### Task 5: Health Check (S, parallel)

**What:** HTTP handler for `/healthz` that returns gateway status and upstream reachability.

**Output files:**
- `integrations/gateway/src/health.ts` -- `createHealthHandler(config): (req, res) => void`
- `integrations/gateway/test/health.test.ts`

**Response shape:**
```json
{
  "status": "ok",
  "gateway": "@bolyra/gateway",
  "version": "0.1.0",
  "uptime": 3600,
  "target": "http://localhost:3000/mcp",
  "targetReachable": true,
  "mode": "production|dev",
  "receiptsEnabled": true,
  "nonceStore": "memory"
}
```

**Upstream probe:** HEAD request to target URL with 2s timeout. Returns 503 if unreachable.

**Test:** `cd integrations/gateway && npx jest health.test`

---

### Task 6: Auth Middleware (M, sequential -- depends on Task 1)

**What:** Express-compatible middleware that extracts the `Authorization: Bolyra <base64>` header, calls `verifyBundle()` and `checkToolPolicy()` from `@bolyra/mcp`, and produces standard HTTP error responses.

**Depends on:** Task 1 (needs `types.ts`)

**Input files:**
- `integrations/mcp/src/verify.ts`
- `integrations/mcp/src/types.ts`
- `integrations/mcp/src/server-http.ts` (pattern reference)

**Output files:**
- `integrations/gateway/src/middleware.ts` -- `createGatewayMiddleware(config): RequestHandler`
- `integrations/gateway/test/middleware.test.ts`

**Error responses (JSON-RPC formatted):**
- 401: Missing or malformed `Authorization` header
- 401: Proof verification failed (invalid ZKP, expired credential, bad nonce)
- 403: Insufficient permissions for requested tool
- All error bodies follow JSON-RPC 2.0 error format: `{ jsonrpc: "2.0", id, error: { code, message, data } }`

**Dev mode:** When `devMode: true`, skip real ZKP verification. Accept any well-formed bundle with mock credential resolution.

**Test:** `cd integrations/gateway && npx jest middleware.test`

---

### Task 7: Reverse Proxy Core (L, sequential -- depends on Tasks 1, 3, 5, 6)

**What:** HTTP reverse proxy using Node.js native `http.request`/`https.request`. Routes requests, applies auth middleware selectively, injects headers, handles upstream errors.

**Depends on:** Tasks 1, 3, 5, 6

**Output files:**
- `integrations/gateway/src/proxy.ts` -- `createGatewayProxy(config): http.Server`
- `integrations/gateway/test/proxy.test.ts`

**Request routing:**
1. `GET {healthPath}` -> health handler (Task 5), skip proxy
2. Parse JSON-RPC body. If method != `tools/call` -> forward to upstream without auth
3. If method == `tools/call` -> run auth middleware (Task 6), then forward if authorized
4. Inject `X-Bolyra-*` headers (Task 3) on authorized requests
5. Strip `Authorization` header before forwarding (consumed by gateway)
6. Rewrite `Host` header to upstream hostname

**Error handling:**
- Upstream connection refused / timeout -> 502 Bad Gateway with JSON-RPC error body
- Malformed JSON-RPC body -> 400 Bad Request
- Upstream non-2xx -> forward upstream's status code and body unchanged

**Tests cover:** Non-auth passthrough, auth gating, 502 on upstream failure, header injection, health intercept, malformed body handling.

**Test:** `cd integrations/gateway && npx jest proxy.test`

---

### Task 8: CLI Entry Point (M, sequential -- depends on Tasks 2, 4, 7)

**What:** CLI argument parser that loads config, merges CLI flags, wires up receipt writer, and starts the proxy server.

**Depends on:** Tasks 2, 4, 7

**Output files:**
- `integrations/gateway/src/cli.ts` -- `#!/usr/bin/env node` entry, argument parsing (no external dep -- use `process.argv` with a minimal parser or Node's `parseArgs`), startup banner

**CLI arguments:** (as specified in design doc section 1)
- `--target <url>` (required unless in config)
- `--port <number>` (default 4100)
- `--config <path>` (default `./gateway.yaml`)
- `--dev` (enable dev mode)
- `--receipt-dir <path>`, `--receipt-stdout`, `--no-receipts`
- `--network <name>` (default `base-sepolia`)
- `--help`

**Startup banner:**
```
@bolyra/gateway v0.1.0
  Mode:    production|dev
  Target:  http://localhost:3000/mcp
  Port:    4100
  Receipts: ./receipts/ (file)
  Network: base-sepolia
```

**Test:** `cd integrations/gateway && npx tsc --noEmit` (type-check; CLI is tested via integration test in Task 10)

---

### Task 9: Library Exports (S, sequential -- depends on all Tasks 1-8)

**What:** Finalize `src/index.ts` with all public exports. Update `package.json` `bin` field and `files` array.

**Depends on:** Tasks 1-8

**Output files:**
- `integrations/gateway/src/index.ts` -- public API surface:
  - `createGatewayMiddleware` from middleware
  - `createGatewayProxy` from proxy
  - `loadConfig` from config
  - `injectBolyraHeaders`, `computeHmac`, `verifyHmac` from headers
  - `createReceiptWriter` from receipts
  - `createHealthHandler` from health
  - All types from types
- `integrations/gateway/package.json` -- verify `bin`, `files`, `main`, `types` fields are correct

**Test:** `cd integrations/gateway && npm run build` -- full build must succeed, `dist/` produced.

---

### Task 10: Integration Test (M, sequential -- depends on Task 9)

**What:** End-to-end test that spins up a mock upstream HTTP server, starts the gateway proxy in dev mode, and exercises the full request lifecycle.

**Depends on:** Task 9

**Output files:**
- `integrations/gateway/test/integration.test.ts`

**Test scenarios:**
1. `tools/call` with valid dev-mode auth -> 200, request reaches upstream, receipt file created
2. `tools/call` without auth header -> 401 JSON-RPC error
3. `tools/call` with insufficient permissions -> 403 JSON-RPC error
4. Non-`tools/call` method (e.g., `tools/list`) -> forwarded without auth check
5. Upstream down -> 502 JSON-RPC error
6. Health endpoint -> 200 with status JSON
7. X-Bolyra-* headers present on proxied request

**Test:** `cd integrations/gateway && npx jest integration.test`

---

### Task 11: Documentation (S, sequential -- depends on Task 9)

**What:** README.md with quickstart, config reference, architecture diagram, library API, and deployment guidance.

**Depends on:** Task 9 (needs final API surface)

**Output files:**
- `integrations/gateway/README.md`

**Sections:**
1. Quickstart (3 commands: install, create config, run)
2. CLI reference (all flags)
3. Config file reference (annotated YAML example)
4. Architecture diagram (ASCII, same as spec)
5. Library API (for embedding in custom servers)
6. Security model (trust boundary, deployment guidance)
7. Receipt output modes

**Test:** `test -f integrations/gateway/README.md && echo PASS`

---

## Execution Plan

**Wave 1 (parallel):** Tasks 1, 2, 3, 4, 5
- 5 subagents in separate worktrees
- No dependencies between them
- All are S or M sized

**Wave 2 (sequential):** Task 6
- Needs Task 1 (types.ts) complete
- Can start as soon as Task 1 finishes

**Wave 3 (sequential):** Task 7
- Needs Tasks 1, 3, 5, 6 complete
- Largest task (L) -- core proxy logic

**Wave 4 (sequential):** Task 8
- Needs Tasks 2, 4, 7 complete
- CLI wires everything together

**Wave 5 (sequential):** Task 9
- Needs all prior tasks
- Quick finalization of exports

**Wave 6 (parallel):** Tasks 10, 11
- Both depend only on Task 9
- Integration test and docs run concurrently

## Risk Notes

- **No external proxy dependency.** Using Node.js native `http.request` keeps the dep tree small but means we handle edge cases (chunked transfer, connection reuse) ourselves. If this proves fragile in Task 7, the fallback is adding `undici` (ships with Node 18+) as an optional dep.
- **Dev mode is the only testable mode without circuits.** Integration tests use dev mode (mock verification). Real ZKP verification is tested in `@bolyra/mcp`'s own test suite, not here.
- **No Redis nonce store in v0.1.** `MemoryNonceStore` only. Redis adapter deferred to v0.2 as noted in spec.
