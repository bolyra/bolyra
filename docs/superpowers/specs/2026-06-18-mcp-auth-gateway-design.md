# MCP Auth Gateway — Design Spec

**Date:** 2026-06-18
**Pipeline:** pdlc-2026-06-18-mcp-auth-gateway
**Status:** Draft (pending Gate 1)
**Author:** Bolyra PDLC Orchestrator

## Problem

`@bolyra/mcp` ships verification middleware that MCP server authors embed in their code. This requires:

1. Adding `@bolyra/mcp` as a dependency
2. Importing and wiring `bolyraAuthMiddleware()` or `withBolyraAuthStdio()`
3. Configuring `resolveCredential`, `nonceStore`, `toolPolicy`, `receiptSigner`
4. Understanding Bolyra's credential model

This is acceptable for SDK-savvy operators but blocks adoption for the common case: a team with a working MCP server that wants agent auth without modifying their server code.

## Solution

**Bolyra MCP Auth Gateway** (`@bolyra/gateway`) — a standalone Node.js reverse proxy that sits in front of any HTTP-based MCP server. One command:

```bash
npx @bolyra/gateway --target http://localhost:3000/mcp
```

The gateway:
- Intercepts all incoming MCP JSON-RPC requests
- Verifies Bolyra proof bundles on `tools/call` requests (passes other methods through)
- Enforces per-tool permission policies from a YAML/JSON config file
- Prevents nonce replay via a built-in nonce store (in-memory default, Redis adapter available)
- Emits signed audit receipts for every tool call decision (allow + deny)
- Returns standard HTTP 401/403 with JSON-RPC error bodies for unauthorized requests
- Proxies authorized requests to the upstream MCP server with `X-Bolyra-*` headers attached

For advanced users, the gateway also exports its core middleware as a library, so it can be embedded in existing Express/Hono/Fastify apps.

## Architecture

```
                  ┌──────────────────────────────────┐
                  │         @bolyra/gateway           │
   Agent ────────►│                                    │──────► Upstream MCP Server
  (with proof     │  1. Parse Authorization header     │        (unmodified)
   bundle)        │  2. verifyBundle() from @bolyra/mcp│
                  │  3. checkToolPolicy()              │
                  │  4. Nonce replay check              │
                  │  5. Emit signed receipt             │
                  │  6. Proxy request + X-Bolyra-* hdrs│
                  │                                    │
                  │  Config: gateway.yaml              │
                  │  Receipts: ./receipts/ or stdout    │
                  └──────────────────────────────────┘
```

### Package Structure

```
integrations/gateway/
├── package.json          # @bolyra/gateway
├── tsconfig.json
├── src/
│   ├── index.ts          # Library entry: re-exports middleware
│   ├── cli.ts            # CLI entry: npx @bolyra/gateway
│   ├── proxy.ts          # HTTP reverse proxy core
│   ├── config.ts         # Config file loader (YAML/JSON)
│   ├── middleware.ts      # Express-compatible middleware (wraps @bolyra/mcp verify)
│   ├── headers.ts        # X-Bolyra-* header injection
│   ├── receipts.ts       # Receipt writer (file, stdout, webhook)
│   ├── health.ts         # Health check endpoint (/healthz)
│   └── types.ts          # Gateway-specific types
├── test/
│   ├── proxy.test.ts     # Proxy integration tests
│   ├── config.test.ts    # Config loading tests
│   ├── middleware.test.ts # Middleware unit tests
│   ├── headers.test.ts   # Header injection tests
│   └── receipts.test.ts  # Receipt writer tests
└── README.md
```

### Dependencies

```
@bolyra/sdk       — credential types, verify functions
@bolyra/mcp       — verifyBundle(), checkToolPolicy(), MemoryNonceStore
@bolyra/receipts  — createAuthReceipt(), signReceipt()
```

The gateway is a thin orchestration layer over existing packages. No new crypto or verification logic — it reuses `@bolyra/mcp`'s `verifyBundle()` and `checkToolPolicy()` directly.

## Detailed Design

### 1. CLI (`src/cli.ts`)

```
npx @bolyra/gateway [options]

Options:
  --target <url>       Upstream MCP server URL (required)
  --port <number>      Gateway listen port (default: 4100)
  --config <path>      Path to gateway config file (default: ./gateway.yaml)
  --dev                Enable dev mode (mock verification)
  --receipt-dir <path> Directory for receipt JSON files (default: ./receipts/)
  --receipt-stdout     Write receipts to stdout instead of files
  --no-receipts        Disable receipt generation
  --network <name>     Bolyra network (default: base-sepolia)
  --help               Show help
```

The CLI:
1. Loads config file (if present)
2. Merges CLI flags over config (CLI wins)
3. Creates the HTTP server with proxy middleware
4. Starts listening
5. Logs startup banner with target URL, port, dev/prod mode

### 2. Configuration (`src/config.ts`)

Config file format (YAML preferred, JSON also accepted):

```yaml
# gateway.yaml
target: http://localhost:3000/mcp
port: 4100
network: base-sepolia

# Dev mode skips real ZKP verification
devMode: false

# Credential resolution
credentials:
  # For production: "registry" uses on-chain IdentityRegistry
  source: registry
  registryAddress: "0x..."
  rpcUrl: "https://base-sepolia.g.alchemy.com/v2/..."

  # Alternative: "static" for testing with a fixed credential map
  # source: static
  # map:
  #   "12345678": { permissionBitmask: "255", expiryTimestamp: "1750000000", commitment: "12345678" }

# Per-tool policies
tools:
  write_file:
    requireBitmask: 0b10     # WRITE_DATA
  delete_file:
    requireBitmask: 0b110    # WRITE_DATA + FINANCIAL_SMALL
    maxChainDepth: 0          # Direct credentials only
  transfer_funds:
    requireBitmask: 0b11100  # FINANCIAL_*
    minScore: 90

# Nonce replay protection
nonce:
  store: memory              # "memory" (default) or "redis"
  # redis:
  #   url: redis://localhost:6379
  maxProofAge: 300            # seconds

# Receipt signing
receipts:
  enabled: true
  issuer: "my-gateway"
  keyId: "k1"
  privateKey: "${BOLYRA_RECEIPT_KEY}"  # env var substitution
  output: file                # "file", "stdout", or "webhook"
  dir: ./receipts/
  # webhook:
  #   url: https://my-audit-service.example.com/receipts
  #   headers:
  #     Authorization: "Bearer ${AUDIT_TOKEN}"

# Health check
health:
  enabled: true
  path: /healthz
```

Config loading:
- Supports YAML (via `yaml` package) and JSON
- Environment variable substitution: `${VAR_NAME}` in string values
- Validates required fields at startup (fail fast)
- CLI flags override config file values

### 3. Reverse Proxy (`src/proxy.ts`)

The proxy handles:

**Request flow:**
1. Receive incoming HTTP request
2. If `GET /healthz` (or configured health path): return health status, skip proxy
3. Parse JSON-RPC body
4. If method is NOT `tools/call`: proxy directly to upstream (no auth required)
5. If method IS `tools/call`: run auth middleware, then proxy if authorized

**Proxying:**
- Uses Node.js `http.request` / `https.request` (no external proxy dependency)
- Forwards all headers except `Authorization` (consumed by gateway) and `Host` (rewritten)
- Adds `X-Bolyra-*` headers to the proxied request (see section 5)
- Streams response body back to client unchanged
- Preserves HTTP status codes from upstream
- Handles upstream connection errors with 502 Bad Gateway

**Why no WebSocket/SSE proxy:**
MCP's Streamable HTTP transport (2025-06-18 spec) uses standard HTTP POST for requests and optional SSE for server-initiated notifications. The gateway only needs to gate `tools/call` requests, which are always POST. SSE streams (server-to-client notifications) can be proxied as passthrough since they don't carry tool invocations.

If the upstream uses the older SSE transport, the gateway proxies the SSE endpoint as passthrough (no auth on the event stream — auth is on the POST that triggers tool execution).

### 4. Auth Middleware (`src/middleware.ts`)

Reuses `@bolyra/mcp` verification entirely:

```typescript
import { verifyBundle, checkToolPolicy, MemoryNonceStore } from '@bolyra/mcp';
import type { BolyraMcpConfig, BolyraProofBundle } from '@bolyra/mcp';
```

The middleware:
1. Extracts `Authorization: Bolyra <base64>` header
2. Decodes and parses the proof bundle
3. Calls `verifyBundle(bundle, mcpConfig)` — all ZKP verification, delegation chain walking, credential binding, expiry checks
4. Calls `checkToolPolicy(toolName, authCtx, mcpConfig)` — per-tool permission enforcement
5. On success: attaches `BolyraAuthContext` to request, continues to proxy
6. On failure: returns 401/403 with JSON-RPC error body

No new verification logic. The gateway is a deployment wrapper around `@bolyra/mcp`.

### 5. Header Injection (`src/headers.ts`)

When a request passes verification, the gateway adds headers to the proxied request so the upstream server can read the auth context without importing Bolyra:

```
X-Bolyra-Verified: true
X-Bolyra-DID: did:bolyra:base-sepolia:abc123...
X-Bolyra-Score: 90
X-Bolyra-Permissions: 255
X-Bolyra-Chain-Depth: 0
X-Bolyra-Receipt-ID: a1b2c3d4e5f67890
```

Headers are informational — the upstream server can ignore them or use them for logging/auditing. The gateway is the enforcement point; the upstream trusts the gateway's decision.

A `X-Bolyra-HMAC` header signs all X-Bolyra-* headers with a shared secret (configurable), so the upstream can verify the headers were set by the gateway and not injected by a client that bypasses it. This is optional — without the shared secret, headers are unsigned.

### 6. Receipt Writer (`src/receipts.ts`)

Every tool call decision (allow AND deny) produces a signed receipt via `@bolyra/receipts`:

**Output modes:**
- **File:** One JSON file per receipt in `--receipt-dir`. Filename: `{ISO-timestamp}-{receipt-id}.json`
- **Stdout:** One JSON line per receipt (NDJSON), for piping to log aggregators
- **Webhook:** POST receipt JSON to a configured URL with optional auth headers

The receipt writer:
- Never blocks the request path — writes are fire-and-forget (buffered, async)
- Logs write failures but does not fail the request
- Rotates file output by day (subdirectories: `receipts/2026-06-18/`)

### 7. Health Check (`src/health.ts`)

`GET /healthz` returns:

```json
{
  "status": "ok",
  "gateway": "@bolyra/gateway",
  "version": "0.1.0",
  "uptime": 3600,
  "target": "http://localhost:3000/mcp",
  "targetReachable": true,
  "mode": "production",
  "receiptsEnabled": true,
  "nonceStore": "memory"
}
```

Checks upstream reachability with a lightweight probe (HEAD request to target). Returns 503 if upstream is unreachable.

### 8. Library Export (`src/index.ts`)

For users who want to embed the gateway middleware in their own server:

```typescript
export { createGatewayMiddleware } from './middleware';
export { createGatewayProxy } from './proxy';
export { loadConfig } from './config';
export { injectBolyraHeaders } from './headers';
export { createReceiptWriter } from './receipts';
export type { GatewayConfig, GatewayMiddlewareOptions } from './types';
```

## Security Considerations

### Threat Model

The gateway is the trust boundary. Agents present proof bundles; the gateway verifies them before forwarding requests to the upstream server. The upstream server trusts the gateway.

**Threats addressed:**
1. **Replay attacks** — Nonce store prevents reuse of proof bundles within `maxProofAge`
2. **Credential substitution** — `verifyBundle()` binds proof to claimed credential via Poseidon3 scope commitment
3. **Delegation escalation** — Delegation chain walking enforces one-way scope narrowing (circuit-enforced)
4. **Scope bypass** — `checkToolPolicy()` enforces per-tool permission bitmask requirements
5. **Header injection** — Optional HMAC signing of X-Bolyra-* headers prevents forgery by clients bypassing the gateway
6. **Upstream impersonation** — HTTPS to upstream recommended; gateway validates TLS by default
7. **Audit evasion** — Receipts are emitted for denials too, creating a complete audit trail

**Threats NOT addressed (out of scope):**
- **Network-level bypass:** If a client can reach the upstream directly (bypassing the gateway), auth is not enforced. Deployment guidance: bind upstream to localhost or a private network; only expose the gateway.
- **Upstream authorization bugs:** The gateway gates tool calls; it does not audit what the upstream does with them.

### Credential Resolution

In production mode, the gateway needs to resolve credential commitments to full `AgentCredential` objects. Two built-in strategies:

1. **Registry** (recommended): Query the on-chain `IdentityRegistry` contract via ethers.js. Requires `rpcUrl` and `registryAddress`.
2. **Static map** (testing): A JSON map of commitment -> credential. For development and integration testing only.

Custom resolvers can be provided when using the library API.

### Key Management

Receipt signing requires a secp256k1 private key. The config supports:
- Environment variable references (`${BOLYRA_RECEIPT_KEY}`)
- Direct hex values (development only — not recommended for production)

The gateway never logs or exposes the signing key.

## Version and Packaging

- **Package name:** `@bolyra/gateway`
- **Initial version:** `0.1.0`
- **Binary name:** `bolyra-gateway` (via package.json `bin` field)
- **npx support:** `npx @bolyra/gateway` works out of the box
- **Dependencies:**
  - `@bolyra/sdk` (peer, `>=0.5.0`)
  - `@bolyra/mcp` (direct, `^0.6.0`)
  - `@bolyra/receipts` (direct, `^0.6.0`)
  - `yaml` (direct, for config parsing)
  - `ethers` (peer, optional — needed for registry credential resolution)

## What This Does NOT Include

- **stdio transport proxy:** The gateway is HTTP-only. stdio servers don't need a proxy — they're spawned by the host, which IS the trust boundary. The existing `withBolyraAuthStdio()` in `@bolyra/mcp` handles that case.
- **OAuth 2.1 integration:** The MCP authorization spec describes OAuth 2.1 flows. The gateway uses the `Bolyra` auth scheme (ZKP bundles), not Bearer tokens. OAuth interop is a future feature.
- **Rate limiting:** Out of scope for v0.1. Can be added as middleware or handled by an upstream load balancer.
- **Multi-target routing:** One gateway instance, one upstream. Use multiple instances or a reverse proxy for multiple upstreams.
- **Dashboard/UI:** Receipts are files/stdout/webhooks. Visualization is the operator's responsibility.
- **Redis nonce store:** The `NonceStore` interface from `@bolyra/mcp` is used. A Redis adapter is mentioned in config but deferred to v0.2 — v0.1 ships with `MemoryNonceStore` only.

## Test Strategy

- **Unit tests:** Config parsing, header injection, receipt writing, health check
- **Integration tests:** Full proxy flow with a mock upstream HTTP server and dev-mode verification
- **No circuit/contract tests:** The gateway does not touch circuits or contracts directly; it calls `@bolyra/mcp` which is already tested

Test command: `cd integrations/gateway && npm test`

## Success Criteria

1. `npx @bolyra/gateway --target http://localhost:3000/mcp --dev` starts a working proxy
2. Unauthenticated `tools/call` requests get 401
3. Authenticated requests with valid dev-mode bundles pass through to upstream
4. Per-tool policies reject insufficiently-privileged agents with 403
5. Receipts are written for every tool call decision
6. Health endpoint returns gateway status
7. All existing `npm test` (385+ tests) continue passing
8. Gateway-specific tests pass
