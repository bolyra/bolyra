---
title: MCP Integration
visibility: public
sources:
  - integrations/mcp/README.md
  - integrations/mcp/package.json
  - integrations/mcp/src/
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [mcp, middleware, authentication, zkp, stdio, http]
---

Authentication middleware for Model Context Protocol servers. Gates `tools/call` requests so only agents with valid Bolyra ZKP proof bundles can invoke sensitive tools.

## Overview

`@bolyra/mcp` (v0.6.4) wraps MCP servers -- stdio or HTTP -- and intercepts every `tools/call` request. Each call must carry a proof bundle (a pair of Groth16 proofs bound to a shared session nonce). Discovery calls (`initialize`, `tools/list`) pass through unauthenticated.

- **npm:** `@bolyra/mcp`
- **Peer deps:** `@bolyra/sdk >=0.4.0`, `@modelcontextprotocol/sdk >=1.0.0`
- **License:** Apache-2.0

## Key Concepts

- **Proof bundle:** Two Groth16 proofs (human + agent) bound to a session nonce. Carried in `params._meta.bolyra` (stdio) or `Authorization: Bolyra <base64>` header (HTTP).
- **Tool policy:** A map of tool names to BigInt permission bitmasks (e.g., `read_file: 1n` for READ_DATA). The agent's effective bitmask must satisfy the tool's required bitmask.
- **Delegation chains:** v=2 bundles narrow scope from root credential to leaf agent across multiple hops. The effective bitmask is always the leaf's (most-restricted).
- **Dev mode:** Uses mock proofs with fixed-seed identities. No circuit artifacts or trusted setup needed.

## How It Works

1. Extract bundle from `_meta.bolyra` (stdio) or `Authorization` header (HTTP).
2. Verify the handshake -- both proofs, nonce freshness, score floor.
3. Check the tool's permission policy against the agent's effective bitmask.
4. Attach a `BolyraAuthContext` to the request for downstream handlers.
5. Reject with an MCP error if any step fails.

### Server API

```ts
// stdio -- wrap before server.connect(transport)
withBolyraAuthStdio(server: McpServer, config: BolyraMcpConfig): void

// HTTP -- Express middleware, rejects unauthenticated tools/call with 401
bolyraAuthMiddleware(config: BolyraMcpHttpConfig): express.RequestHandler
```

### Client API

```ts
attachBolyraProof(human, agent, options?) -> Promise<{ headers, meta, bundle }>
attachDelegatedBolyraProof(human, rootCred, hops, options?) -> Promise<BolyraClientAuth>
```

### Config

```ts
interface BolyraMcpConfig {
  network?: string;          // default: 'base-sepolia'
  minScore?: number;         // 0-100, default: 70
  maxProofAge?: number;      // seconds, default: 300
  toolPolicy?: ToolPermissionPolicy;
  devMode?: boolean;
  resolveCredential?: (commitment: string) => Promise<AgentCredential | null>;
  sdkConfig?: BolyraConfig;
}
```

### Source layout

| File | Purpose |
|------|---------|
| `src/server-stdio.ts` | `withBolyraAuthStdio` implementation |
| `src/server-http.ts` | `bolyraAuthMiddleware` Express handler |
| `src/client.ts` | `attachBolyraProof`, `attachDelegatedBolyraProof` |
| `src/verify.ts` | `verifyBundle`, `checkToolPolicy` |
| `src/nonce-store.ts` | Nonce freshness tracking |
| `src/types.ts` | Config and context types |

## Current Status

v0.6.4 on npm. Stable for both stdio (Claude Desktop, Cursor, Cline) and HTTP transports. Dev mode works out of the box; production mode requires circuit artifacts and a credential resolver.

## See Also

- [Gateway](gateway.md) -- standalone reverse proxy built on top of this package
- [OpenClaw](openclaw.md) -- trust verification adapter
- `integrations/mcp/examples/protected-file-server/` -- complete working example
