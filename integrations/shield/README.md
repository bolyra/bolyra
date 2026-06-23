# @bolyra/shield

Stdio MCP auth proxy. Wrap any MCP server with per-tool permission enforcement, replay protection, and audit receipts. No code changes to the server.

## Quick Start

```bash
npx @bolyra/shield --server "npx @modelcontextprotocol/server-filesystem /tmp" --dev
```

Shield spawns the target server as a child process, intercepts `tools/call` requests, verifies agent credentials, and enforces tool policies before forwarding.

## Config

Create `shield.yaml`:

```yaml
devMode: true

nonce:
  store: memory
  maxProofAge: 300

receipts:
  enabled: true
  output: stderr

tools:
  read_file:
    requireBitmask: 1    # READ_DATA
  write_file:
    requireBitmask: 2    # WRITE_DATA
  delete_file:
    requireBitmask: 2    # WRITE_DATA
```

Then:

```bash
npx @bolyra/shield --server "node my-server.js" --config shield.yaml
```

## How It Works

```
Agent ←stdin/stdout→ Shield ←stdin/stdout→ MCP Server
                       │
                 verifyBundle()
                 checkToolPolicy()
                 nonceStore.markIfFresh()
                 emitReceipt()
```

- `initialize`, `tools/list`, `ping` — forwarded without auth
- `tools/call` — proof extracted from `params._meta.bolyra`, verified, policy checked, then forwarded or rejected
- Receipts emitted to stderr (stdout is the MCP transport)

## Permission Bitmask

| Bit | Permission |
|-----|-----------|
| 0 | READ_DATA |
| 1 | WRITE_DATA |
| 2 | FINANCIAL_SMALL |
| 3 | FINANCIAL_MEDIUM |
| 4 | FINANCIAL_UNLIMITED |
| 5 | SIGN_ON_BEHALF |
| 6 | SUB_DELEGATE |
| 7 | ACCESS_PII |

## Shield vs Gateway

| | Shield | Gateway |
|---|--------|---------|
| Transport | stdio | HTTP |
| Use case | Local MCP servers (Claude Desktop, Cursor) | Remote/networked MCP servers |
| How it wraps | Spawns child process | Reverse proxy |
| Proof source | `params._meta.bolyra` | `Authorization: Bolyra <base64>` header |
| Receipts | stderr | stdout/file/webhook |

Both use the same `verifyBundle()` and `checkToolPolicy()` from `@bolyra/mcp`.

## Library Usage

```typescript
import { createShield, loadShieldConfig } from '@bolyra/shield';

const config = loadShieldConfig('./shield.yaml');
const { child, stop } = createShield(config);
```

## Links

- [Gateway (HTTP)](../gateway/README.md) — for HTTP MCP servers
- [MCP Middleware](../mcp/README.md) — for embedding auth in your server code
- [Bolyra docs](https://bolyra.ai)
