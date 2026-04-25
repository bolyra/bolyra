# @bolyra/mcp

> Bolyra ZKP authentication middleware for [Model Context Protocol](https://modelcontextprotocol.io/) servers.

Adds a mutual zero-knowledge proof of human-delegated agent identity to any MCP server, over **stdio** or **HTTP**. Drop-in: one wrapper line, no changes to your tool handlers.

## What this fixes

MCP servers today have no caller-identity story for stdio (the trust boundary is "whoever spawned the process") and an under-adopted OAuth 2.1 story for HTTP. Either way, an MCP server cannot answer:

- "Did a real human authorize this agent to call me?"
- "Does this agent's permission scope cover this specific tool?"
- "Can I prove the call chain without learning who the operator is?"

Bolyra answers all three with a single Groth16 mutual handshake (~100ms server-side).

## Two transports, two right answers

| Transport | Where the proof lives | Spec alignment |
|---|---|---|
| HTTP / SSE / Streamable-HTTP | `Authorization: Bolyra <base64-bundle>` | OAuth 2.1 resource-server pattern, custom auth scheme per RFC 7235 |
| stdio | `params._meta.bolyra` | Spec defines no stdio auth; `_meta` is the only protocol-level surface |

Both reduce to the same `BolyraAuthContext` on the request. Tool handlers don't care which transport delivered it.

## Install

```bash
npm install @bolyra/mcp @bolyra/sdk @modelcontextprotocol/sdk
```

## Stdio server (Claude Desktop, Cursor, Cline)

```ts
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { withBolyraAuthStdio } from '@bolyra/mcp';
import { z } from 'zod';

const server = new McpServer({ name: 'fs-server', version: '1.0.0' });

// Register tools as usual
server.registerTool(
  'read_file',
  { description: 'Read a file', inputSchema: z.object({ path: z.string() }) },
  async ({ path }) => ({ content: [{ type: 'text', text: await readFile(path) }] }),
);

// Then wrap with Bolyra (BEFORE connecting the transport)
withBolyraAuthStdio(server, {
  resolveCredential: async (commitment) => myRegistry.get(commitment),
  toolPolicy: {
    read_file: 0b01n,    // requires READ_DATA bit
    write_file: 0b10n,   // requires WRITE_DATA bit
  },
});

await server.connect(new StdioServerTransport());
```

Calls without a valid proof bundle in `params._meta.bolyra` get back:

```json
{ "isError": true, "content": [{ "type": "text", "text": "Bolyra auth required: missing proof bundle in params._meta.bolyra" }] }
```

## HTTP server (Express / Connect)

```ts
import express from 'express';
import { bolyraAuthMiddleware } from '@bolyra/mcp';
import { createMyMcpHttpHandler } from './my-mcp-http';

const app = express();
app.use(express.json());

app.use('/mcp', bolyraAuthMiddleware({
  resolveCredential: async (commitment) => myRegistry.get(commitment),
  toolPolicy: { read_file: 0b01n, write_file: 0b10n },
}));

app.use('/mcp', createMyMcpHttpHandler());

app.listen(3000);
```

Discovery requests (`initialize`, `tools/list`) pass through unauthenticated, matching how OAuth resource servers expose `.well-known/*` without auth. Only `tools/call` is gated.

## Client side (works for both transports)

```ts
import { attachBolyraProof } from '@bolyra/mcp';
import { createHumanIdentity, createAgentCredential } from '@bolyra/sdk';

const human = await createHumanIdentity(mySecret);
const credential = await createAgentCredential(human, /* ... */);

const auth = await attachBolyraProof(human, credential);
// auth.headers.Authorization → "Bolyra eyJ2I..."
// auth.meta.bolyra → { v: 1, humanProof, agentProof, nonce, credentialCommitment }

// Stdio:
await client.callTool({ name: 'read_file', arguments: { path: '...' }, _meta: auth.meta });
// HTTP:
await fetch('/mcp', { headers: { ...auth.headers, 'content-type': 'application/json' }, ... });
```

## Configuration

```ts
interface BolyraMcpConfig {
  network?: string;                  // default 'base-sepolia' — only affects DID format
  minScore?: number;                 // default 70 — score floor for verified=true
  maxProofAge?: number;              // default 300s — nonce freshness window
  toolPolicy?: ToolPermissionPolicy; // tool name → required permission bitmask
  resolveCredential: (commitment: string) => Promise<AgentCredential | null>;
  sdkConfig?: BolyraConfig;          // rpc/registry/circuit dirs
}
```

The HTTP variant also accepts `authScheme` (default `"Bolyra"`).

## Performance

A single mutual handshake verification is dominated by the Groth16 verify cost (~5–10ms native, ~30–60ms snarkjs). The proof generation itself is client-side (~100ms with rapidsnark). End-to-end overhead per tool call: ~110ms p50 with the full pipeline, comfortably under the perceptible-latency floor for interactive agent workflows.

## License

MIT.
