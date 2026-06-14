# @bolyra/mcp

Gate MCP tool calls so only authorized agents can call sensitive tools.

## Quick Start (60 seconds)

```bash
npm install @bolyra/mcp @bolyra/sdk @modelcontextprotocol/sdk
```

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withBolyraAuthStdio } from '@bolyra/mcp';

const server = new McpServer({ name: 'my-server', version: '1.0.0' });

server.tool('read_file', { path: { type: 'string' } }, async (args) => ({
  content: [{ type: 'text', text: `Reading ${args.path}` }],
}));

withBolyraAuthStdio(server.server, {
  devMode: true,
  toolPolicy: {
    // 1n = READ_DATA, 2n = WRITE_DATA (BigInt — add 'n' suffix)
    read_file: 1n,
  },
});
```

That's it. Every `tools/call` now requires a valid Bolyra proof bundle.

## Dev mode (full example)

Dev mode uses mock proofs — no circuit artifacts, no trusted setup, instant startup. Use it to build and test your server before wiring real ZKP verification.

```ts
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { withBolyraAuthStdio } from '@bolyra/mcp';

// Server
const server = new McpServer({ name: 'my-server', version: '1.0.0' });

server.tool('read_file', { path: { type: 'string' } }, async (args) => ({
  content: [{ type: 'text', text: 'file contents...' }],
}));

withBolyraAuthStdio(server.server, {
  devMode: true,
  toolPolicy: {
    // 1n = READ_DATA, 2n = WRITE_DATA (BigInt — add 'n' suffix)
    read_file: 1n,
    write_file: 2n,
  },
});

await server.connect(new StdioServerTransport());
```

Client side:

```ts
import { createDevIdentities, attachBolyraProof } from '@bolyra/sdk';

const { human, agent } = await createDevIdentities();
const auth = await attachBolyraProof(human, agent, { devMode: true });

// stdio
await client.callTool({ name: 'read_file', arguments: { path: '/tmp/x' }, _meta: auth.meta });
// HTTP
await fetch('/mcp', { headers: { ...auth.headers }, ... });
```

## How it works

Every `tools/call` request must carry a **proof bundle**: a pair of Groth16 proofs (one from the human's circuit, one from the agent's) bound to a shared session nonce.

The server side:

1. Extracts the bundle from `params._meta.bolyra` (stdio) or the `Authorization: Bolyra <base64>` header (HTTP).
2. Verifies the handshake — both proofs, nonce freshness, score floor.
3. Checks the tool's permission policy against the agent's effective bitmask.
4. Attaches a `BolyraAuthContext` to the request for downstream handlers.
5. Rejects with an MCP error if any step fails.

Discovery calls (`initialize`, `tools/list`) pass through unauthenticated.

**Delegation chains** (v=2 bundles) narrow scope from root credential to leaf agent across multiple hops. The effective bitmask seen by tool policies is always the leaf's — the most-restricted scope.

## API reference

### Server — stdio

```ts
withBolyraAuthStdio(server: McpServer, config: BolyraMcpConfig): void
```

Wraps an `McpServer` instance. Must be called before `server.connect(transport)`.

### Server — HTTP

```ts
bolyraAuthMiddleware(config: BolyraMcpHttpConfig): express.RequestHandler
```

Express middleware. Mount before your MCP HTTP handler. Rejects unauthenticated `tools/call` requests with HTTP 401.

### Client helpers

```ts
attachBolyraProof(
  human: HumanIdentity,
  agent: AgentCredential,
  options?: AttachProofOptions,
): Promise<BolyraClientAuth>
```

Runs a handshake and returns `{ headers, meta, bundle }`. Pass `options.devMode = true` to skip real proving and emit a mock bundle.

```ts
attachDelegatedBolyraProof(
  human: HumanIdentity,
  rootCred: AgentCredential,
  hops: DelegationHopSpec[],
  options?: AttachProofOptions,
): Promise<BolyraClientAuth>
```

Like `attachBolyraProof` but walks a delegation chain and returns a v=2 bundle.

### Verification

```ts
verifyBundle(bundle: BolyraProofBundle, config: BolyraMcpConfig): Promise<BolyraAuthContext>
```

Verify a bundle directly — useful for custom transports or offline verification.

```ts
checkToolPolicy(
  toolName: string,
  ctx: BolyraAuthContext,
  policy: ToolPermissionPolicy,
): { allowed: boolean; reason?: string }
```

Check a `BolyraAuthContext` against a tool's required bitmask.

### Dev identities (re-exported from SDK)

```ts
createDevIdentities(options?: DevIdentityOptions): Promise<DevIdentities>
```

Returns fixed-seed `{ human, agent, operatorKey }` — deterministic, no circuit artifacts required. Logs a warning on first call. Never use in production.

## Production configuration

Swap `devMode: true` for a real `resolveCredential` resolver and point the SDK at your circuit artifacts:

```ts
withBolyraAuthStdio(server, {
  resolveCredential: async (commitment) => myRegistry.get(commitment),
  toolPolicy: {
    // 1n = READ_DATA, 2n = WRITE_DATA (BigInt — add 'n' suffix)
    read_file: 1n,
    write_file: 2n,
  },
  sdkConfig: {
    circuitDir: '/path/to/circuits/build',
    rpcUrl: 'https://sepolia.base.org',
    registryAddress: '0x2781dF8b6381462d881C833Fb703d68c661c9577',
  },
});
```

Full config interface:

```ts
interface BolyraMcpConfig {
  network?: string;          // DID network label (default: 'base-sepolia')
  minScore?: number;         // Minimum score floor 0–100 (default: 70)
  maxProofAge?: number;      // Nonce freshness window in seconds (default: 300)
  toolPolicy?: ToolPermissionPolicy;
  devMode?: boolean;         // Mock verification — dev/test only
  resolveCredential?: (commitment: string) => Promise<AgentCredential | null>;
  sdkConfig?: BolyraConfig;
}
```

The HTTP variant adds `authScheme?: string` (default `"Bolyra"`).

## Transport guide

| Transport | Bundle location | Notes |
|---|---|---|
| stdio (Claude Desktop, Cursor, Cline) | `params._meta.bolyra` | MCP spec defines no stdio auth surface; `_meta` is the only protocol-level field |
| HTTP / SSE / Streamable-HTTP | `Authorization: Bolyra <base64-bundle>` | Custom auth scheme per RFC 7235; aligns with OAuth 2.1 resource-server pattern |

Both produce the same `BolyraAuthContext` on the server side. Tool handlers don't need to know which transport was used.

## Example

See [`examples/protected-file-server/`](./examples/protected-file-server/) for a complete stdio server + client pair using dev mode. Run it with:

```bash
cd integrations/mcp
npm run example:protected-file-server
```
