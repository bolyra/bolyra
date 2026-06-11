# Protected File Server — Bolyra MCP Example

A complete, runnable example of a permission-gated MCP server using Bolyra dev mode.
No ZK circuit artifacts required — dev mode uses mock proofs so it runs instantly.

## Quick start

```bash
npm install
npm run demo
```

Expected output: two successful reads followed by one permission-denied write.

## What just happened

1. **Server startup** — `server.ts` creates a temporary sandbox directory, seeds it
   with `hello.txt`, and registers three tools:

   | Tool | Required permission |
   |---|---|
   | `list_files` | `READ_DATA` (bit 0) |
   | `read_file`  | `READ_DATA` (bit 0) |
   | `write_file` | `WRITE_DATA` (bit 1) |

   The server wraps itself with `withBolyraAuthStdio({ devMode: true, toolPolicy })`.
   Every `tools/call` request must carry a Bolyra proof bundle in `params._meta.bolyra`.

2. **Client — full-permission identity** — `client.ts` calls `createDevIdentities()`
   (default bitmask `0b11111111`), then `attachBolyraProof(human, agent, { devMode: true })`
   to generate a mock proof bundle. The bundle travels in `_meta.bolyra` on each tool call.
   `list_files` and `read_file` succeed because `READ_DATA` is set.

3. **Client — read-only identity** — a second set of identities is created with
   `permissionBitmask: 0b01n` (READ_DATA only). `write_file` is called with this
   proof; the server checks the policy, finds `WRITE_DATA` (bit 1) missing, and
   returns `Bolyra policy denied: …`. The underlying handler never runs.

The proof bundle is a base64-encoded JSON object. In dev mode the ZK proofs are
replaced with mock values — verification only checks the dev flag and the
permission bitmask extracted from the public signals.

## Try it yourself

**Add a new tool with a higher permission requirement:**

```ts
// server.ts
mcpServer.tool('delete_file', 'Delete a file', { name: z.string() }, async ({ name }) => { … });

// toolPolicy
toolPolicy: { …, delete_file: 4n }  // FINANCIAL_SMALL — just for illustration
```

**Test an intermediate bitmask:**

```ts
// client.ts
const { human, agent } = await createDevIdentities({ permissionBitmask: 0b11n }); // READ + WRITE
```

**Deny everything by passing no proof at all:**

```ts
await client.callTool({ name: 'list_files', arguments: {} });
// → Bolyra auth required: missing proof bundle in params._meta.bolyra
```

## Go to production

Swap out two lines:

```ts
// server: remove devMode
withBolyraAuthStdio(mcpServer.server, { toolPolicy });

// client: remove devMode — proveHandshake runs the real ZK circuit
const auth = await attachBolyraProof(human, agent);
```

Production mode runs Groth16/PLONK proofs via the `@bolyra/sdk` prover.
Set `BOLYRA_RAPIDSNARK` to point at the compiled `rapidsnark_prover` binary
(`circuits/build/rapidsnark_prover`) for ~10x faster proving vs snarkjs.

## Claude Desktop note

Claude Desktop does not currently attach Bolyra proof bundles to MCP tool calls.
To use Bolyra auth with Claude Desktop today, run a thin proxy that injects
the proof bundle before forwarding to this server. A reference proxy lives at
`examples/mcp-demo/dist/bolyra-proxy.js`.
