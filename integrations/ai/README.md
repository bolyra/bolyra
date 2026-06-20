# @bolyra/ai

Bolyra ZKP authentication adapter for the [Vercel AI SDK](https://sdk.vercel.ai). Protect AI tool calls with zero-knowledge proofs.

## Install

```bash
npm install @bolyra/ai ai zod
```

## Quick Start

### 1. Wrap a Language Model (Client Side)

Inject Bolyra auth into outgoing tool calls:

```typescript
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { withBolyraAuth } from '@bolyra/ai';

const model = withBolyraAuth(openai('gpt-4o'), {
  credential: agentCredential,
  operatorPrivateKey: process.env.BOLYRA_OPERATOR_KEY!,
  humanIdentity: humanId,
});

// Tool calls now carry Bolyra proof bundles
const result = await streamText({
  model,
  tools: myTools,
  prompt: 'Read the quarterly report',
});
```

### 2. Verify Incoming Requests (Server Side)

Gate tool execution behind Bolyra auth:

```typescript
// app/api/tools/route.ts (Next.js App Router)
import { bolyraAuthMiddleware } from '@bolyra/ai';

const auth = bolyraAuthMiddleware({
  toolPolicy: {
    'read_file': { requireBitmask: 1 },     // READ_DATA
    'send_payment': { requireBitmask: 4 },   // FINANCIAL_SMALL
  },
});

export async function POST(req: Request) {
  const { verified, reason, context } = await auth.verify(req, 'read_file');
  if (!verified) {
    return Response.json({ error: reason }, { status: 401 });
  }
  // context.did, context.permissionBitmask, context.score available
}
```

### 3. Add Auth Tools for the LLM

Let the model authenticate and manage credentials programmatically:

```typescript
import { generateText } from 'ai';
import { createBolyraTools } from '@bolyra/ai';

const bolyraTools = createBolyraTools({
  credential: agentCredential,
  devMode: true,
});

const result = await generateText({
  model: openai('gpt-4o'),
  tools: { ...bolyraTools, ...myAppTools },
  prompt: 'Authenticate, then check if you can read files',
});
```

## Dev Mode

All three APIs support `devMode: true` for local development without circuit artifacts:

```typescript
// Client
const model = withBolyraAuth(openai('gpt-4o'), { devMode: true });

// Server
const auth = bolyraAuthMiddleware({ devMode: true });

// Tools
const tools = createBolyraTools({ credential, devMode: true });
```

Dev mode uses `createDevIdentities()` from `@bolyra/sdk` to generate fixed-seed test credentials.

## API Reference

### `withBolyraAuth(model, config)`

Wraps a `LanguageModelV1` with Bolyra auth middleware. Returns a new `LanguageModelV1`.

**Config:**

| Field | Type | Description |
|---|---|---|
| `credential` | `AgentCredential` | Agent credential for direct proof generation |
| `operatorPrivateKey` | `string \| Buffer` | Operator key for signing |
| `humanIdentity` | `HumanIdentity` | Human identity for mutual handshake |
| `gateway` | `{ url, apiKey? }` | Gateway mode config |
| `toolPermissions` | `Record<string, Permission>` | Per-tool permission requirements |
| `devMode` | `boolean` | Use mock proofs |
| `network` | `string` | Network identifier (default: `base-sepolia`) |

### `bolyraAuthMiddleware(config)`

Creates a server-side verifier. Returns a `BolyraVerifier` with `verify(req, toolName?)` and `verifyHeader(header, toolName?)`.

### `createBolyraTools(config)`

Creates four Vercel AI SDK tools:

| Tool | Description |
|---|---|
| `bolyra_authenticate` | Generate a proof bundle |
| `bolyra_delegate` | Create a scoped delegation |
| `bolyra_check_permissions` | Check a specific permission |
| `bolyra_credential_info` | Return credential metadata |

## Architecture

```
@bolyra/ai
  src/
    middleware.ts          withBolyraAuth() - model wrapper
    server-middleware.ts   bolyraAuthMiddleware() - request verifier
    tools.ts               createBolyraTools() - tool definitions
    types.ts               Config interfaces
    utils.ts               Bundle encoding, nonce generation
    index.ts               Public exports
```

## License

Apache-2.0
