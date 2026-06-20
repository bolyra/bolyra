# Vercel AI SDK Adapter — Design Spec

**Date:** 2026-06-20
**Author:** Viswa + Claude Opus 4.6 (PDLC Orchestrator)
**Status:** Draft
**Pipeline:** `pdlc-2026-06-20-vercel-ai-adapter`
**Package:** `@bolyra/ai`

## 1. Overview

The Vercel AI SDK (`ai` on npm) is the dominant framework for building AI-powered applications on Next.js and Vercel. It provides `generateText()`, `streamText()`, and the `useChat()` React hook for server and client-side AI interactions. Tool calling is a first-class citizen via `tool()` with typed `execute` callbacks.

This adapter brings Bolyra ZKP authentication to the Vercel AI SDK ecosystem. It provides three integration surfaces:

1. **`withBolyraAuth(model, config)`** — wraps a language model via `wrapLanguageModel()` middleware to automatically inject Bolyra proof bundles into outgoing tool call headers.
2. **`bolyraAuthMiddleware(config)`** — Express/Next.js middleware that verifies incoming Bolyra credentials on tool call requests (server-side gate).
3. **`createBolyraTools(config)`** — generates Vercel AI SDK `tool()` definitions for Bolyra auth operations (authenticate, delegate, check permissions).

The adapter supports both the **SD-JWT delegation path** (direct proof bundles) and the **gateway path** (delegating verification to a `@bolyra/gateway` instance).

## 2. Motivation

- **Ecosystem reach.** Vercel AI SDK is the default for Next.js AI apps. Supporting it opens Bolyra to the largest JS/TS AI framework audience.
- **Complement to LangChain.** The existing LangChain adapter (Python-first) covers the research/agent-framework segment. `@bolyra/ai` covers the production web-app segment.
- **Framework-native patterns.** Vercel AI SDK has its own middleware system (`wrapLanguageModel`), tool definition format, and streaming protocol. A native adapter is cleaner than forcing users to wire raw SDK calls.

## 3. Architecture

```
@bolyra/ai
├── src/
│   ├── index.ts              # Public exports
│   ├── middleware.ts          # withBolyraAuth() — language model wrapper
│   ├── server-middleware.ts   # bolyraAuthMiddleware() — request verification
│   ├── tools.ts              # createBolyraTools() — tool definitions
│   ├── types.ts              # Config types, option interfaces
│   └── utils.ts              # Proof bundle encoding, header helpers
├── test/
│   ├── middleware.test.ts     # withBolyraAuth unit tests
│   ├── server-middleware.test.ts  # bolyraAuthMiddleware unit tests
│   ├── tools.test.ts         # createBolyraTools unit tests
│   └── integration.test.ts   # End-to-end with mock model + tools
├── package.json
├── tsconfig.json
├── jest.config.js
├── LICENSE
├── NOTICE
└── README.md
```

**Location:** `integrations/ai/` (follows existing pattern: `integrations/gateway/`, `integrations/mcp/`)

### 3.1 Dependencies

| Dependency | Type | Version | Notes |
|---|---|---|---|
| `ai` | peer | `>=3.0.0` | Vercel AI SDK core |
| `@ai-sdk/provider` | peer | `>=0.0.10` | Provider types (LanguageModelV1) |
| `@bolyra/sdk` | dependency | `>=0.5.0` | Core SDK for proof generation/verification |
| `@bolyra/mcp` | dependency | `~0.6.0` | `verifyBundle()`, `checkToolPolicy()` for server-side |
| `zod` | peer | `>=3.0.0` | Required by Vercel AI SDK tool schemas |

### 3.2 Package Metadata

```json
{
  "name": "@bolyra/ai",
  "version": "0.1.0",
  "description": "Bolyra ZKP authentication adapter for Vercel AI SDK — protect AI tool calls with zero-knowledge proofs",
  "license": "Apache-2.0"
}
```

## 4. API Design

### 4.1 `withBolyraAuth(model, config)` — Language Model Wrapper

Wraps a language model using Vercel AI SDK's `wrapLanguageModel()` to intercept tool calls and inject Bolyra auth headers.

```typescript
import { withBolyraAuth } from '@bolyra/ai';
import { openai } from '@ai-sdk/openai';

const model = withBolyraAuth(openai('gpt-4o'), {
  // Credential source: either inline or resolver
  credential: agentCredential,        // AgentCredential from @bolyra/sdk
  operatorPrivateKey: '0x...',        // For signing proof bundles

  // OR: gateway mode — skip proof generation, just add bearer token
  gateway: {
    url: 'https://gateway.example.com',
    apiKey: 'gw_...',
  },

  // Optional: permission requirements per tool
  toolPermissions: {
    'read_file': Permission.READ_DATA,
    'send_payment': Permission.FINANCIAL_SMALL,
  },
});

const result = await generateText({
  model,
  tools: { /* ... */ },
  prompt: 'Read the quarterly report and summarize it',
});
```

**Implementation approach:**

1. Use `wrapLanguageModel()` from the `ai` package.
2. The middleware intercepts the `doGenerate` / `doStream` calls.
3. Before each tool call execution, it:
   - Generates a fresh session nonce.
   - Builds a `BolyraProofBundle` using `@bolyra/sdk`.
   - Attaches the bundle as a base64-encoded `Authorization: Bolyra <bundle>` header in the tool call's execution context.
4. In gateway mode, it attaches a simpler bearer token instead.

**Type signature:**

```typescript
export function withBolyraAuth(
  model: LanguageModelV1,
  config: BolyraAuthConfig,
): LanguageModelV1;

export interface BolyraAuthConfig {
  /** Direct credential mode */
  credential?: AgentCredential;
  operatorPrivateKey?: string;
  humanIdentity?: HumanIdentity;

  /** Gateway mode (mutually exclusive with credential) */
  gateway?: {
    url: string;
    apiKey?: string;
  };

  /** Per-tool permission requirements (tool name → minimum permission) */
  toolPermissions?: Record<string, Permission>;

  /** Dev mode: use mock proofs (no circuit artifacts needed) */
  devMode?: boolean;

  /** Network identifier (default: 'bolyra-mainnet') */
  network?: string;
}
```

### 4.2 `bolyraAuthMiddleware(config)` — Server-Side Verification

Express/Next.js compatible middleware that verifies Bolyra credentials on incoming requests. Reuses `verifyBundle()` and `checkToolPolicy()` from `@bolyra/mcp`.

```typescript
import { bolyraAuthMiddleware } from '@bolyra/ai';

// Next.js API route (App Router)
export async function POST(req: Request) {
  const auth = await bolyraAuthMiddleware({
    network: 'bolyra-mainnet',
    toolPolicy: {
      'read_file': { requireBitmask: 1 },  // READ_DATA
      'send_payment': { requireBitmask: 4, minScore: 80 },
    },
    devMode: process.env.NODE_ENV === 'development',
  });

  const result = auth.verify(req);
  if (!result.verified) {
    return Response.json({ error: result.reason }, { status: 401 });
  }

  // Proceed with tool execution, auth context available
  const { did, permissionBitmask, score } = result.context;
}
```

**Type signature:**

```typescript
export function bolyraAuthMiddleware(
  config: BolyraServerConfig,
): BolyraVerifier;

export interface BolyraServerConfig {
  /** Network identifier */
  network?: string;
  /** Per-tool policies */
  toolPolicy?: Record<string, {
    requireBitmask?: number;
    minScore?: number;
    maxChainDepth?: number;
  }>;
  /** Dev mode: accept mock proofs */
  devMode?: boolean;
  /** Custom credential resolver */
  resolveCredential?: (commitment: string) => Promise<AgentCredential | null>;
  /** Nonce store (default: in-memory) */
  nonceStore?: NonceStore;
}

export interface BolyraVerifier {
  /** Verify a request's Bolyra authorization */
  verify(req: Request, toolName?: string): Promise<BolyraVerifyResult>;
  /** Verify raw authorization header value */
  verifyHeader(authHeader: string, toolName?: string): Promise<BolyraVerifyResult>;
}

export interface BolyraVerifyResult {
  verified: boolean;
  reason?: string;
  context?: BolyraAuthContext;
}
```

### 4.3 `createBolyraTools(config)` — Auth Tool Definitions

Creates Vercel AI SDK-compatible tool definitions for common Bolyra auth operations. These tools can be added to any `generateText()` or `streamText()` call so the LLM can programmatically authenticate, delegate, or check permissions.

```typescript
import { createBolyraTools } from '@bolyra/ai';

const bolyraTools = createBolyraTools({
  credential: agentCredential,
  operatorPrivateKey: '0x...',
  devMode: true,
});

const result = await generateText({
  model: openai('gpt-4o'),
  tools: {
    ...bolyraTools,
    ...myAppTools,
  },
  prompt: 'Authenticate and then read the file',
});
```

**Tools provided:**

| Tool Name | Description | Parameters |
|---|---|---|
| `bolyra_authenticate` | Generate a proof bundle for the current agent credential | `{ nonce?: string }` |
| `bolyra_delegate` | Create a delegated credential with narrowed permissions | `{ permissions: number, ttlSeconds: number }` |
| `bolyra_check_permissions` | Check if the current credential has a given permission | `{ permission: string }` |
| `bolyra_credential_info` | Return metadata about the current credential (DID, expiry, permissions) | `{}` |

**Type signature:**

```typescript
export function createBolyraTools(
  config: BolyraToolsConfig,
): Record<string, CoreTool>;

export interface BolyraToolsConfig {
  credential: AgentCredential;
  operatorPrivateKey?: string;
  humanIdentity?: HumanIdentity;
  devMode?: boolean;
  network?: string;
}
```

## 5. Integration Patterns

### 5.1 Client-Side: Protecting Outgoing Tool Calls

The primary use case: an AI app making tool calls to external services that require Bolyra auth.

```typescript
// app/api/chat/route.ts (Next.js App Router)
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { withBolyraAuth } from '@bolyra/ai';

const authedModel = withBolyraAuth(openai('gpt-4o'), {
  credential: loadCredential(),
  operatorPrivateKey: process.env.BOLYRA_OPERATOR_KEY!,
});

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({ model: authedModel, messages, tools: myTools });
  return result.toDataStreamResponse();
}
```

### 5.2 Server-Side: Verifying Incoming Tool Calls

An MCP server or API endpoint that gates tool execution behind Bolyra auth.

```typescript
// app/api/tools/route.ts
import { bolyraAuthMiddleware } from '@bolyra/ai';

const auth = bolyraAuthMiddleware({
  toolPolicy: { 'query_db': { requireBitmask: 1 } },
});

export async function POST(req: Request) {
  const { verified, reason, context } = await auth.verify(req, 'query_db');
  if (!verified) return Response.json({ error: reason }, { status: 401 });
  // ... execute tool
}
```

### 5.3 Full Stack: Both Sides

```typescript
// Client side: withBolyraAuth wraps the model
// Server side: bolyraAuthMiddleware verifies incoming calls
// Result: end-to-end Bolyra auth without any manual header management
```

## 6. Dev Mode

Like all Bolyra integrations, the adapter supports dev mode:

- `devMode: true` uses `createDevIdentities()` from `@bolyra/sdk`
- No circuit artifacts required
- Mock proofs pass server-side verification when the server is also in dev mode
- Tool calls show `[DEV]` prefix in receipts

## 7. Testing Strategy

| Layer | What | How |
|---|---|---|
| Unit | `withBolyraAuth` wraps model correctly | Mock `LanguageModelV1`, verify middleware intercepts |
| Unit | `bolyraAuthMiddleware` verifies/rejects | Construct proof bundles, verify pass/fail |
| Unit | `createBolyraTools` produces valid tool schemas | Check Zod schemas, call execute functions |
| Integration | End-to-end with dev mode | `generateText()` with mock model, Bolyra tools, verify auth flow |
| Conformance | Proof bundle format | Verify bundles match `@bolyra/mcp` expected format |

All tests use dev mode (no circuit artifacts). Test command: `cd integrations/ai && npm test`.

## 8. Non-Goals (v0.1)

- **React hooks** (`useBolyraAuth()`). Will come in v0.2 once the core API stabilizes.
- **Edge Runtime support.** The `@bolyra/sdk` uses Node crypto primitives. Edge compatibility requires a separate effort.
- **Multi-tenant credential management.** v0.1 assumes a single credential per model wrapper instance.
- **Receipt generation.** Server middleware does not generate `@bolyra/receipts` in v0.1. Can be added as an option in v0.2.

## 9. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Vercel AI SDK API instability | Breaking changes in middleware API | Pin `ai` peer dep to `>=3.0.0`, test against latest |
| `wrapLanguageModel` limitations | May not expose tool call context at the right layer | Fall back to custom provider wrapper if needed |
| Bundle size | `@bolyra/sdk` pulls in snarkjs/noble | Tree-shaking via ESM exports; document that dev mode is lighter |
| Naming collision | `@bolyra/ai` vs Vercel's `ai` package | Different scope (`@bolyra/`), no collision. Package description clearly differentiates |

## 10. Standards Impact

**N/A** — no protocol, circuit, or spec changes. This is a pure integration package that consumes existing `@bolyra/sdk` and `@bolyra/mcp` APIs. No changes to `spec/`, `circuits/`, or protocol-level SDK functions.

## 11. Security Impact

**Low surface addition.** The adapter does not introduce new cryptographic operations:

- Proof generation delegates to `@bolyra/sdk` (existing, audited path).
- Proof verification delegates to `@bolyra/mcp` `verifyBundle()` (existing, audited path).
- Nonce management reuses `MemoryNonceStore` from `@bolyra/mcp`.
- No new key material handling beyond passing through `operatorPrivateKey` (same as gateway/MCP patterns).

**One area to watch:** the `withBolyraAuth` middleware holds the operator private key in memory for the lifetime of the model wrapper. This matches the gateway pattern but should be documented. Users handling highly sensitive keys should use the gateway mode instead (key stays server-side).

## 12. File Manifest

All new files under `integrations/ai/`:

| File | Purpose |
|---|---|
| `package.json` | Package manifest with peer deps |
| `tsconfig.json` | TypeScript config (strict, ESM) |
| `jest.config.js` | Test configuration |
| `LICENSE` | Apache 2.0 (copy from root) |
| `NOTICE` | Attribution notice |
| `README.md` | Usage docs with examples |
| `src/index.ts` | Public API exports |
| `src/middleware.ts` | `withBolyraAuth()` implementation |
| `src/server-middleware.ts` | `bolyraAuthMiddleware()` implementation |
| `src/tools.ts` | `createBolyraTools()` implementation |
| `src/types.ts` | Config and option types |
| `src/utils.ts` | Proof bundle encoding, header helpers |
| `test/middleware.test.ts` | Unit tests for model wrapper |
| `test/server-middleware.test.ts` | Unit tests for server middleware |
| `test/tools.test.ts` | Unit tests for tool definitions |
| `test/integration.test.ts` | End-to-end integration test |
