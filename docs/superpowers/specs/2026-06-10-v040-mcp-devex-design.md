# v0.4.0 Design: MCP Developer Experience

**Date:** 2026-06-10
**Status:** Approved
**Theme:** "npm install → authenticated MCP server in 60 seconds"

## Summary

v0.4.0 focuses `@bolyra/mcp` as the hero integration for AI framework
developers. Three deliverables remove the cold-start barrier: dev mode
(mock proving), a runnable example (protected file server), and an
integration test (MCP SDK client ↔ server). Two packages bump:
`@bolyra/sdk` (provides mock proving) and `@bolyra/mcp` (consumes it).

## Motivation

The MCP package already has solid internals — dual-transport auth
(stdio + HTTP), delegation chain verification, tool-level permission
gating. But a developer who runs `npm install @bolyra/mcp` today hits a
wall: they need circuit artifacts (~50MB), Merkle tree enrollment, EdDSA
key generation, and ~16 seconds of proof time before anything works.

Dev mode eliminates that wall. The example makes the value tangible. The
integration test makes it credible.

## Non-Goals

- PLONK graduation (decided: hold, Groth16 is REQUIRED per spec)
- Cross-network spend accounting (no external pull)
- Other integrations (langchain, crewai, openai-agents, openclaw,
  payment-protocols) — stay at 0.3.x
- Circuit or contract changes — zero on-chain work
- Python SDK changes — `bolyra` (PyPI) stays at 0.3.0

## 1. Dev Mode

### 1.1 `createDevIdentities()`

New export from `@bolyra/sdk`. Returns a `{ human, agent, operatorKey }`
tuple with pre-built in-memory identities. No Merkle tree, no
enrollment, no circuit artifacts.

```typescript
import { createDevIdentities } from '@bolyra/sdk';

const { human, agent, operatorKey } = await createDevIdentities();
```

**Async:** This function is `async` because it uses Poseidon hashing and
EdDSA signing from `circomlibjs` to produce structurally valid objects.
The circomlibjs initialization takes ~50ms on first call. No circuit
artifacts (`.wasm`, `.zkey`, `.ptau`) are loaded — only the hash/sign
primitives.

The identities are structurally valid `HumanIdentity` and
`AgentCredential` objects with deterministic but unique values derived
from a fixed seed. `agent.permissionBitmask` defaults to `0b11111111n`
(all permissions). `agent.expiryTimestamp` is set to `now + 24h`.

### 1.2 Mock Proving

**Breaking change:** The third parameter of `attachBolyraProof` changes
from `sdkConfig?: BolyraConfig` to `options?: { devMode?: boolean;
sdkConfig?: BolyraConfig }`. Same for `attachDelegatedBolyraProof`
(fourth parameter). Migration: `attachBolyraProof(h, a, sdkConfig)`
becomes `attachBolyraProof(h, a, { sdkConfig })`. Acceptable pre-1.0.

When `options.devMode` is true, the client helper:

1. Generates a random session nonce (same as production).
2. Builds a structurally valid `BolyraProofBundle` with mock proof
   arrays (correct length, random values) and real public signal
   positions (nonce at the right index, commitment at the right index).
3. Signs the bundle with an HMAC using a well-known dev key so the
   server can distinguish "intentional dev proof" from "garbage."
4. Returns the same `BolyraClientAuth` shape as production — `headers`,
   `meta`, `bundle`.

Time: ~1ms. No circuit artifacts loaded.

### 1.3 Mock Verification

When `devMode: true` is passed to `withBolyraAuthStdio`,
`bolyraAuthMiddleware`, or `verifyBundle` directly:

1. Checks the HMAC signature instead of calling `sdk.verifyHandshake`.
2. All other checks still run: nonce freshness, bundle version, tool
   policy, delegation chain shape validation, scoring.
3. `BolyraAuthContext.did` is prefixed `did:bolyra:dev:` so downstream
   code can detect dev mode.

### 1.4 Safeguards

- First use logs: `"⚠ Bolyra dev mode — proofs are not
  cryptographically verified. Do not use in production."`
- The dev HMAC key is a well-known constant (not a secret). It exists
  only to distinguish "dev bundle" from "malformed production bundle."
- `resolveCredential` is optional in dev mode — the mock verifier
  constructs a synthetic credential from the bundle's
  `credentialCommitment`. In production mode, `resolveCredential`
  remains required.

### 1.5 Config Shape

```typescript
// Server (stdio)
withBolyraAuthStdio(server, {
  devMode: true,
  toolPolicy: { write_file: 0b10n },
});

// Server (HTTP)
app.use('/mcp', bolyraAuthMiddleware({
  devMode: true,
  toolPolicy: { write_file: 0b10n },
}));

// Client
const auth = await attachBolyraProof(human, agent, { devMode: true });
// Migration from 0.3.x: attachBolyraProof(h, a, sdkConfig)
//                     → attachBolyraProof(h, a, { sdkConfig })
```

**Type change:** `resolveCredential` in `BolyraMcpConfig` moves from
required to optional (`resolveCredential?: ...`). In `verify.ts`, the
production code path throws a clear error if `resolveCredential` is
missing AND `devMode` is not true. In dev mode, the verifier constructs
a synthetic credential from the bundle's `credentialCommitment`.

All other config fields (`network`, `minScore`, `maxProofAge`,
`toolPolicy`, `sdkConfig`) work identically in both modes.

## 2. Hero Example: Protected File Server

### 2.1 Location

`integrations/mcp/examples/protected-file-server/`

### 2.2 Structure

```
examples/protected-file-server/
├── server.ts     # ~60 lines — MCP server with Bolyra auth
├── client.ts     # ~40 lines — client that proves + calls tools
├── package.json  # deps: @bolyra/mcp, @modelcontextprotocol/sdk
└── README.md     # step-by-step walkthrough
```

### 2.3 Server (`server.ts`)

Creates an MCP stdio server with 3 tools:

| Tool | Permission Required | Behavior |
|------|---------------------|----------|
| `list_files` | `READ_DATA` (bit 0) | Lists files in a sandbox dir |
| `read_file` | `READ_DATA` (bit 0) | Reads a file by name |
| `write_file` | `WRITE_DATA` (bit 1) | Writes content to a file |

Wrapped with `withBolyraAuthStdio(server, { devMode: true, toolPolicy })`.

### 2.4 Client (`client.ts`)

1. Creates dev identities.
2. Generates a dev-mode proof bundle.
3. Calls `list_files` — succeeds (agent has all permissions).
4. Calls `read_file` — succeeds.
5. Creates a second agent with `READ_DATA` only.
6. Calls `write_file` with the restricted agent — fails with policy
   error.
7. Prints each result with clear labels.

### 2.5 README

Sections:
1. **Quick start** — `npm install && npx tsx client.ts` (server is
   spawned as a child process by the client, or run side-by-side).
2. **What just happened** — explains the proof flow, tool policy, and
   permission denial.
3. **Try it yourself** — modify permissions, add a tool, tighten policy.
4. **Go to production** — swap `devMode: true` for real config, point at
   circuit artifacts, deploy. Links to the full API docs.
5. **Use with Claude Desktop** — manual setup: add the server to
   `claude_desktop_config.json`, explain what happens when Claude calls
   a tool without a proof bundle (auth required error).

## 3. Integration Test

### 3.1 Location

`integrations/mcp/test/dev-mode-e2e.test.ts`

### 3.2 What It Tests

One test file, ~80 lines, Jest. Uses the MCP SDK's in-memory transport
(no subprocess, no network):

```typescript
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
```

Note: the stdio wrapper reads the proof from `params._meta.bolyra`, not
from transport-level auth, so the test must attach the bundle via the
client's request params rather than `InMemoryTransport.send()` authInfo.

| Test Case | Asserts |
|-----------|---------|
| Valid dev proof + permitted tool | Tool executes, returns result |
| Valid dev proof + insufficient permissions | MCP error: policy denied |
| No proof bundle | MCP error: auth required |
| Expired nonce (mock clock) | MCP error: stale nonce |
| Delegation chain in dev mode | Chain walks, leaf scope used for policy |

### 3.3 What It Does NOT Test

- Real circuit proving (SDK test suite covers this).
- Real Merkle enrollment (contract test suite covers this).
- Actual Claude Desktop / Cursor / Cline (manual QA, documented in
  example README).

## 4. Housekeeping

### 4.1 QUICKSTART.md (`sdk/QUICKSTART.md`)

- Line 75: `formatPlonkProof(agentProof)` → `formatGroth16Proof(agentProof)`.
- Lines 101-103: Update verifier contract name table to match
  `base-sepolia.json` (HumanGroth16Verifier, AgentGroth16Verifier,
  DelegationGroth16Verifier).
- Line 93: Update spec link from `-00.md` to `-01.md`.

### 4.2 MCP README.md

Rewrite to lead with the dev-mode quickstart:
1. Install
2. 10-line server example (dev mode)
3. Full API reference (existing content, reorganized)
4. Production configuration
5. Transport guide (stdio vs HTTP)

### 4.3 CHANGELOG.md

v0.4.0 cohort entry covering: dev mode, protected file server example,
integration test, spec alignment (Groth16 REQUIRED), QUICKSTART fix.

## 5. Cohort Version Bump

| Package | Current | v0.4.0 | Reason |
|---------|---------|--------|--------|
| `@bolyra/sdk` | 0.3.1 | 0.4.0 | Exports `createDevIdentities()` + mock proving |
| `@bolyra/mcp` | 0.3.0 | 0.4.0 | Dev mode, example, integration test |
| `@bolyra/payment-protocols` | 0.3.1 | 0.3.1 | unchanged |
| `@bolyra/openclaw` | 0.3.0 | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.3.0 | 0.3.0 | unchanged |

Per cohort policy, only the two packages with runtime changes bump to
0.4.0. The cohort base advances to 0.4.

## 6. Implementation Order

1. SDK: `createDevIdentities()` + mock proving helpers
2. MCP: dev mode wiring (client + server + verify)
3. MCP: integration test (`dev-mode-e2e.test.ts`)
4. MCP: protected file server example
5. Docs: QUICKSTART.md fix, MCP README rewrite, CHANGELOG entry
6. Release: tag `v0.4.0`, publish via OIDC pipeline

## 7. Success Criteria

- `npm install @bolyra/mcp` + copy the 10-line server example from the
  README → working authenticated MCP server in under 60 seconds.
- `npx tsx client.ts` in the example dir → permission grant + denial
  visible in output.
- `npm test` in `integrations/mcp/` → all tests pass including the new
  dev-mode e2e suite.
- Zero circuit artifacts downloaded. Zero blockchain interaction. Zero
  key generation. Dev mode is self-contained.

## 8. Risks

- **MCP SDK internal handler capture** — `captureExistingHandler` relies
  on internal `_requestHandlers` map shape. If the SDK changes this in a
  minor release, the stdio wrapper breaks. Mitigated by: the integration
  test catches this immediately; the escape hatch
  (`callToolRequestSchema` injection) bypasses the discovery.
- **Dev mode in production** — someone ships `devMode: true` to prod.
  Mitigated by: warning log, `did:bolyra:dev:` prefix, and
  documentation. Not a security boundary — dev mode is explicitly
  documented as "not cryptographically verified."
