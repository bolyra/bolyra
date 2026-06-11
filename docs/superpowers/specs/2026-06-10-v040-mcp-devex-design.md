# v0.4.0 Design: MCP Developer Experience

**Date:** 2026-06-10
**Status:** Approved (revised after Codex review)
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

## 0. Prerequisite: Fix Nonce Semantics (pre-v0.4.0)

**Bug (Codex finding):** `proveHandshake` in `sdk/src/handshake.ts:47`
defaults nonce to `BigInt(Date.now())` (milliseconds), but
`verifyBundle` in `integrations/mcp/src/verify.ts:218` treats nonce as
Unix seconds when computing age: `const nonceAgeSec = Number(now - nonce)`.
This means production nonces appear ~1000x older than they are, causing
every proof to fail the freshness check unless `maxProofAge` is set
absurdly high.

**Fix (must land before any v0.4.0 work):**
- `sdk/src/handshake.ts`: change default nonce from `BigInt(Date.now())`
  to `BigInt(Math.floor(Date.now() / 1000))` (Unix seconds).
- `verify.ts:202`: `const now = BigInt(Math.floor(Date.now() / 1000))`
  (already correct — confirm it stays seconds).
- Add a test that generates a proof with the default nonce and verifies
  it passes freshness within 5 seconds.
- Ship as `@bolyra/sdk@0.3.2` patch before the v0.4.0 cohort.

## 1. Dev Mode

### 1.1 `createDevIdentities()`

New export from `@bolyra/sdk`, added to `sdk/src/index.ts`. Returns a
`{ human, agent, operatorKey }` tuple with pre-built in-memory
identities. No Merkle tree, no enrollment, no circuit artifacts.

```typescript
import { createDevIdentities } from '@bolyra/sdk';

const { human, agent, operatorKey } = await createDevIdentities();
```

**Async:** This function is `async` because it uses Poseidon hashing and
EdDSA signing from `circomlibjs` to produce structurally valid objects.
The circomlibjs initialization takes ~50ms on first call. No circuit
artifacts (`.wasm`, `.zkey`, `.ptau`) are loaded — only the hash/sign
primitives.

**Implementation file:** `sdk/src/dev.ts`, exported via `sdk/src/index.ts`.

**Identity shape:** Uses a fixed seed (`0xDEV0`) to derive deterministic
keys via the same `derivePublicKeyScalar()` and `eddsaSign()` paths as
production (`sdk/src/identity.ts:71,102`). The result is structurally
identical to production identities — real EdDSA signature, real Poseidon
commitment, real public key coordinates. "No key generation" in the
motivation refers to the user not needing to generate or manage keys;
the function still derives keys internally via circomlibjs.

**Determinism:** Given the same seed, the derived `secret`, `publicKey`,
`commitment`, `modelHash`, `operatorPublicKey`, and `signature` are
identical across calls. `expiryTimestamp` is the one non-deterministic
field — set to `BigInt(Math.floor(Date.now() / 1000)) + 86400n` (now +
24h). Callers who need fully deterministic output can pass an optional
`{ expiryTimestamp }` override.

**`agent` fields:**
- `permissionBitmask`: `0b11111111n` (all permissions)
- `modelHash`: `BigInt('0xDEV0MODEL')` (fixed, recognizable)
- `expiryTimestamp`: `now + 24h` (or caller override)
- `signature`: valid EdDSA signature over `(modelHash, operatorPubKey,
  permissionBitmask, expiryTimestamp, commitment)` — same circuit input
  order as production

**Restricted dev agent:** `createDevIdentities({ permissionBitmask: 0b01n })`
returns an agent with only `READ_DATA`. The example uses this to demo
permission denial.

### 1.2 Mock Proving

**Breaking change:** The third parameter of `attachBolyraProof` changes
from `sdkConfig?: BolyraConfig` to `options?: { devMode?: boolean;
sdkConfig?: BolyraConfig }`. Same for `attachDelegatedBolyraProof`
(fourth parameter). Migration: `attachBolyraProof(h, a, sdkConfig)`
becomes `attachBolyraProof(h, a, { sdkConfig })`. Acceptable pre-1.0.

When `options.devMode` is true, the client helper:

1. Generates a random session nonce as Unix seconds (same unit as
   production after the Section 0 fix).
2. Builds a structurally valid `BolyraProofBundle` with:
   - Mock proof arrays: `uint256[8]` filled with random values (correct
     Groth16 flattened shape).
   - Real public signal positions: nonce at index 4 (human) / index 5
     (agent), commitment at index 0, scopeCommitment at index 2.
   - `credentialCommitment` from the agent credential.
3. Sets `bundle._dev = true` as a format marker (see 1.2.1).
4. Returns the same `BolyraClientAuth` shape as production — `headers`,
   `meta`, `bundle`.

Time: ~1ms. No circuit artifacts loaded.

#### 1.2.1 Bundle Schema Change

`BolyraProofBundle` gains an optional `_dev?: boolean` field:

```typescript
export interface BolyraProofBundle {
  v: 1 | 2;
  humanProof: Proof;
  agentProof: Proof;
  nonce: string;
  credentialCommitment: string;
  delegationChain?: BolyraDelegationLink[];
  /** Present and true only in dev-mode bundles. Not a security boundary. */
  _dev?: boolean;
}
```

**Why not HMAC (Codex finding):** The original spec proposed an HMAC
with a well-known key. Codex correctly noted this is misleading — a
public key means anyone can forge the "signature," so it provides no
authentication. A boolean `_dev` marker is honest: it says "this is a
dev bundle" without pretending to be a cryptographic check. The server
in dev mode accepts `_dev: true` bundles; in production mode, it rejects
them.

### 1.3 Mock Verification

When `devMode: true` is passed to `withBolyraAuthStdio`,
`bolyraAuthMiddleware`, or `verifyBundle` directly:

1. Checks `bundle._dev === true`. If `_dev` is missing or false,
   falls through to production verification (so dev clients can't
   accidentally bypass a production server).
2. Skips `sdk.verifyHandshake()` — returns a synthetic `verifyResult`:
   ```typescript
   const verifyResult = {
     verified: true,
     humanNullifier: BigInt(bundle.humanProof.publicSignals[1]),
     scopeCommitment: BigInt(bundle.agentProof.publicSignals[2]),
   };
   ```
3. All other checks still run: nonce freshness (against real clock),
   bundle version, tool policy gate.
4. **Delegation chain in dev mode:** chain shape validation runs (hop
   count, field parsing, expiry checks), but `sdk.verifyDelegation()`
   and `sdk.poseidon3()` calls are skipped. The mock walks the chain,
   extracts `delegateeScope` and `delegateeCommitment` from each link,
   and uses the leaf values as effective permissions. This means
   delegation in dev mode tests the policy/permission flow but not
   cryptographic chain binding.
5. Scoring in dev mode: all score components that don't depend on real
   ZKP verification award full points. Dev bundles score 100 by default
   (unless nonce is stale or permissions are missing).
6. `BolyraAuthContext.did` is prefixed `did:bolyra:dev:`.

#### 1.3.1 Verifier Restructuring (Codex finding)

Current `verifyBundle` in `verify.ts:90` calls `resolveCredential`
unconditionally before proof verification. With dev mode:

```
if (config.devMode) {
  // Build synthetic credential from bundle fields
  credential = buildSyntheticCredential(bundle);
} else {
  if (!config.resolveCredential) {
    throw new Error('resolveCredential is required in production mode');
  }
  credential = await config.resolveCredential(bundle.credentialCommitment);
}
```

The synthetic credential uses:
- `permissionBitmask` from `agentProof.publicSignals[3]`
- `expiryTimestamp` from `agentProof.publicSignals[4]`
- `commitment` from `bundle.credentialCommitment`
- Other fields (`modelHash`, `operatorPublicKey`, `signature`) set to
  placeholder values — they are not checked in dev mode

### 1.4 Safeguards

- First use logs: `"⚠ Bolyra dev mode — proofs are not
  cryptographically verified. Do not use in production."`
- Production servers reject `_dev: true` bundles (the `_dev` check only
  fires when the server's own `devMode` config is true).
- `did:bolyra:dev:` prefix lets downstream code detect dev mode.
- **No replay protection beyond nonce age (acknowledged).** Dev bundles
  with a fresh nonce can be replayed within `maxProofAge` (default
  300s). This is acceptable for dev mode — the threat model is
  "developer testing locally," not "adversary replaying proofs."

### 1.5 Config Shape

```typescript
// Server (stdio)
withBolyraAuthStdio(server, {
  devMode: true,
  toolPolicy: { write_file: 2n },  // bigint literal in code
});

// Server (HTTP)
app.use('/mcp', bolyraAuthMiddleware({
  devMode: true,
  toolPolicy: { write_file: 2n },
}));

// Client
const auth = await attachBolyraProof(human, agent, { devMode: true });
// Migration from 0.3.x: attachBolyraProof(h, a, sdkConfig)
//                     → attachBolyraProof(h, a, { sdkConfig })
```

**Type changes to `BolyraMcpConfig`:**
- Add `devMode?: boolean`
- `resolveCredential` moves from required to optional
  (`resolveCredential?: ...`). Runtime throws if missing AND `devMode`
  is not true.

**`toolPolicy` and bigint (Codex finding):** `ToolPermissionPolicy` uses
`bigint` values, which cannot be represented in JSON. This is fine for
programmatic config (the primary use case), but the README must show
code examples, not JSON config files. If JSON config is needed in the
future, add a `toolPolicyHex` alternative that accepts hex strings.

#### 1.5.1 HTTP Auth Context Fix (Codex finding)

Current `server-http.ts:108` writes `req.bolyra = authCtx`, but MCP SDK
HTTP transports do not propagate `req.bolyra` to handler `extra`. The
fix: also write to `req.auth` (which MCP SDK transports forward to
`extra.authInfo`):

```typescript
req.bolyra = authCtx;
(req as any).auth = { bolyra: authCtx };
```

This is a production bug fix that should ship with v0.4.0, not a
dev-mode-only change.

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

**Wrapper ordering (Codex finding):** The stdio wrapper comments in
`server-stdio.ts` are contradictory — line 39 says "call BEFORE
registerTool" but line 58 throws unless a handler exists. The example
must use the correct order: `registerTool()` first, then
`withBolyraAuthStdio()`. The contradiction in the source comments
should be fixed as part of v0.4.0.

### 2.4 Client (`client.ts`)

1. Creates dev identities.
2. Generates a dev-mode proof bundle.
3. Calls `list_files` — succeeds (agent has all permissions).
4. Calls `read_file` — succeeds.
5. Creates a second agent with `READ_DATA` only via
   `createDevIdentities({ permissionBitmask: 0b01n })`.
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
5. **Claude Desktop note** — explains that Claude Desktop does not
   currently attach Bolyra proof bundles to MCP calls, so tools will
   return "auth required." This is a limitation of the current MCP auth
   landscape, not a Bolyra bug. The section documents the expected
   behavior honestly rather than claiming a working integration.

## 3. Integration Test

### 3.1 Location

`integrations/mcp/test/dev-mode-e2e.test.ts`

### 3.2 Transport Strategy (Codex finding)

Codex found that `InMemoryTransport` may not be exported by the
installed MCP SDK version (1.29.0). Before implementation, verify:

```bash
node -e "require('@modelcontextprotocol/sdk/inMemory.js')" 2>&1
```

**If available:** Use `InMemoryTransport.createLinkedPair()`.

**If not available (fallback):** Use the real `McpServer` + `StdioServerTransport`
with a subprocess spawn. The test spawns the server as a child process
and communicates via stdin/stdout. Slower (~2s vs ~500ms) but guaranteed
to work and exercises the real `captureExistingHandler` code path that
an in-memory mock would skip.

**Preference: subprocess.** Even if `InMemoryTransport` exists, the
subprocess approach is more valuable because it exercises the full
stdio wrapper path including `captureExistingHandler`, `loadCallToolRequestSchema`,
and the real `setRequestHandler` interception. An in-memory transport
would bypass these and miss the exact breakage the test is supposed to
catch.

### 3.3 What It Tests

One test file, ~100 lines, Jest.

| Test Case | Asserts |
|-----------|---------|
| Valid dev proof + permitted tool | Tool executes, returns result |
| Valid dev proof + insufficient permissions | MCP error: policy denied |
| No proof bundle | MCP error: auth required |
| Expired nonce (mock clock) | MCP error: stale nonce |
| Dev bundle against non-dev server | MCP error: verification failed (not silently accepted) |

### 3.4 What It Does NOT Test

- Real circuit proving (SDK test suite covers this).
- Real Merkle enrollment (contract test suite covers this).
- Actual Claude Desktop / Cursor / Cline (manual QA, documented in
  example README as expected-failure behavior).
- Delegation chain in dev mode (tested via unit test in
  `test/verify.test.ts`, not via the e2e subprocess path — delegation
  requires too much ceremony for a transport-level test).

### 3.5 tsconfig Note (Codex finding)

MCP's `tsconfig.json` excludes `test/`. Type errors in the new e2e test
only surface under Jest/ts-jest, not during `npm run typecheck`. Either:
- Add a separate `tsconfig.test.json` that includes `test/`, or
- Run `npx tsc --noEmit -p tsconfig.test.json` in CI alongside Jest.

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
integration test, nonce fix, HTTP auth context fix, spec alignment
(Groth16 REQUIRED), QUICKSTART fix.

### 4.4 Fix stdio wrapper ordering comments

`server-stdio.ts` lines 39-46: rewrite the JSDoc to match reality.
The correct order is: `registerTool()` first, then
`withBolyraAuthStdio()`. The wrapper captures the previously-registered
handler and chains through it.

## 5. Cohort Version Bump

| Package | Current | v0.4.0 | Reason |
|---------|---------|--------|--------|
| `@bolyra/sdk` | 0.3.1 → 0.3.2 (nonce fix) → 0.4.0 | 0.4.0 | Nonce fix + `createDevIdentities()` + mock proving |
| `@bolyra/mcp` | 0.3.0 | 0.4.0 | Dev mode, HTTP auth fix, example, integration test |
| `@bolyra/payment-protocols` | 0.3.1 | 0.3.1 | unchanged |
| `@bolyra/openclaw` | 0.3.0 | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.3.0 | 0.3.0 | unchanged |

**Peer dep bump (Codex finding):** `@bolyra/mcp` declares
`"@bolyra/sdk": "^0.3.0"` in `package.json`. This must become
`"@bolyra/sdk": "^0.4.0"` so npm resolves the SDK version that exports
`createDevIdentities`. Without this, `npm install` can resolve to
`@bolyra/sdk@0.3.2` which lacks dev mode.

Per cohort policy, only the two packages with runtime changes bump to
0.4.0. The cohort base advances to 0.4.

## 6. Implementation Order

0. **Nonce fix** — `sdk/src/handshake.ts` ms→seconds, test, ship as
   `@bolyra/sdk@0.3.2` patch.
1. **SDK: `createDevIdentities()`** — `sdk/src/dev.ts`, export from
   `sdk/src/index.ts`, unit tests.
2. **MCP: type changes** — `_dev` on `BolyraProofBundle`, `devMode` on
   `BolyraMcpConfig`, `resolveCredential` optional.
3. **MCP: dev mode wiring** — client mock proving (`client.ts`), server
   mock verification (`verify.ts`), HTTP auth context fix
   (`server-http.ts`), wrapper comment fix (`server-stdio.ts`).
4. **MCP: integration test** — `test/dev-mode-e2e.test.ts` via
   subprocess transport.
5. **MCP: protected file server example** — `examples/protected-file-server/`.
6. **Docs** — QUICKSTART.md fix, MCP README rewrite, CHANGELOG entry.
7. **Release** — bump `package.json` versions, update peer dep, rebuild
   `dist/`, run `npm pack --dry-run` to verify published layout, tag
   `v0.4.0`, publish via OIDC pipeline.

## 7. Success Criteria

- `npm install @bolyra/mcp` + copy the 10-line server example from the
  README → working authenticated MCP server in under 60 seconds.
- `npx tsx client.ts` in the example dir → permission grant + denial
  visible in output.
- `npm test` in `integrations/mcp/` → all tests pass including the new
  dev-mode e2e suite.
- Zero circuit artifacts downloaded. Zero blockchain interaction.
- Nonce freshness check passes with default `maxProofAge` (300s) in
  both dev and production modes.

## 8. Risks

- **MCP SDK internal handler capture** — `captureExistingHandler` relies
  on internal `_requestHandlers` map shape. If the SDK changes this in a
  minor release, the stdio wrapper breaks. Mitigated by: the subprocess
  integration test catches this immediately; the escape hatch
  (`callToolRequestSchema` injection) bypasses the discovery.
- **Dev mode in production** — someone ships `devMode: true` to prod.
  Mitigated by: warning log, `did:bolyra:dev:` prefix, `_dev` bundle
  marker rejected by non-dev servers. Not a security boundary — dev
  mode is explicitly documented as "not cryptographically verified."
- **HTTP batched JSON-RPC (Codex finding)** — `bolyraAuthMiddleware`
  only gates request bodies whose top-level `method` is `tools/call`.
  Batched JSON-RPC arrays (multiple method calls in one HTTP body) are
  not gated. This is a pre-existing limitation, not introduced by
  v0.4.0. Document it in the HTTP transport section of the README as a
  known limitation. Fix is out of scope for v0.4.0.
- **Package boundary (Codex finding)** — `BolyraProofBundle` is defined
  in `@bolyra/mcp`, but mock proving lives in `@bolyra/sdk`. The SDK
  mock helpers return raw proof/signal arrays, not a full bundle — the
  MCP client helper (`attachBolyraProof`) assembles the bundle. This
  keeps the package boundary clean: SDK owns crypto primitives, MCP
  owns wire format.

## Appendix: Codex Review Findings Tracker

| Finding | Severity | Resolution |
|---------|----------|------------|
| Nonce ms vs seconds | Critical | Section 0: pre-v0.4.0 patch |
| Bundle has no dev marker field | Critical | Section 1.2.1: `_dev` boolean |
| HMAC is misleading (public key) | Critical | Section 1.2.1: replaced with `_dev` boolean |
| Mock verifyResult shape undefined | Critical | Section 1.3: synthetic shape defined |
| resolveCredential required, called unconditionally | Critical | Section 1.3.1: restructured |
| devMode not in config types | Critical | Section 1.5: type changes listed |
| HTTP req.bolyra doesn't reach handlers | Critical | Section 1.5.1: auth context fix |
| InMemoryTransport may not exist | High | Section 3.2: subprocess fallback |
| "Deterministic but unique" contradictory | High | Section 1.1: determinism clarified |
| "Zero key generation" misleading | High | Section 1.1: clarified |
| Synthetic credential shape unspecified | High | Section 1.3.1: fields defined |
| Claude Desktop "integration" is failure demo | High | Section 2.5: honest framing |
| stdio wrapper ordering contradictory | High | Section 4.4: comment fix |
| toolPolicy bigint not JSON-serializable | High | Section 1.5: documented |
| Peer dep must bump to ^0.4.0 | Medium | Section 5: peer dep bump |
| SDK export file not named | Medium | Section 1.1: `sdk/src/dev.ts` + index |
| tsconfig excludes tests | Medium | Section 3.5: tsconfig.test.json |
| HTTP batched JSON-RPC not gated | Medium | Section 8: documented limitation |
| Package boundary blur | Medium | Section 8: boundary clarified |
| Release sequencing (lockfiles, dist, pack) | Medium | Section 6 step 7: sequencing added |
