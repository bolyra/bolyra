# @bolyra/cli — Credential Management CLI

**Date:** 2026-06-19
**Author:** Viswa + Claude Opus 4.6 (PDLC Orchestrator)
**Status:** Draft
**Pipeline:** pdlc-2026-06-19-credential-cli

## Overview

A unified CLI tool (`bolyra`) that exposes credential lifecycle management, key generation, receipt verification, and dev identity generation from the command line. Currently these operations require writing TypeScript against `@bolyra/sdk` directly. The CLI removes that barrier for operators, CI pipelines, and developers.

Ships as `@bolyra/cli` at `integrations/cli/` in the monorepo with a `bin` entry of `bolyra`.

## Motivation

1. **No production credential tooling.** `createAgentCredential()` exists in the SDK but requires a TypeScript program to call. Operators deploying agents need a CLI workflow: generate keys, create credentials, inspect them, revoke them.
2. **Fragmented CLI surface.** `@bolyra/receipts` ships `bolyra-receipt-verify` as a standalone binary. `@bolyra/gateway` ships `bolyra-gateway`. There is no unified `bolyra` command that brings these together.
3. **Dev workflow gap.** `createDevIdentities()` works in code but developers can't quickly generate test fixtures from the command line for use with curl, gateway testing, or MCP server configuration.

## Command Surface

### `bolyra cred create`

Create a new agent credential. Prompts for or accepts via flags:

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--operator-key <path>` | string | yes | — | Path to Ed25519 private key file (32-byte raw or PEM) |
| `--model <name>` | string | yes | — | Model identifier string (hashed internally via SHA-256 to field element) |
| `--permissions <list>` | string | yes | — | Comma-separated permission names: `read,write,financial_small,...` |
| `--expiry <duration\|timestamp>` | string | yes | — | Duration (`30d`, `1y`, `8h`) or Unix timestamp |
| `--out <path>` | string | no | stdout | Output file path for the credential JSON |
| `--store` | boolean | no | false | Also save to local credential store (`~/.bolyra/credentials/`) |

**Output:** JSON with all `AgentCredential` fields serialized as decimal strings (matching registry API format). Commitment printed to stderr for easy capture.

**Behavior:**
- Reads operator private key from file
- Hashes model name: `SHA-256(model_name)` truncated to BN254 field
- Parses permission names to `Permission[]` array, validates cumulative encoding
- Parses expiry: duration strings converted to absolute timestamp from now
- Calls `createAgentCredential()` from `@bolyra/sdk`
- Serializes BigInt fields as decimal strings in output JSON
- If `--store`: writes to `~/.bolyra/credentials/{commitment}.json`

### `bolyra cred inspect <file|commitment>`

Inspect a credential from a file or local store.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--json` | boolean | no | false | Output raw JSON instead of human-readable table |

**Output (human-readable):**
```
Credential: 0x1a2b3c...
  Model hash:    0x4d5e6f...
  Operator key:  (Ax, Ay) = (0x..., 0x...)
  Permissions:   READ_DATA, WRITE_DATA, FINANCIAL_SMALL (bitmask: 0b00000111)
  Expiry:        2027-06-19T00:00:00Z (364d remaining)
  DID:           did:bolyra:agent:0x1a2b3c...
  Status:        active | expired | revoked
```

**Resolution order:**
1. If argument is a file path that exists: read JSON from file
2. If argument matches a commitment in `~/.bolyra/credentials/`: read from store
3. If neither: error with suggestion

### `bolyra cred revoke <commitment>`

Mark a credential as revoked in the local store.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--reason <text>` | string | no | — | Optional reason for revocation |

**Behavior:**
- Reads credential from `~/.bolyra/credentials/{commitment}.json`
- Adds `"revoked": true, "revokedAt": "ISO-8601", "revokedReason": "..."` to the stored JSON
- Prints confirmation

**Note:** This is local-only revocation. On-chain or registry-level revocation is out of scope for v1. The local store is the source of truth for this CLI. Future versions will integrate with the credential registry API (`createRegistryResolver`).

### `bolyra cred list`

List credentials in the local store.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--json` | boolean | no | false | Output as JSON array |
| `--filter <status>` | string | no | all | Filter by: `active`, `expired`, `revoked` |

**Output (human-readable):**
```
 COMMITMENT         MODEL       PERMISSIONS  EXPIRY              STATUS
 0x1a2b...ef34      gpt-4o      RW$          2027-06-19          active
 0x5c6d...ab12      claude-4    RW$SP        2026-12-01          expired
 0x9e0f...cd56      gemini-2    R            revoked 2026-06-15  revoked
```

Permission abbreviations: R=READ_DATA, W=WRITE_DATA, $=FINANCIAL_SMALL, $$=FINANCIAL_MEDIUM, $$$=FINANCIAL_UNLIMITED, S=SIGN_ON_BEHALF, D=SUB_DELEGATE, P=ACCESS_PII.

### `bolyra key generate`

Generate an Ed25519 operator keypair.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--out <path>` | string | no | `./operator.key` | Output path for private key |
| `--format <fmt>` | string | no | `raw` | `raw` (32 bytes) or `hex` |

**Behavior:**
- Generates 32 cryptographically random bytes via `crypto.getRandomValues()`
- Writes private key to `{out}` (file mode 0o600)
- Writes public key to `{out}.pub` (derived via `derivePublicKey()` from SDK)
- Prints public key coordinates to stdout

### `bolyra key show <file>`

Show public key info from a private key file.

**Output:**
```
Public Key:
  x: 0x1234...
  y: 0x5678...
  DID: did:bolyra:operator:0x1234...
```

### `bolyra receipt verify <file>`

Verify a signed audit receipt. Wraps the existing `bolyra-receipt-verify` logic from `@bolyra/receipts`.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--stdin` | boolean | no | false | Read from stdin |
| `--signer <address>` | string | no | — | Expected signer address |
| `--max-age <seconds>` | number | no | 86400 | Maximum receipt age |

**Behavior:** Delegates to the same `verifyReceipt()` and `hashPayload()` from `@bolyra/receipts`. Same output format as existing `bolyra-receipt-verify` CLI.

### `bolyra dev`

Generate dev identities for testing.

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--permissions <bitmask>` | string | no | `0xFF` | Permission bitmask (hex or decimal) |
| `--expiry <timestamp>` | string | no | 2099-12-31 | Expiry timestamp |
| `--out <path>` | string | no | stdout | Output file for identities JSON |

**Output:** JSON containing `{ human, agent, operatorKey }` from `createDevIdentities()` with BigInt fields serialized as decimal strings. Includes a warning banner on stderr.

### `bolyra --version`

Prints `@bolyra/cli {version}`.

### `bolyra --help`

Prints top-level help listing all subcommands.

## Architecture

### Package Structure

```
integrations/cli/
  package.json          # @bolyra/cli, bin: { "bolyra": "dist/main.js" }
  tsconfig.json
  src/
    main.ts             # Entry point: parseArgs router
    commands/
      cred-create.ts    # bolyra cred create
      cred-inspect.ts   # bolyra cred inspect
      cred-revoke.ts    # bolyra cred revoke
      cred-list.ts      # bolyra cred list
      key-generate.ts   # bolyra key generate
      key-show.ts       # bolyra key show
      receipt-verify.ts # bolyra receipt verify
      dev.ts            # bolyra dev
    store.ts            # ~/.bolyra/credentials/ store management
    format.ts           # Output formatting (table, JSON, permission abbreviations)
    parse.ts            # Shared parsing (duration strings, permission names, bigint serialization)
  test/
    cred-create.test.ts
    cred-inspect.test.ts
    cred-list.test.ts
    key-generate.test.ts
    store.test.ts
    parse.test.ts
    format.test.ts
```

### Dependencies

- `@bolyra/sdk` — `createAgentCredential`, `createHumanIdentity`, `createDevIdentities`, `Permission`, types, `derivePublicKey`, `poseidon2`
- `@bolyra/receipts` — `verifyReceipt`, `hashPayload`, `SignedReceipt` type
- `node:util/parseArgs` — argument parsing (Node 18+ built-in, no external deps)
- `node:crypto` — key generation
- `node:fs`, `node:path` — file I/O, store management

**No external dependencies** beyond the Bolyra packages. This is deliberate: the CLI should install fast and have a minimal dependency tree.

### Argument Parsing

Uses `node:util` `parseArgs()` (stable since Node 18.11). Two-level routing:

```
argv[2] = subcommand group ("cred", "key", "receipt", "dev")
argv[3] = action ("create", "inspect", "revoke", "list", "generate", "show", "verify")
argv[4:] = flags and positional args → parseArgs()
```

Each command module exports `{ run(args: string[]): Promise<void> }`. The router in `main.ts` matches and dispatches.

### Local Credential Store

Location: `~/.bolyra/credentials/`

Each credential is a JSON file named `{commitment-hex-prefix}.json` (first 16 hex chars of commitment for filename, full commitment inside).

Store format (superset of `AgentCredential`):
```json
{
  "commitment": "12345...",
  "modelHash": "67890...",
  "modelName": "gpt-4o",
  "operatorPublicKey": { "x": "...", "y": "..." },
  "permissionBitmask": "7",
  "expiryTimestamp": "1750291200",
  "signature": { "R8": { "x": "...", "y": "..." }, "S": "..." },
  "createdAt": "2026-06-19T12:00:00Z",
  "revoked": false,
  "revokedAt": null,
  "revokedReason": null
}
```

All BigInt values serialized as decimal strings (matching the registry API wire format). The `modelName` field is metadata not present in the SDK type -- stored for human-readable display.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Verification/validation failure (e.g., receipt invalid, credential expired) |
| 2 | Usage error (bad args, missing required flags) |

### BigInt Serialization

All BigInt fields serialize as decimal strings in JSON output. This matches:
- The credential registry API format (`createRegistryResolver` in SDK)
- JavaScript's `BigInt.toString()` default
- Avoids hex ambiguity (0x prefix, case sensitivity)

For human-readable output, commitments and hashes display as `0x{hex}` with truncation.

## Security Considerations

1. **Private key file permissions.** `bolyra key generate` writes private keys with mode `0o600`. `bolyra cred create` reads key files but never writes them. Key material is never printed to stdout (only public key info).

2. **No key in credential store.** The local credential store contains only the credential (which includes the operator public key and signature) but never the private key. The private key is only needed at creation time.

3. **Dev mode warning.** `bolyra dev` prints a warning to stderr: `[bolyra] WARNING: Dev identities use fixed seeds. Never use in production.`

4. **Local-only revocation.** Revocation in v1 is local store metadata only. It does not propagate to any registry or on-chain state. The CLI prints this caveat on `cred revoke`.

5. **No credential transport.** The CLI does not send credentials over the network. It creates and stores them locally. Distribution is the operator's responsibility.

## Scope Boundaries

### In Scope (v1)
- All 8 commands listed above
- Local credential store at `~/.bolyra/credentials/`
- Human-readable and JSON output modes
- Duration string parsing for expiry (`30d`, `1y`, `8h`)
- Permission name parsing and validation

### Out of Scope (future)
- Registry API integration (`bolyra cred push/pull` to sync with remote registry)
- On-chain revocation (requires contract interaction)
- Interactive prompts (v1 is flags-only, suitable for scripting)
- Shell completion
- Config file (`~/.bolyra/config.json`) for default registry URLs, etc.
- `bolyra prove` / `bolyra verify` for handshake proof generation/verification

## Testing Strategy

- Unit tests for parsing (duration strings, permission names, BigInt serialization)
- Unit tests for store operations (CRUD on `~/.bolyra/credentials/`)
- Integration tests for each command (invoke `main.ts` with args, check stdout/stderr/exit code)
- Tests use a temp directory for the credential store (never touch real `~/.bolyra/`)
- Receipt verify tests reuse fixtures from `@bolyra/receipts` test suite

## Compatibility

- Node 18+ (parseArgs requirement)
- Works on macOS, Linux. Windows: should work but untested in v1 (path separators handled by `node:path`)
- `@bolyra/sdk` peer dependency (will use workspace version)
- `@bolyra/receipts` peer dependency for `receipt verify` subcommand

## Migration Path

- `bolyra-receipt-verify` (from `@bolyra/receipts`) continues to work. The CLI wraps it, not replaces it.
- `bolyra-gateway` (from `@bolyra/gateway`) is unaffected. The CLI is a management tool, not a runtime component.
- Future: `@bolyra/receipts` can deprecate `bolyra-receipt-verify` bin in favor of `bolyra receipt verify`.
