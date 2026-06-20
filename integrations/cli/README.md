# @bolyra/cli

Unified CLI for Bolyra credential lifecycle management. Create, inspect, revoke, and list agent credentials. Generate Ed25519 operator keypairs. Verify signed audit receipts. Generate dev identities for testing.

## Install

```bash
npm install -g @bolyra/cli
```

Or use directly in the monorepo:

```bash
cd integrations/cli && npm run build && node dist/main.js
```

## Requirements

- Node.js 18.11+
- `@bolyra/sdk` and `@bolyra/receipts` (installed as dependencies)

## Commands

### Generate an operator keypair

```bash
bolyra key generate --out operator.key
# Creates operator.key (private, mode 0600) and operator.key.pub (public key JSON)
```

### Show public key from private key

```bash
bolyra key show operator.key
# Public Key:
#   x: 0x1234...
#   y: 0x5678...
#   DID: did:bolyra:operator:0x1234...
```

### Create a credential

```bash
bolyra cred create \
  --operator-key operator.key \
  --model gpt-4o \
  --permissions read,write,financial_small \
  --expiry 30d \
  --store
```

Flags:
- `--operator-key <path>` (required) Path to Ed25519 private key
- `--model <name>` (required) Model identifier
- `--permissions <list>` (required) Comma-separated: `read`, `write`, `financial_small`, `financial_medium`, `financial_unlimited`, `sign`, `delegate`, `pii`
- `--expiry <duration|timestamp>` (required) Duration (`30d`, `1y`, `8h`) or Unix timestamp
- `--out <path>` Write credential JSON to file (default: stdout)
- `--store` Also save to `~/.bolyra/credentials/`

### Inspect a credential

```bash
# From file
bolyra cred inspect credential.json

# From local store (by commitment)
bolyra cred inspect 12345678901234567890

# JSON output
bolyra cred inspect credential.json --json
```

### List credentials

```bash
bolyra cred list
bolyra cred list --filter active
bolyra cred list --json
```

### Revoke a credential

```bash
bolyra cred revoke 12345678901234567890 --reason "key compromised"
```

Note: Revocation is local-only in v1. It does not propagate to any registry or on-chain state.

### Verify a receipt

```bash
bolyra receipt verify receipt.json
bolyra receipt verify receipt.json --signer 0xabc...
cat receipt.json | bolyra receipt verify --stdin --max-age 3600
```

### Generate dev identities

```bash
bolyra dev
bolyra dev --permissions 0x07 --expiry 1750000000 --out dev-identities.json
```

**WARNING:** Dev identities use fixed seeds. Never use in production.

## Credential Store

Credentials are stored locally at `~/.bolyra/credentials/`. Each credential is a JSON file named by its commitment hash prefix.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Verification/validation failure |
| 2 | Usage error (bad args, missing required flags) |

## License

Apache-2.0
