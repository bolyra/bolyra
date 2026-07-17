# @bolyra/cli

Unified CLI for Bolyra credential lifecycle management. Create, inspect, revoke, and list agent credentials. Generate Ed25519 operator keypairs. Verify signed audit receipts and hash-chained receipt logs. Generate dev identities for testing.

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

### Verify an external proof bundle (`bolyra verify`)

A spawnable external verifier for MCP hosts and agent-coordination servers. The
host writes one JSON request to stdin and reads exactly one allow/deny verdict
from stdout — fail-closed on anything else (non-zero exit, timeout, unparseable
or multi-object stdout, missing fields).

```bash
echo '{"version":1,"bundle":"<opaque proof string>","request":{"agent_name":"BlueLake","project_key":"/data/proj","program":"claude-code","model":"opus-4.1","granted_capabilities":["send_message"]},"now_unix":1720000000}' \
  | bolyra verify --roots-file roots.json --capability-map caps.json --circuits-dir ./vkeys
# -> {"verdict":"allow"}   (or {"verdict":"deny","code":"...","message":"..."})
```

Flags: `--nonce-mode local|host` (default `local`), `--roots-file <path>`,
`--root <decimal>` (repeatable) / `BOLYRA_TRUSTED_ROOTS`, `--capability-map <path>`,
`--circuits-dir <path>` / `BOLYRA_CIRCUITS_DIR`, `--verbose`.

It verifies the proof envelope + Groth16 proof (vkeyHash-pinned), delegation-chain
non-expansion, scope/capability binding, model binding, strict expiry, trusted
Merkle roots, and nonce replay — all anchored to the proof's public commitments.
See the host-agnostic **[External Verifier Contract v1](../../spec/external-verifier-contract-v1.md)**
and the **[mcp_agent_mail integration guide](../../docs/integrations/mcp-agent-mail-verifier.md)**.

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
bolyra receipt verify receipt.json --signer-from https://gateway.example/.well-known/bolyra-signers.json
cat receipt.json | bolyra receipt verify --stdin --max-age 3600
```

### Verify a receipt log as a hash chain

`receipt verify` checks one receipt; `receipt verify-chain` checks a whole
JSONL log (one signed receipt per line, e.g. a gateway audit log) — every
ES256K signature AND the hash chain each signed payload carries
(`chain: { seq, prevReceiptHash }`, genesis = 32 zero bytes):

```bash
bolyra receipt verify-chain audit-log.jsonl
bolyra receipt verify-chain audit-log.jsonl --signer 0xabc...
bolyra receipt verify-chain audit-log.jsonl --signer-from https://gateway.example/.well-known/bolyra-signers.json
bolyra receipt verify-chain audit-log.jsonl --expect-count 128 --expect-head 0xdef...
bolyra receipt verify-chain audit-log.jsonl --allow-unchained   # log STARTS with pre-chaining receipts
```

Detects, from the log alone: edited receipts, deleted lines, reordered lines,
inserted lines, and head truncation (a log that no longer starts at genesis).
**Not detectable from the log alone:** truncation from the tail — a chain cut
after any receipt is still internally consistent. On success the command
prints the chain head hash; pin it (and the count) externally — anchoring
mechanism and cadence are enterprise-configurable — and pass them back via
`--expect-head` / `--expect-count` to close that gap.

### Issue a spend mandate (`bolyra mandate issue`)

Issue a delegated spend mandate an AI agent presents to a payment route gated by
[`@bolyra/mpp`](../mpp-payments). The operator signs a request binding — the
agent, the audience (payee), a financial tier, and an expiry — and the command
prints the `bvp/1` presentation the gate verifies (the `X-Bolyra-Authorization`
header value):

```bash
# One-time: create the operator key the mandate is signed with.
bolyra key generate --out operator.key

# Issue a small-tier (< $100) mandate for one agent + one payee, good for 30 days.
bolyra mandate issue \
  --operator-key operator.key \
  --agent shopper-bot \
  --audience api.merchant.example \
  --model opus-4.1 \
  --tier small \
  --expiry 30d
# stdout: the bvp/1 presentation (base64url) — pipe it straight into a header.
# stderr: a human-readable summary + the operator public key to trust in the gate.

# Amount-first alternative: map a max USD spend to the smallest covering tier.
bolyra mandate issue --operator-key operator.key --agent shopper-bot \
  --audience api.merchant.example --model opus-4.1 --max-usd 5000 --expiry 30d
# $5000 -> medium tier (covers small + medium spends)
```

Tiers are cumulative: `small` (< $100), `medium` (< $10,000, covers small),
`unlimited` (covers small + medium). The agent presents the output to the gate,
which verifies it **before** any payment logic runs (allow within tier, deny
over tier / expired / wrong-audience / tampered).

**This is issuance, not key management or a wallet.** The `--operator-key` is a
key you already hold (from `bolyra key generate`); this command never generates,
stores, or rotates keys, holds funds, or settles payments — it only signs one
mandate. Classical (EdDSA-binding) issuance only; it emits no ZK proof, matching
`@bolyra/mpp`'s default verifier.

**Classical trust boundary.** The operator signature binds the request binding —
`{agent, audience, program, model, capabilities}` — so the **spend ceiling**
(the signed capability tier) is tamper-evident. In classical mode `--expiry` is
**not** bound by the signature (a presenter can re-anchor a later expiry and
still verify), so treat it as advisory: prefer short expiries and rely on the
capability ceiling; cryptographic time-bounding needs the zk-class verifier
(`bolyra verify`). `--nonce` is an **unsigned, unverified** id for your own
audit — not a replay nonce and not tamper-evident. A spend mandate is a standing
authorization reusable within its tier and expiry by design.

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
