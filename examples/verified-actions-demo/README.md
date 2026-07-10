# Verified agent actions — end-to-end demo

Every MCP tool call your agents make is checked against the agent's registered
credential and receipted with an ES256K signature — allows **and** denies.
This demo runs the whole story in one command: an authorized call goes
through, an out-of-scope call is blocked, a replayed proof is rejected, a
forged permission claim is caught, and every decision lands as an
individually signed, offline-verifiable receipt in a JSONL audit log.

## Run it (under 5 minutes)

```bash
cd examples/verified-actions-demo
npm install
npm run demo
```

That's it. You'll see four scenes and an audit section:

| Scene | What happens | Verdict |
|---|---|---|
| 1 | `support-agent` (READ\|WRITE) calls `refund_customer` | **ALLOWED** — forwarded upstream, signed allow receipt |
| 2 | `reporting-agent` (READ only) calls `refund_customer` | **DENIED** — 403 with the exact reason, signed deny receipt |
| 3 | `reporting-agent` calls `read_ledger` | **ALLOWED** — per-action authority, not per-agent blocklists |
| 4 | attacker replays scene 1's proof bundle | **REJECTED** — nonce replay protection, signed deny receipt |
| 5 | forged bundle claims READ\|WRITE it was never granted | **REJECTED** — caught against the registered credential, signed deny receipt |

Then the demo prints the audit log (`audit/audit-log.jsonl`, one signed
receipt per line), verifies every receipt against the published signer
address, and shows that three kinds of tampering (flipping a verdict,
rewriting the deny reason, splicing a signature from another receipt) all
break verification. Signatures make each *receipt* tamper-evident;
whole-log integrity (detecting deleted or reordered lines) is a production
add-on — sequence numbers or hash-chaining with externally anchored
checkpoints.

Re-verify later, with the gateway long gone:

```bash
npm run verify   # needs only audit/*.jsonl + audit/signer.json + @bolyra/receipts
```

## What a receipt looks like

Each line in `audit-log.jsonl` is a self-contained `SignedReceipt`:

```jsonc
{
  "id": "0x32982ab42544e275",
  "payload": {
    "v": 1,
    "kind": "bolyra.auth",
    "issuedAt": 1783035000,
    "issuer": "verified-actions-demo-gateway",
    "subject": { "rootDid": "did:bolyra:dev:…", "actingDid": "did:bolyra:dev:…", "...": "..." },
    "decision": {
      "allowed": false,
      "reasonCode": "Tool \"refund_customer\" requires permissions 10b, agent has 1b",
      "score": 100,
      "permissionBitmask": "1",
      "chainDepth": 0
    },
    "proof": { "nonce": "…", "humanProofHash": "…", "agentProofHash": "…", "publicSignalsHash": "…" }
  },
  "signature": {
    "alg": "ES256K",
    "signer": "0x6f57a2d737bf21a52010a26af2a480a28d6624b5",
    "payloadHash": "0x…",
    "value": "0x…"       // 65-byte r||s||v secp256k1 signature
  }
}
```

`verifyReceipt()` recomputes the canonical payload hash, recovers the signer
from the signature, and checks both — so an auditor needs nothing but the
JSONL file and the signer address. Change one byte of the payload and
verification fails.

## How it works

```
                        +------------------------------------------------------+
  agent                 |  gateway host (src/gateway-host.ts)                    |
  (proof bundle in  --> |                                                        | --> upstream MCP server
   Authorization        |  1. bundle parse + verification + score  \  createGatewayMiddleware
   header)              |  2. nonce replay protection              /  (@bolyra/gateway)
                        |  3. credential binding — registered permissions        |    (src/upstream.ts —
                        |     (production: resolveCredential + scopeCommitment)  |     never sees Authorization,
                        |  4. per-tool policy — checkToolPolicy (@bolyra/mcp)    |     only X-Bolyra-* headers)
                        |                                                        |
                        |  every decision -> ES256K receipt                      |
                        |  (@bolyra/receipts) -> audit JSONL                     |
                        +------------------------------------------------------+
```

- **Policy** lives in [`gateway.yaml`](./gateway.yaml) — parsed by
  `@bolyra/gateway`'s own `loadConfig()`, so it is the exact format you'd hand
  to `npx @bolyra/gateway` in production. `read_ledger` requires `READ_DATA`
  (bit 0), `refund_customer` requires `WRITE_DATA` (bit 1).
- **Verification** is the shipped `createGatewayMiddleware` from
  `@bolyra/gateway` — the same code path as the standalone proxy. The host
  runs the tool-policy check itself (same `checkToolPolicy` from `@bolyra/mcp`
  the gateway uses) so that **deny receipts carry full context**: agent DID,
  score, held vs. required permissions, and the human-readable reason.
- **Receipts** are `createAuthReceipt` + `signReceipt` from
  `@bolyra/receipts` — the standard Bolyra receipt schema, signed ES256K
  (secp256k1 + keccak256, Ethereum-compatible recovery).

| File | Role |
|---|---|
| `src/demo.ts` | One-command orchestration + narration |
| `src/gateway-host.ts` | Gateway middleware + policy + signed receipts + forwarding |
| `src/upstream.ts` | Mock "payments" MCP server being protected |
| `src/agents.ts` | Demo credentials + dev-mode proof bundles |
| `src/audit.ts` | Signed JSONL audit log: record / read / verify / tamper-check |
| `src/verify-audit.ts` | Standalone offline verification (`npm run verify`) |
| `gateway.yaml` | Tool policy, in the standard `@bolyra/gateway` config format |
| `test/demo.test.ts` | E2E test: allow, deny, receipt count, tamper rejection |

## Dev mode vs. production

The demo runs in **dev mode**, so it starts in seconds on a fresh machine
with no circuit artifacts. Bundle shape, signal layout, nonce/replay
handling, policy checks, and receipt signing are the real thing. Two things
are stand-ins:

- **Proofs are mocked.** Dev mode skips ZK verification, which also means the
  permission mask inside a dev bundle is self-asserted. That is why the host
  cross-checks every claim against its registered-credential map (scene 5) —
  the dev-mode equivalent of production's `resolveCredential` +
  `scopeCommitment` binding, where a forged mask simply cannot produce a
  valid Groth16 proof. In production, agents generate real proofs via
  `attachBolyraProof()` from `@bolyra/mcp` (backed by `@bolyra/sdk` and the
  compiled circuits) and the verifier sets `devMode: false`.
- **The signing key is ephemeral.** Production uses the gateway operator's
  persistent key (`receipts.privateKey` in the config), and the signer
  address in `audit/signer.json` becomes the pinned trust anchor.

## Deploying this pattern for real

The **enforcement** side ships as two packaged options, no application
changes:

- **HTTP MCP servers:** put the standalone proxy in front —
  `npx @bolyra/gateway --target http://localhost:3000/mcp` (see
  [`integrations/gateway`](../../integrations/gateway/README.md)).
- **stdio MCP servers** (Claude Desktop, Cursor, etc.):
  `npx @bolyra/shield --server "node my-server.js"` (see
  [`integrations/shield`](../../integrations/shield/README.md)), with
  `--learn` to auto-generate a least-privilege policy from the server's own
  tool list.

Both enforce the same trust boundary shown here — proof-bundle
verification, nonce replay protection, and per-tool policy. Two honest
caveats about what is demo-host code rather than packaged behavior:

- **Credential binding (check 3):** in production, `verifyBundle` binds the
  proof to the resolved credential via its `scopeCommitment` — but the
  credential resolver is wired by the embedder (`resolveCredential` in the
  library API), which is exactly the role this demo's registered-credential
  map plays. The packaged CLI does not ship a resolver out of the box today.
- **Receipts:** as of `@bolyra/gateway` 0.3.0, the packaged proxy emits
  ES256K-signed receipts on every allow *and* deny decision in both dev and
  production modes (including signed anonymous receipts for missing or
  malformed bundles), with the signer address pinned in `signer.json` — the
  same pattern as this demo's audit layer. This demo still embeds its own
  audit layer (`src/gateway-host.ts` + `src/audit.ts`) because it narrates
  each decision and adds the registered-credential binding above.

## Test

```bash
npm test
```

Compiles, runs the full demo as a child process, and asserts: both allow
verdicts, all three deny verdicts (policy, replay, forged claim), exactly one
signed receipt per decision, every receipt verifies independently (the test
imports `@bolyra/receipts` directly), and all tampered variants fail
verification.
