# @bolyra/mpp

**Verify an agent's delegated spend mandate before accepting an MPP payment credential.**

[MPP](https://mpp.dev) (Machine Payments Protocol) gives machines a payment
interface: Request → 402 Challenge → payment Credential → Verification +
Payment-Receipt. It answers *"did this client pay?"* — deliberately not
*"was this agent authorized to spend?"*. When the paying client is an
autonomous agent rather than its operator, that second question is the missing
precondition. This package adds it as a small authorization middleware for
[mppx](https://github.com/wevm/mppx) servers: the agent presents an
operator-signed Bolyra spend mandate in a request header, and the gate
verifies it — fail-closed — **before the MPP payment flow proceeds**.

How the two protocols compose (without modifying either) is mapped in
[Bolyra as an Authorization Companion to MPP](https://github.com/bolyra/bolyra/blob/main/docs/mpp-authorization-companion.md).
One line: **MPP moves the money; Bolyra proves the mandate.**

> This is a community-built integration. It is not affiliated with, endorsed
> by, or sponsored by the MPP authors, wevm, Tempo, or Stripe.

## Install

Into an existing mppx server:

```bash
npm install @bolyra/mpp
```

Starting fresh? Install both:

```bash
npm install @bolyra/mpp mppx
```

`mppx` is an optional peer dependency — this package never imports it at
runtime; it wraps the method objects you already build with mppx.

## Quickstart

This snippet shows the integration shape (placeholders like `secretKey` and the
operator pubkeys are yours to fill in); for a copy-paste-runnable version with
a mock agent and real values, see [`examples/mandate-demo`](./examples/mandate-demo).
The adapter wraps `Method.Server` *before* it is passed to `Mppx.create()`, so
no middleware changes are needed and every mppx framework adapter (Express,
Hono, Elysia, Next.js) is covered automatically:

```ts
import { Mppx, tempo } from 'mppx/server'
import { bolyraGate } from '@bolyra/mpp'

const tempoCharge = tempo({
  currency: '0x20c0000000000000000000000000000000000000',
  recipient: '0x742d35Cc6634c0532925a3b844bC9e7595F8fE00',
})

const gatedCharge = bolyraGate(tempoCharge, {
  // The payee identity the operator's mandate must be signed for.
  audience: 'api.merchant.example',
  // In-process classical verification (default, no ZK dependency).
  // Fail-closed: an empty trusted set never means "all operators trusted".
  verifier: {
    kind: 'classical',
    trustedOperators: [{ x: '<operator pubkey x>', y: '<operator pubkey y>' }],
  },
})

const mppx = Mppx.create({ methods: [gatedCharge], secretKey })

// Your route handler is unchanged:
export async function handler(request: Request) {
  const result = await mppx.charge({ amount: '25' })(request)
  if (result.status === 402) return result.challenge
  return result.withReceipt(Response.json({ data: '...' }))
}
```

The agent carries its mandate presentation (a `bvp/1` bundle, base64url JSON)
in the `X-Bolyra-Authorization` header on every request. Denials return RFC
9457 Problem Details (`application/problem+json`) with a stable machine-readable
`code`, **before** any challenge is issued or payment logic runs:

```json
{
  "type": "https://bolyra.ai/problems/mpp/scope-exceeded",
  "title": "Spend Exceeds Delegated Tier",
  "status": 403,
  "detail": "required scope exceeds the credential scope",
  "code": "scope_exceeded"
}
```

On allow, the mppx receipt (and therefore the `Payment-Receipt` header) gains
a `bolyraAuthorization` extension field — tier, amount, verifier kind, and the
ES256K-signed, hash-chained authorization receipt reference — giving the
**approved → paid** audit pair described in the companion note.

## Amount → tier mapping

The route's `amount` is resolved to USD and mapped to the cumulative
financial-tier bits of `@bolyra/sdk`'s Permission model. Comparison is
exact-decimal (never float); boundaries are strict:

| Route amount (USD) | Required capability | Permission bits |
|---|---|---|
| `< 100` | `mpp:financial:small` | `FINANCIAL_SMALL` |
| `100 … < 10,000` | `mpp:financial:medium` | `FINANCIAL_SMALL + FINANCIAL_MEDIUM` |
| `>= 10,000` | `mpp:financial:unlimited` | all three financial bits |

An operator delegating up to the medium tier signs the binding with
`capabilities: ["mpp:financial:small", "mpp:financial:medium"]` — higher tiers
list the lower ones, mirroring the cumulative bit encoding. By default
`amount` is read as a decimal USD string (the `mppx.charge({ amount: '1' })`
convention); pass `amountToUsd` when your route prices in token base units or
another currency. Unresolvable amounts fail closed.

## Configuration

| Option | Type | Default | Notes |
|---|---|---|---|
| `audience` | `string` | required | Byte-literal match against the mandate's signed `project_key` (payee binding) |
| `verifier` | `VerifierConfig` | required | `classical` (in-process), `command` (EVC v1 spawn), or `url` (hosted verifier) |
| `verifier.trustedOperators` | `{x, y}[]` | required for `classical` | Decimal-string operator pubkeys; empty set fails closed |
| `program` | `string` | `"mpp"` | Binding `program` discriminator |
| `model` | `string` | echo bundle | Optional model pin; when set, the signed binding must name it |
| `amountToUsd` | `(ctx) => string \| number` | `options.amount` as USD | Resolve route amounts for tier mapping; errors fail closed |
| `enforce` | `"always" \| "payment"` | `"always"` | `"payment"` skips gating on credential-less challenge probes |
| `header` | `string` | `x-bolyra-authorization` | Request header carrying the presentation; `Authorization` is rejected (MPP's payment credential rides it) |
| `nonceStore` | `NonceStoreLike` | in-memory | Reserve-before-act store for host-nonce-mode verifiers; **inject a shared, durable store for multi-instance deployments** |
| `receipts` | `{issuer?, keyId?, privateKey?}` | ephemeral key | ES256K decision receipts; pin a key in production |
| `onReceipt` | `(receipt) => void` | — | Sink for every signed decision receipt (allow and deny) |

Verifier backends:

```ts
// External Verifier Contract v1 command (zk-class checks, delegation chains).
// `bolyra verify` needs the MPP capability vocabulary mapped to Permission
// bits — write MPP_CAPABILITY_MAP (exported by this package) to a JSON file:
//   { "mpp:financial:small": ["FINANCIAL_SMALL"],
//     "mpp:financial:medium": ["FINANCIAL_SMALL", "FINANCIAL_MEDIUM"],
//     "mpp:financial:unlimited": ["FINANCIAL_SMALL", "FINANCIAL_MEDIUM", "FINANCIAL_UNLIMITED"] }
verifier: {
  kind: 'command',
  command: 'bolyra',
  args: ['verify', '--roots', 'roots.json', '--capability-map', 'mpp-capabilities.json'],
}

// Hosted verifier endpoint (e.g. the Bolyra hosted-verify preview):
verifier: { kind: 'url', url: 'https://…/v1/verify', token: process.env.BOLYRA_VERIFY_TOKEN }
```

Both external modes speak the
[External Verifier Contract v1](https://github.com/bolyra/bolyra/blob/main/spec/external-verifier-contract-v1.md)
(one JSON request in, one fail-closed verdict out) and implement the host
obligations: 10s default timeout, stdout/response-body caps (1 MiB), strict
single-object closed-schema verdict parsing (unknown members and unrecognized
`kind` values reject), and reserve-before-act nonce handling. **Every**
verifier failure class — timeout, crash, garbage output, unreachable
endpoint, oversized response — denies with `internal_error`; a broken
verifier is never an allow.

## What is and isn't checked (read this)

The default verifier is **classical** — the same classical pipeline as the
Bolyra hosted-verify preview, run in-process. It does **not** verify
zero-knowledge proofs, so every public signal and credential field in the
bundle is self-asserted. The one cryptographically load-bearing fact is the
operator's EdDSA-Poseidon signature over the request binding. A classical
`allow` means, and only means:

> A configured trusted operator signed a binding authorizing this exact
> `{agent_name, project_key, program, model, capabilities}`, the request
> matches that signed binding, and the granted capability (the amount's
> financial tier) is a subset of it.

Checked (classical):

- trusted-operator gate (`trustedOperators`; empty set fails closed)
- EdDSA-Poseidon binding signature against that operator key
- byte-literal request↔binding match — `project_key` is your `audience`
- granted tier capability ⊆ operator-signed capabilities
- consistency checks on the revealed credential: Poseidon scope anchoring,
  model-hash binding, cumulative permission-bit subset, strict expiry
  (`now == expiry` is expired)

**Not** checked (classical):

- Groth16 proof verification, Merkle-root inclusion, human-uniqueness, and
  delegation-chain proofs — bundles carrying zk-only slots are **denied**,
  not half-verified; use a zk-class external verifier (`bolyra verify`) via
  `verifier: { kind: 'command', … }` for those
- replay: a spend mandate is a *standing* authorization, reusable within tier
  and expiry by design; per-payment idempotency is MPP's challenge binding.
  (External verifiers in host nonce mode DO make presentations one-shot —
  the gate reserves their `consume_nonces` before acting. The default
  reservation store is in-memory and per-process: it does not survive
  restarts or span instances — inject `nonceStore` for that.)
- dynamic pricing: the tier check reads the **route's configured amount** at
  preflight time, before any method `request` hook runs. For standard methods
  mppx pins the economic request fields across calls (stable binding), so the
  configured amount is authoritative; if you build a custom method whose
  request hook changes the amount, make `amountToUsd` resolve the
  authoritative price — the gate cannot see post-hook values.
- `agent_name` and `model` (unless pinned via `model`) are echoed from the
  presented bundle — they identify, they don't restrict. The load-bearing
  host-asserted fields are `audience` and the amount tier.
- payment validity itself — that is mppx's job, which runs after the gate

Scope: HTTP request flows. If mppx's payment verification is somehow reached
without a gate decision for that request (standalone `verifyCredential()`
calls, non-HTTP transports), the wrapped `verify` **fails closed**.

## Example

A self-contained runnable demo — mppx server + this gate, a mock agent with a
delegated small-tier mandate, an allowed $25 spend and a denied $500 spend —
lives in [`examples/mandate-demo`](./examples/mandate-demo):

```bash
cd examples/mandate-demo && npm install && npm run demo
```

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
