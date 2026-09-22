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

Starting fresh? Install both, pinned to the supported pair:

```bash
npm install @bolyra/mpp mppx@0.8.13
```

`mppx` is an optional peer dependency — this package never imports it at
runtime; it wraps the method objects you already build with mppx. The peer
range is **exactly `0.8.13`**, so an unpinned `npm install ... mppx` can fail
with `ERESOLVE`; the command above avoids it.

### Supported versions

| | Version |
|---|---|
| `@bolyra/mpp` | 0.6.0 |
| `mppx` (peer) | exactly 0.8.13 |
| `@bolyra/cli` | requires `@bolyra/mpp` ^0.6.0 |
| Node | 20, 22 and 24 are exercised in CI |

### Spend mandates authorize a TIER, not an amount

`issueMandate` takes either `tier` or `coversAmountUsd`. The second one selects
the smallest tier that covers the amount, and the credential then authorizes
that whole tier — so `coversAmountUsd: 25` authorizes any amount under $100.
Read `authorizedMaxUsd` / `authorizedRange` on the result for the ceiling you
actually got, and prefer `tier` when you want the authorization to equal the
input. (`maxUsd` was removed in 0.6.0; it named a ceiling it never enforced.)

Nothing accumulates across requests: a mandate bounds each request, not a
running total. A succession of separately-permitted $99 charges is not capped
at $99.

### Replay retention is bounded

A host-mode verifier tells the gate how long to retain each consumed nonce, and
the gate honours that exactly — EVC §3.2 makes it an obligation, so the store
never silently retains for less. Bolyra's own verifiers now bound what they ask
for to 30 days, which is what keeps a long-lived credential from turning the
replay store into an unbounded structure.

The tradeoff, stated: once a reservation ages out, the same unmodified
presentation is accepted again and reserves afresh, repeatedly until the
credential expires. If you need protection for the credential's whole life,
issue credentials that expire inside the retention window.

Set `maxRetentionSeconds` to refuse a verifier's requirement you do not want to
honour; it fails closed rather than pretending. At `maxEntries` the store
refuses new reservations and the gate denies `internal_error` rather than
evicting a live reservation.

## Quickstart

See it run first — one command, nothing else to install:

```bash
npx @bolyra/mpp demo
```

Under two minutes, fully in-process: an operator issues a small-tier spend
mandate (`issueMandate`), an agent presents it to a route gated by
`bolyraGate`, a $25 spend **allows**, a $500 spend **denies** with the RFC
9457 problem body before any payment logic runs, a mandate-less request
**denies**, and the ES256K-signed authorization receipt is verified. The
verification path is the real shipped code; only the route is a clearly
labeled stub standing in for an mppx method (for the same flow against real
mppx, see [`examples/mandate-demo`](./examples/mandate-demo)).

This snippet shows the integration shape (placeholders like `secretKey` and the
operator pubkeys are yours to fill in); for a copy-paste-runnable version with
a mock agent and real values, see [`examples/mandate-demo`](./examples/mandate-demo).
The adapter wraps `Method.Server` *before* it is passed to `Mppx.create()`, so
no middleware changes are needed and every mppx framework adapter (Express,
Hono, Elysia, Next.js) is covered automatically:

```ts
import { Mppx, tempo } from 'mppx/server'
import { bolyraGate, handleDenials } from '@bolyra/mpp'

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

// A denial THROWS `BolyraDeniedError` before your handler body runs, so the
// protected action below can only execute on an allow. `handleDenials` turns
// the throw into the RFC 9457 response; without it, the error propagates and
// your framework's error path answers (still no side effect).
export const handler = handleDenials(async (request: Request) => {
  const result = await mppx.charge({ amount: '25' })(request)
  if (result.status === 402) return result.challenge
  // ...the protected action...
  return result.withReceipt(Response.json({ data: '...' }))
})
```

`handleDenials` is for frameworks that consume a *returned* `Response` (Next
App Router, Cloudflare Workers, Hono, Bun). An Express/Node handler must write
to `res`, and a returned `Response` does not complete the request — use mppx's
own Express middleware and `sendDenial(err, res)` in an error middleware:

```ts
import { payment } from 'mppx/express'
import { sendDenial } from '@bolyra/mpp'

app.post('/paid', payment(mppx.charge, { amount: '25' }), (req, res) => {
  // ...the protected action (only reached on an allow + verified payment)...
  res.json({ ok: true })
})

app.use(async (err, req, res, next) => {
  if (await sendDenial(err, res)) return // status + application/problem+json written
  next(err)
})
```

Under `mppx/express` a preflight denial rejects the middleware's promise, and
Express >= 5 forwards async rejections to error middleware (Express 4 needs an
async wrapper).

> **Why it throws.** mppx maps any non-402 `Response` returned from a method
> `preflight` to an outer `{ status: 200, withReceipt }`, so a *returned* denial
> reaches your handler as success and the action runs before the client sees
> the 401/403. 0.5.0 changed the gate to throw. (Breaking for handlers that
> relied on a returned denial; see CHANGELOG.)

The agent carries its mandate presentation (a `bvp/1` bundle, base64url JSON)
in the `X-Bolyra-Authorization` header on every request. A denial is thrown as
`BolyraDeniedError` **before** any challenge is issued or payment logic runs;
`handleDenials` renders it as RFC 9457 Problem Details
(`application/problem+json`) with a stable machine-readable `code`:

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

### Hooks and discovery (read before combining with method hooks)

- The gate uses `enforce: 'always'` unless you say otherwise: Bolyra runs before your method's `preflight`/`authorize`, including on requests with no Payment credential.
- `enforce: 'payment'` keeps credential-less 402 discovery **only** when the method has **no `authorize` hook** (refused at construction with `BolyraGateConfigError`) and its `preflight` returns nothing or a 402. Any other credential-less outcome fails closed.
- Every hook that runs during ungated discovery must perform **no protected effects**. The gate cannot verify that by inspecting hooks; it is your integration's obligation.
- At request time, nothing inside the gate escapes as an exception **except `BolyraDeniedError`** (internal faults, including a throwing `onReceipt` sink, become a 500 `internal_error` denial thrown the same way — a sink failure denies even an otherwise-valid request). Construction-time validation throws `TypeError`/`BolyraGateConfigError` synchronously; your method's own hooks keep their own error behavior.
- **`onReceipt` is synchronous.** A sink that returns a Promise is treated as a failure and the request is denied (an async sink's rejection could otherwise never fail the decision); do your I/O in a queue the sink hands off to synchronously.
- **Where a denial surfaces depends on the stage.** A `preflight` denial propagates out of `mppx.charge(...)(request)` (this is what `handleDenials` catches). A denial thrown from `verify` — a missing or already-consumed decision — is caught by mppx itself, logged as `mppx: internal verification error`, and re-issued as a 402 challenge; the Bolyra Problem Details are not recoverable there. Both are fail-closed.
- A failed `originalVerify` is not retryable against the same captured request: the decision is consumed one-use; the client re-runs the request **with a fresh presentation** (a fresh authorization decision; in host-nonce mode the original presentation's nonce was already reserved on the allow, so re-sending it would deny `nonce_replayed`).
- **One bundle = one presentation.** Issue a fresh presentation per gated HTTP attempt — including the payment retry after a 402 challenge under `enforce: 'always'`, because the discovery attempt already ran the gate and reserved its nullifier; only `enforce: 'payment'` skips the gate on discovery (`issueMandate` / `bolyra mandate issue`; the signer is local and cheap) — rather than re-sending one. Each issuance mints a fresh random nullifier (`publicSignals[1]`); a hosted verifier hands that nullifier back for the gate to reserve before acting, so the same bundle presented twice denies `nonce_replayed` while a re-issued one does not. Classical-mode replay protection is **cooperative**: the nullifier is host-reserved, not proof-bound — an in-process `{ kind: 'classical' }` verifier reserves nothing (see "What is and isn't checked").
- Tested scope: single-method HTTP `Request` charge handlers at mppx 0.8.13. `compose` intents, non-`Request` transports, and per-item streaming authorization are not established.

### Issuing the mandate (operator side)

The presentation the agent carries is minted by the operator with the Bolyra
CLI — [`bolyra mandate issue`](../cli#issue-a-spend-mandate-bolyra-mandate-issue)
— not hand-assembled. The operator signs a request binding for one agent, one
audience, and one financial tier, and the CLI prints the exact `bvp/1`
presentation this gate verifies:

```bash
bolyra key generate --out operator.key         # one-time: the operator key
bolyra mandate issue \
  --operator-key operator.key \
  --agent shopper-bot \
  --audience api.merchant.example \
  --model opus-4.1 \
  --tier small \
  --expiry 30d
# stdout: the base64url bvp/1 presentation → the X-Bolyra-Authorization header.
# stderr: a summary + the operator public key to list in `trustedOperators` above.
```

The operator public key printed on stderr is exactly what you configure as a
`trustedOperators` entry in the gate. **This is issuance, not key management or
a wallet:** the operator key is one you already hold; `bolyra mandate issue`
never generates, stores, or rotates keys, holds funds, or settles payments — it
signs one standing spend mandate. `@bolyra/mpp`'s test fixtures mint through the
same issuance path (`issueMandate`), so there is one code path, not two.

The mandate is standing; the **presentation is one-shot**. Every issuance carries
a fresh random nullifier, and a hosted verifier has the gate reserve it on allow,
so mint a new presentation for each action instead of re-sending one (the signer
is local; issuing is cheap). See "Hooks and discovery" above.

In classical mode the operator signature binds the request binding
(`{agent, audience, program, model, capabilities, expiry}` — binding v2), so both
the **spend ceiling** (signed capability tier) and the **time bound** (`expiry`,
pinned equal to the credential expiry) are tamper-evident: a presenter can no
longer re-anchor a later expiry on an issued mandate. The `permission_bitmask`
remains a self-asserted consistency field; sound bitmask enforcement still needs
the zk-class verifier. See "What is and isn't checked" below.

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
| `audience` | `string` | required | Byte-literal match against the mandate's signed `project_key` (payee binding). Must be a stable machine identifier — printable ASCII excluding space, 1..256 chars (receipt instance binding §3.1.1); display names are rejected at construction |
| `verifier` | `VerifierConfig` | required | `classical` (in-process), `command` (EVC v1 spawn), or `url` (hosted verifier) |
| `verifier.trustedOperators` | `{x, y}[]` | required for `classical` | Decimal-string operator pubkeys; empty set fails closed |
| `program` | `string` | `"mpp"` | Binding `program` discriminator |
| `model` | `string` | echo bundle | Optional model pin; when set, the signed binding must name it |
| `amountToUsd` | `(ctx) => string \| number` | `options.amount` as USD | Resolve route amounts for tier mapping; errors fail closed |
| `enforce` | `"always" \| "payment"` | `"always"` | `"payment"` skips gating on credential-less challenge probes |
| `header` | `string` | `x-bolyra-authorization` | Request header carrying the presentation; `Authorization` is rejected (MPP's payment credential rides it) |
| `nonceStore` | `NonceStoreLike` | in-memory | Reserve-before-act store for host-nonce-mode verifiers; **inject a shared, durable store for multi-instance deployments** |
| `receipts` | `{issuer?, keyId?, privateKey?}` | ephemeral key | ES256K decision receipts; pin a key in production |
| `onReceipt` | `(receipt) => void` | — | Sink for every signed decision receipt (allow and deny). Receipts carry a signed `instance` block (receipt instance binding v1) whenever the spend facts are resolved; verify with `verifyInstanceBinding` from `@bolyra/receipts` in addition to `verifyReceipt` |
| `now` | `() => number` | `Date.now`-derived | Clock override (unix **seconds**). Tests only. Mutually exclusive with `nowMs`; receipts built from it carry `.000Z` decision timestamps |
| `nowMs` | `() => number` | `Date.now` | Clock override (epoch **milliseconds**). Tests only. Mutually exclusive with `now`; drives both the verifier clock and the ms-precision `decisionAt` in the receipt instance block |

Related exports: `buildDecisionInstance(facts)` builds the signed instance block from `DecisionInstanceFacts` — the pure spec-§3 preimage facts (`audience`/`program`/`capabilities`/`amountUsd`/`decisionAt`/`requestNonce?`); derive them from resolved receipt facts with `instanceFactsFrom(receiptFacts)`. Hosts emitting their own receipts — e.g. x402 EVC profile hosts — set `requestNonce` to their pre-decision challenge nonce. `AUDIENCE_IDENTIFIER_PATTERN` is the §3.1.1 audience syntax.

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
> `{agent_name, project_key, program, model, capabilities, expiry}`, the request
> matches that signed binding, and the granted capability (the amount's
> financial tier) is a subset of it.

Checked (classical):

- trusted-operator gate (`trustedOperators`; empty set fails closed)
- EdDSA-Poseidon binding signature against that operator key (binding v2 — the
  signed binding includes `expiry`)
- signed `binding.expiry == credential.expiry` (binding v2); an obsolete
  five-field v1 binding is rejected `unsupported_version`
- byte-literal request↔binding match — `project_key` is your `audience`
- granted tier capability ⊆ operator-signed capabilities
- consistency checks on the revealed credential: Poseidon scope anchoring,
  model-hash binding, cumulative permission-bit subset, strict expiry
  (`now == expiry` is expired) over the signature-bound expiry

**Not** checked (classical):

- Groth16 proof verification, Merkle-root inclusion, human-uniqueness, and
  delegation-chain proofs — bundles carrying zk-only slots are **denied**,
  not half-verified; use a zk-class external verifier (`bolyra verify`) via
  `verifier: { kind: 'command', … }` for those
- sound **permission-bitmask** enforcement against a malicious trusted operator:
  the revealed `permission_bitmask` is a self-asserted consistency field (the
  scope commitment is recomputable from public inputs). `expiry`, by contrast,
  IS tamper-evident as of binding v2 — signed and pinned to the credential
  expiry — so a re-anchored expiry no longer verifies. For sound bitmask/scope
  enforcement use the zk-class verifier (`bolyra verify`).
- replay: a spend mandate is a *standing* authorization, reusable within tier
  and expiry by design; per-payment idempotency is MPP's challenge binding.
  Replay protection in classical mode is **cooperative**: the binding
  signature does not cover the nullifier (`publicSignals[1]`), so a presenter
  can rewrite it and re-present. External verifiers in host nonce mode make
  UNMODIFIED re-sends one-shot — the gate reserves their `consume_nonces`
  before acting — but nothing binds the nullifier to the proof. The default
  reservation store is in-memory and per-process: it does not survive
  restarts or span instances — inject `nonceStore` for that.
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
delegated small-tier mandate issued by the real `bolyra mandate issue` CLI, an
allowed $25 spend and a denied $500 spend — lives in
[`examples/mandate-demo`](./examples/mandate-demo). It shells out to the CLI, so
build the CLI first:

```bash
(cd ../cli && npm install && npm run build)   # once: build the CLI the demo calls
cd examples/mandate-demo && npm install && npm run demo
```

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
