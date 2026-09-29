# x402 EVC Authorization-Evidence Profile — v0 (draft)

Status: draft for ecosystem discussion. Companion to the External Verifier
Contract v1 (`spec/external-verifier-contract-v1.md`, "EVC") and to the x402
payment flow. This profile does NOT modify x402 and does NOT modify the EVC
wire; it defines how an x402 resource server carries **authorization
evidence** alongside an x402 payment, using the EVC request's open extension
seam (§2.2 `additionalProperties: true`).

## 1. Problem

x402 proves a payment is **funded and well-formed**. It does not prove the
agent presenting it was **authorized** to spend that amount, with that payee,
at that time. The record after the fact says an action happened without
saying who permitted it. This profile carries a host-verifiable answer to
"who permitted this spend?" through the existing x402 402/retry round-trip —
gate 1 (authorization evidence) of the two-gates model; payee risk (gate 2)
is out of scope by design.

## 2. Flow

1. Resource server responds `402` with its x402 `PAYMENT-REQUIRED`
   requirements, plus a fresh single-use challenge context:
   `x402-evc-nonce` (opaque) and `x402-evc-expires` (unix seconds).
2. The agent retries with its payment credential (unchanged x402) AND an
   operator-signed presentation bundle (`bvp/1`) in the
   `x-bolyra-authorization` header (same header as `@bolyra/mpp`).
3. Before payment settlement logic runs, the server builds an EVC §2.1
   request (this profile, §3) and dispatches it to its configured verifier
   (`classical | command | url`). A `deny` short-circuits with RFC 9457
   `application/problem+json` (the EVC §9 code taxonomy). Only an `allow`
   lets the payment proceed.
4. The decision MAY be recorded as an ES256K hash-chained decision receipt
   (`@bolyra/receipts`) — the handoff artifact to any downstream risk layer.

The host checks in step 3 MAY instead be run by an **agent-side host** (a
payer-side enforcement point holding the operator's mandate) when the
resource server does not participate in this profile; see §4.2.

## 3. Request extension

The EVC request envelope gains one profile member (envelope-level, §2.2 seam;
the `request` object and `bundle` are unchanged, so every conformant v1
verifier keeps working — verifiers that do not understand the profile simply
ignore it):

```json
{
  "version": 1,
  "bundle": "<bvp/1 presentation>",
  "request": {
    "agent_name": "<from the signed binding>",
    "project_key": "<audience — MUST equal the payee identity the host serves>",
    "program": "x402",
    "model": "<host-pinned or echoed>",
    "granted_capabilities": ["<tier token for the USD amount>"]
  },
  "now_unix": 1755900000,
  "x402_evc": {
    "profile": "x402_evc/0",
    "resource": "<the paid resource being accessed>",
    "amount": "<decimal USD string>",
    "asset": "<requirements.asset>",
    "network": "<requirements.network>",
    "payee": "<requirements.payTo>",
    "nonce": "<the 402 challenge nonce>",
    "expires_at": 1755900300,
    "verifier": "classical | command | url"
  }
}
```

Payment fields follow **x402 v2 vocabulary** (`network`, `payTo`, atomic-unit
string amounts in the 402's `accepts` entries); the profile's `amount` is the
host-resolved decimal USD value used for tier mapping.

Field semantics — and, importantly, who enforces what. The cryptographically
enforced binding is the EVC one: the operator's signature over `{agent_name,
project_key, program, model, capabilities, expiry}`. The `x402_evc` extension
member is **carried for audit and for profile-aware verifiers**; conformant
the default v1 verifier does not evaluate it, which is exactly why the checks below are split
between verifier and host:

- `resource` — the identifier of the paid route/resource, carried so the
  decision record names *what* was accessed. Not part of the signed binding
  in v0; a profile-aware verifier MAY enforce it, and receipts record it.
- `amount` — decimal USD. The host maps it to the cumulative financial-tier
  capability (`requiredTierForUsdAmount`); the VERIFIER enforces the signed
  tier ceiling, so an over-mandate amount denies `request_mismatch` /
  `scope_exceeded` exactly as in `@bolyra/mpp`.
- `payee` — the x402 `payTo`. Two checks compose: the VERIFIER compares the
  mandate's signed `project_key` byte-literally to the host `audience`
  (mandate signed for another audience → `request_mismatch`), and the HOST
  must check that its `audience` covers `payTo` (byte-literal equality by
  default, or an explicit canonicalization) BEFORE dispatch — a mismatch
  denies `request_mismatch` without consulting the verifier, because the
  host is the actor that binds `payTo` to its `audience` before dispatch;
  the default (v1) verifier does not evaluate the `x402_evc` extension,
  though a profile-aware verifier MAY. When `payTo` is a placeholder rather
  than a stable identifier, §4.2 defines the only supported binding.
- `nonce` / `expires_at` — the 402 challenge context. The HOST owns both
  checks (EVC §7): a stale context denies `expired`; a reused nonce denies
  `nonce_replayed` via reserve-before-act (§7.3).
- `verifier` — which verifier class the host dispatched to (§3.5 vocabulary),
  recorded for the receipt/audit trail.

## 4. Host obligations (unchanged from EVC v1)

Fail closed on every failure class (missing header, malformed bundle,
verifier timeout/crash/invalid verdict → deny, never allow). Denials are
RFC 9457 problem+json with the stable `code` member; HTTP status per
`@bolyra/mpp`'s `DENY_STATUS` (401 authorization-never-established / 403
mandate-does-not-cover-this / 500 fail-closed).

### 4.1 Decision receipts: instance binding is REQUIRED for this profile

When a host records profile decisions as decision receipts
(`@bolyra/receipts`), each receipt MUST carry the `instance` block of
[receipt-instance-binding-v1](./receipt-instance-binding-v1.md) with
`preimage.requestNonce` set to this profile's 402 challenge nonce — the
`x402-evc-nonce` value, byte-for-byte. In local mode (§4.2) there is no
server-issued nonce: `requestNonce` is the SHA-256 of the `PAYMENT-REQUIRED`
header value exactly as received, so the receipt commits to the challenge
bytes. Receipts do NOT commit to the §4.2 `payee_binding` member.

Why this profile can and must do better than a timestamp discriminator:
the challenge nonce is issued in the 402 response *before* the retry, so
BOTH sides hold it pre-decision. That makes the instance reference
recomputable by the counterparty (unlike the issuer-generated
`proof.nonce`) and closes the same-millisecond residual that
timestamp-only discrimination leaves open. The concrete emission path: the
host already holds the value as `context.nonce` in
`verifyX402EvcAuthorization`'s options, and `@bolyra/mpp` exposes
`DecisionFacts.requestNonce` + `buildDecisionInstance()` — a profile host
recording receipts sets `requestNonce: context.nonce` in the facts it
builds the instance block from. (`bolyraGate` itself is the MPP-transport
gate and has no challenge nonce; this requirement binds profile hosts,
who own their receipt emission.)

A profile-aware relying party MAY additionally join
`instance.preimage.requestNonce` against its own record of the challenge
it issued: a receipt claiming an instance under a nonce the payee never
issued is evidence of fabrication even when the signature verifies.

### 4.2 Issuer-quoted payee binding (agent-side host, placeholder `payTo`)

**Applicability.** A 402 leg whose `payTo` is a placeholder resolved by a
settlement rail (e.g. `urn:x402:agent-pay:see-quote`) and whose `extra`
carries a quote token signed by the payee identity. It does NOT apply to
derived on-chain addresses: a `payTo` that byte-differs from the host
`audience` and carries no issuer-signed quote MUST deny `request_mismatch`.

**Role.** An *agent-side host* is a payer-side enforcement point (agent
platform, wallet, gateway) that receives the 402, holds the operator's
mandate for a named payee identity, and decides before releasing payment.
`audience` is that payee identity, selected by HOST POLICY from the mandate
and configuration — never read from the incoming quote, never confused with
the platform identity or the token `aud`. Enabling quote semantics for an
audience is explicit configuration. The mandate for `audience` authorizes
*quotes issued by that identity for the configured product*; it does not
authorize arbitrary settlements merely quoted by that issuer, and the
settlement destination remains the rail's.

**Local challenge context.** The server issues no `x402-evc-nonce`, so the
host builds the context: `resource` is the exact outbound request URL the
agent will pay for (host-known); `nonce` is the SHA-256 (lowercase hex) of
the `PAYMENT-REQUIRED` header value exactly as received; `expires_at` is
provisional (receipt time plus the leg's `maxTimeoutSeconds`, capped by host
policy, at most 900 s) and is finalized as the minimum of that and the
quote's acceptance deadline. A host MUST NOT refresh an existing context's
receipt time. The header-hash nonce prevents re-authorizing the same
challenge bytes within one enforcement authority's retained window only;
the quote's single-use `(iss, jti)` is the replay protection that does not
renew, so this mode REQUIRES it. Exactly one checked leg is passed to
settlement and only from an allow decision; a host MUST NOT fall back to
another leg after a deny. Replay protection spans one enforcement
authority's shared durable store; unrelated payer hosts do not share it.

**Host MUSTs.** (1) Public keys are provisioned out of band; no key
discovery, no token-supplied key sources (`jwk`, `jku`, `x5u`, `x5c`).
(2) The token `iss` byte-equals `audience`. (3) The token `alg` equals the
configured algorithm for the configured `kid` exactly (ES256 or ES384; no
`none`, no `crit`, no unencoded payload). (4) The token `aud` equals the
configured settlement audience and the signed payee role (e.g. `seller`)
equals the configured role. (5) The leg's `scheme`, `network` and
placeholder `payTo` byte-equal the configured rail. (6) `iat`, `exp` (and
`nbf` when present) are enforced with a stated tolerance and a bounded
lifetime. (7) `(iss, jti)` is single-use via reserve-before-act (EVC §7.3),
retained through the quote's whole acceptance window, together with the
challenge nonce, atomically. (8) The signed price equals the leg's amount
and ISO currency, the host-declared product claims for `resource` are
present and equal, and every settlement-consumed challenge field equals its
authenticated claim; every other leaf under the leg's `extra` MUST be either
the quote token or explicitly declared unbound by host configuration, else
the request denies, and the checked leg passed to settlement MUST carry
only the token and the bound settlement fields. (9) The extension records
`payee_binding` (issuer, `kid`, `jti`, `exp`, SHA-256 of the compact token)
and `payee` stays the literal placeholder; the token hash is an audit
handle, not a unique quote identifier (signature malleability), and replay
identity is `(iss, jti)`.

**MUST NOT claim.** A verified binding establishes who quoted this product
at this price within this window. It does NOT establish the settlement
destination, ownership of any address, delivery, or that the quote was
addressed to this host (`aud` is the settlement rail). `payee_binding` is a
host assertion for audit, not independently verifiable evidence, and
receipts under §4.1 do not commit to it. Payee risk (gate 2) remains out of
scope.

**Non-normative example (observed 2026-09-29, from probe402's 2026-09-28
report; no endorsement implied).** Tavily's `POST /search` 402 offered two
legs. An `exact` leg on Base USDC whose `payTo` differed on every call with
an `extra` of {name, version, terms, tier} and nothing to bind it to: out of
scope, denied. An `agent-pay` leg with `payTo` `urn:x402:agent-pay:see-quote`
and `extra.quoteToken`, an ES384 JWT (`iss https://x402.tavily.com`, `aud
aws:marketplace`, 300 s lifetime, fresh `jti`, `price`, `payTo "seller"`,
`reference`, `settlement.product_id`), with no published key set: the shape
this section binds, given an out-of-band key.

## 5. Open question (the reason this draft exists)

Where should this live: an x402 extension profile, an app-layer example in
the x402 repo, or a separate ecosystem package? The reference implementation
(`@bolyra/payment-protocols` → `x402-evc.ts`, runnable example
`examples/x402-evc-profile/`) is deliberately shaped so any of the three is a
move, not a rewrite.
