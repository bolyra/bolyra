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
v1 verifiers ignore it, which is exactly why the checks below are split
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
  verifier cannot see the extension's payee.
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
`x402-evc-nonce` value, byte-for-byte.

Why this profile can and must do better than a timestamp discriminator:
the challenge nonce is issued in the 402 response *before* the retry, so
BOTH sides hold it pre-decision. That makes the instance reference
recomputable by the counterparty (unlike the issuer-generated
`proof.nonce`) and closes the same-millisecond residual that
timestamp-only discrimination leaves open. The host already holds the
value — it is `context.nonce` in `verifyX402EvcAuthorization`'s options —
so populating `requestNonce` at receipt emission requires no new
plumbing, only the emission-side wiring of the instance block itself.

A profile-aware relying party MAY additionally join
`instance.preimage.requestNonce` against its own record of the challenge
it issued: a receipt claiming an instance under a nonce the payee never
issued is evidence of fabrication even when the signature verifies.

## 5. Open question (the reason this draft exists)

Where should this live: an x402 extension profile, an app-layer example in
the x402 repo, or a separate ecosystem package? The reference implementation
(`@bolyra/payment-protocols` → `x402-evc.ts`, runnable example
`examples/x402-evc-profile/`) is deliberately shaped so any of the three is a
move, not a rewrite.
