# Bolyra as an Authorization Companion to MPP

**Status:** mapping note, v0.1 (2026-07-12). Not affiliated with or endorsed by
the MPP authors. MPP is the [Machine Payments Protocol](https://mpp.dev)
co-developed by Tempo Labs and Stripe.

## Two different questions

MPP gives machines a payment interface: request a resource, receive an HTTP
402 Challenge (method, intent, and an encoded payment request such as the
amount — usually with an expiry), retry with a payment Credential, and get
the resource; success may include a Payment-Receipt. The protocol is an
IETF Internet-Draft (work in progress). It answers, cleanly and atomically:

> **"Did this client pay?"**

It deliberately does not answer a second question that arrives the moment the
paying client is an autonomous agent rather than its operator:

> **"Was this agent authorized to spend?"**

The payment credential proves the method-specific right to pay. It does
not, by itself, prove an operator-to-agent spending mandate: that the
operator delegated spending authority to *this* agent, at *this* limit,
until *this* expiry. For one agent and one human that may be
acceptable; for agent fleets, sub-delegation, and operator liability it is
not.

## The mapping

Bolyra composes with the MPP flow without modifying it:

| MPP step | MPP answers | Bolyra adds |
|---|---|---|
| 1. Request | — | Agent carries a delegated credential: operator-signed permission mask (`FINANCIAL_SMALL / MEDIUM / UNLIMITED` tiers), expiry, and a delegation chain that can only narrow |
| 2. 402 Challenge | method, intent, encoded payment request (e.g. amount), usually expiry | Client-side check: does the challenge amount fit the agent's delegated financial tier? Deny locally before any funds move |
| 3. Credential | payment proof | Alongside the payment Credential, the agent's authorization proof: who delegated, what scope, verified against the operator's key |
| 4. Verification + Payment-Receipt | payment valid; proof of delivery | Server (or a gateway in front of it) verifies authorization via an external verifier before accepting payment; emits a signed authorization receipt |

The server-side check uses the
[External Verifier Contract v1](https://github.com/bolyra/bolyra/blob/main/spec/external-verifier-contract-v1.md):
one JSON request in (the agent's proof bundle + the action), one fail-closed
allow/deny verdict out. Implementations: `bolyra verify` (spawnable CLI — the zk-class verifier
with full scope/expiry/delegation-chain enforcement), a design-partner
hosted HTTP preview for classical zero-install evaluation, JS and Rust
reference hosts, and conformance vectors including hostile-verifier
fixtures. Verifiers
self-describe `kind: classical | zk | external`, so a service can start with
classical signature verification and adopt zero-knowledge verification
(spend authority proven without disclosing the delegation graph or operator
identity) without changing the integration.

## The audit story

Each MPP transaction can then leave two composable receipts:

- **Bolyra authorization receipt** — who delegated the authority, which agent
  acted, under what scope; ES256K-signed, hash-chained (sequence + previous
  hash inside the signed payload), so deletion or reordering of the log is
  detectable.
- **MPP Payment-Receipt** — proof of delivery for the payment itself.

Together they give an audit path — **approved → paid → delivered**.
Bolyra's authorization log is offline-verifiable with the signer keys (with
an externally pinned head/count closing tail truncation); MPP payment and
delivery evidence is verified according to the payment method and the
server's receipt policy.

## One line

**MPP moves the money; Bolyra proves the mandate.**

## Contact

Viswa Kondoju — kondojuviswanadha@gmail.com — [bolyra.ai](https://bolyra.ai)
