# Bolyra Hosted Verify

> ## ⚠️ DESIGN PARTNER PREVIEW
>
> This is a **preview for design partners** — not a production service. No
> SLA, no uptime guarantee, no billing, single shared bearer token, and the
> deployment may be reset at any time. It exists so a host team can try the
> [External Verifier Contract v1](../../spec/external-verifier-contract-v1.md)
> over HTTP in five minutes, before wiring up the `bolyra verify` CLI.

**What it is:** [`bolyra verify`](../cli/)'s External Verifier Contract v1,
exposed as an HTTP endpoint on Cloudflare Workers. `POST /v1/verify` accepts
the exact JSON request object the CLI reads on stdin (spec §2) and returns
exactly one strict spec §3.4 verdict object.

**What kind of verifier it is:** `classical` (Bolyra Core, spec §3.5). Every
verdict carries `"kind": "classical"`. This preview performs **classical
cryptographic and policy checks only** — it does **not** verify zero-knowledge
proofs.

### What an `allow` actually means (read this)

Because the preview does **not** verify the Groth16 proof, every public signal
and credential field in the bundle is *self-asserted* — an attacker can put any
value there. The one cryptographically load-bearing fact in a proof-less bundle
is the operator's EdDSA-Poseidon signature over the request binding (spec §4).
So an `allow` means, and only means:

> A configured **trusted operator** (`TRUSTED_OPERATORS`) signed a binding
> authorizing this exact `{agent_name, project_key, program, model,
> capabilities}`, the request matches that signed binding, and the granted
> capabilities are a subset of it.

The trust anchor is the **operator key set**, not the proof's Merkle root
(which is unverified here and carries no weight). Scope-bitmask and expiry are
checked against the revealed credential for internal consistency, but they are
**not** part of the operator-signed binding in `bvp/1`, so sound enforcement of
scope and expiry requires the zk-class [`bolyra verify`](../cli/) CLI. The live
[`/health`](#get-health) response spells out exactly which checks are
signature-authenticated vs. consistency-only.

## 5-minute quickstart

You need the preview URL and bearer token (ask Viswa — issued per design
partner).

```bash
BASE=https://bolyra-hosted-verify.<account>.workers.dev   # preview URL
TOKEN=<your preview token>

# 1. Health + capability disclosure (no auth):
curl -s $BASE/health | jq

# 2. Verify a known-good presentation (allow):
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq

# → { "verdict": "allow", "kind": "classical",
#     "consume_nonces": [ { "issuer_key": "…", "nonce": "…", "retain_until": … } ] }

# 3. A presentation whose credential lacks the required scope (deny):
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @examples/request.deny-scope.json | jq

# → { "verdict": "deny", "kind": "classical", "code": "scope_exceeded", … }
```

The two example request files are copies of the repo's conformance fixtures
(`integrations/cli/test/fixtures/verify/`); the preview deployment trusts the
fixture operator key so the quickstart works out of the box. To verify **your
own** presentations, your operator public key must be pinned in the
deployment's `TRUSTED_OPERATORS` — that is the design-partner conversation.

## API

### `POST /v1/verify`

- **Auth:** `Authorization: Bearer <preview token>` — anything else is `401`.
- **Body:** one spec §2.1 request object (`version`, `bundle`, `request`,
  `now_unix`), capped at **1 MiB** (the spec §6 stdin bound). The optional
  extension field `kind` may be set to `"classical"`; any other value (e.g.
  `"zk"`) is denied — this endpoint does not do zk verification.
- **Response body:** exactly one spec §3.4 verdict object (closed schema),
  always with `"kind": "classical"`.
- **HTTP status mapping** of the CLI's exit-code semantics (spec §7.1):
  - `200` — a decision was produced: `allow` **or** any policy/crypto `deny`.
    Branch on the verdict, not the status.
  - `500` + `deny code=internal_error` — the verifier could not produce a
    trustworthy verdict (e.g. no trusted roots configured). Fail closed.
  - `401` / `404` / `405` — transport-level errors *before* the contract;
    the body is `{ "error": … }`, not a verdict.
- **Fail-closed:** malformed JSON, non-object bodies, oversized bodies, wrong
  request version, undecodable bundles — every one is an explicit `deny` with
  a spec §9 code, never a silent allow.

### Replay protection: host nonce mode only (and its classical limit)

The Worker is stateless, so it always behaves like `bolyra verify
--nonce-mode host` (spec §8): an `allow` carries `consume_nonces`, and **you
must reserve every entry in durable storage before acting** — reserve-before-
act, spec §7.3. If any nonce was already recorded, treat the presentation as
a replay and reject it even though the verdict said `allow`. There is no
local-mode replay state in this preview.

**Classical caveat (important):** the emitted `nonce` is the bundle's
`nullifierHash` public signal, which — like every other signal — is *not*
verified here (no Groth16). So `consume_nonces` reliably stops replay of the
*identical* bundle, but it is **not** a sound one-time guarantee: a presenter
holding a trusted-operator-signed binding can mint a fresh nullifier and
re-present. Sound single-use enforcement (nullifier bound to the proof)
requires the zk-class `bolyra verify` CLI. Treat host-mode replay reservation
here as consistency-only, in the same bucket as scope and expiry.

### `GET /health`

Unauthenticated. Returns service status, the **DESIGN PARTNER PREVIEW**
label, `verifier_kind: "classical"`, `nonce_mode: "host"`, a `trust_model`
sentence, and the live `checks_authenticated` / `checks_consistency_only` /
`checks_not_performed` lists (the honest capability disclosure below,
machine-readable).

### Signed receipts (`X-Bolyra-Receipt`)

When the deployment has a receipt signing key configured, every response
(allow **and** deny) carries an `X-Bolyra-Receipt` header: a base64url-encoded
[`@bolyra/receipts`](../receipts/) `SignedReceipt` (ES256K over canonical
JSON) attesting to the decision. The response body stays a pure §3.4 verdict —
the closed schema forbids extra fields, hence the header. Verify it with:

```ts
import { verifyReceipt } from '@bolyra/receipts';
const receipt = JSON.parse(atob(header.replace(/-/g, '+').replace(/_/g, '/')));
verifyReceipt(receipt); // → true, signer recoverable from the signature
```

## What it checks (and what it does not)

**Signature-authenticated (sound)** — every item is either an
operator-signed fact or a fail-closed gate:

1. **Trusted-operator gate** — the credential's operator key must be in the
   configured `TRUSTED_OPERATORS` set (no operators configured = fail closed,
   spec §12).
2. **BabyJubjub EdDSA-Poseidon binding signature** (spec §4) — the operator's
   signature over the canonical request binding, against that trusted operator
   key. An attacker cannot forge this for a key they do not hold.
3. Byte-literal request↔binding match (`agent_name` / `project_key` /
   `program` / `model`).
4. `granted_capabilities ⊆` the operator-signed capabilities.

**Consistency-only (NOT operator-signed in `bvp/1`)** — these catch honest
misconfiguration and are needed for internal coherence, but a holder of a
trusted operator key could self-assert any value here, so they do **not**
soundly enforce scope/expiry; the zk-class `bolyra verify` CLI does:

5. Request schema + version (spec §2) and `bvp/1` structure + proof-envelope
   shape (`@bolyra/sdk` `validateEnvelope`).
6. Poseidon scope anchoring — the revealed preimage recomputes the
   *self-asserted* `scopeCommitment` public signal.
7. Model-hash binding — `sha256(model) mod p` equals the revealed
   `modelHash`.
8. Capability → permission-bit mapping + cumulative-scope subset (over the
   revealed bitmask).
9. Strict expiry against caller-supplied `now_unix` (`now == expiry` is
   expired; over the revealed expiry).
10. Nullifier presence + `consume_nonces` emission (host nonce mode).

**Not** performed (zk-class territory — use the `bolyra verify` CLI):

- **Groth16 proof verification + vkey pinning.** The proof envelope is
  structurally validated but the proof math is not checked, so no public
  signal is trusted.
- **Merkle-root inclusion** — the proof's root is unverified and carries no
  trust weight.
- **Human-uniqueness proofs** — human-backed bundles are **denied**, not
  half-verified.
- **Delegation-chain proofs** — delegation-bearing bundles are **denied**.
- **Local replay state** — host nonce mode only (see above).

Pure-JS crypto note: workerd cannot compile the SDK's circomlibjs WASM at
runtime, so Poseidon runs on `poseidon-lite` and EdDSA-Poseidon on
`@zk-kit/eddsa-poseidon` — both use the same circomlibjs-derived constants and
are pinned to the SDK's outputs by this package's conformance tests.

## Conformance

`npm test` runs the spec's `external_verifier` vectors
(`spec/test-vectors.json`) against the Worker in workerd (via
`@cloudflare/vitest-pool-workers`), plus HTTP-surface and fail-closed tests.
Of the 10 `external_verifier` vectors, **5 are driven end-to-end over HTTP**
against the Worker (`allow-agent-only`, `allow-host-nonce`, `deny-malformed-
input`, `deny-scope-exceeded`, `deny-model-mismatch`) and **5 are
`static_verdict` schema vectors** checked against the executable spec §3.4
schema (the `kind` self-description cases). One documented divergence on the
HTTP vectors: `nonce_mode: "local"` produces the same verdict, but the allow
carries `consume_nonces` because this preview is host-mode only.

## Deploy (maintainers)

```bash
npm install
npm test && npm run typecheck
npx wrangler login                      # founder account
npx wrangler secret put PREVIEW_TOKEN   # static preview bearer token
npx wrangler secret put RECEIPT_SIGNER_KEY  # optional: 0x-hex secp256k1 key
npm run deploy                          # workers.dev subdomain ONLY
```

Config lives in `wrangler.jsonc`: `TRUSTED_OPERATORS` (comma-separated `x:y`
decimal operator-key pairs — the deployed default is the repo fixture operator
key), `CAPABILITY_MAP` (optional JSON, merged over the built-in default),
`RECEIPT_ISSUER` / `RECEIPT_KEY_ID`. Deploys go to the workers.dev preview
subdomain only — no custom domains, no routes on bolyra.ai.

## Deliberately out of scope

No SLA, no billing or metering (logs only), no dashboard, no multi-tenant
admin, no zk proving/verification, no custom policy UI, no customer-managed
keys, no status page. If the preview is useful, those conversations come
after.
