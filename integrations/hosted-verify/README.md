# Bolyra Hosted Verify

> ## ⚠️ DESIGN PARTNER PREVIEW
>
> This is a **preview for design partners** — not a production service. No
> SLA, no uptime guarantee, no billing, per-tenant admin and verifier tokens, and the deployment may be reset at any time — a reset clears the managed credential registry, so every binding must be registered again before it will verify. It exists so a host team can try the
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

> An operator the calling tenant configured as **trusted** (the tenant's
> `trusted_operators` list in the deployment's `TENANTS` secret) signed a
> binding authorizing this exact `{agent_name, project_key, program, model,
> capabilities, expiry}` (binding v2), the request matches that signed binding,
> the granted capabilities are a subset of it, **and that signed binding is
> ACTIVE in the tenant's managed credential registry** (registered with
> `POST /v1/credentials` and not revoked).

**Trust-policy amendment (managed registry).** For this verifier, the
configured trusted-root source (spec §9, `untrusted_root`) is *active
signer-binding membership in the tenant's registry*, in addition to
operator-key membership. A credential that is not ACTIVE — never registered,
or revoked — is outside the trusted-root source, so the verdict is
`deny untrusted_root` with `detail: { "reason": "credential_not_active",
"credential_id": "<hex>" }`. Revocation is trust-anchor removal. The EVC spec
does not define a revocation mechanism; this is a documented verifier policy,
permitted because `untrusted_root` is proof-system-agnostic and the deny
schema is unchanged. The registry is consulted only after every classical
check passes; a registry failure or a **2,000 ms** read deadline is the
fail-closed `500` `internal_error` verdict, never an allow.

**Rollout.** Register every binding a tenant expects to verify *before*
deploying a build that reports `registry_enforced: true` on `/health`; once
such a build has served a tenant, a build that verified without the registry
must never be deployed again.

The trust anchor is the **operator key set plus the tenant's registry** (the
amendment above), not the proof's Merkle root (which is unverified here and
carries no weight). As of **binding v2** the signed
binding includes `expiry` (pinned equal to the revealed credential expiry), so a
presenter cannot re-anchor a later expiry — the obsolete five-field v1 binding is
rejected `unsupported_version`. The scope-bitmask remains checked against the
revealed credential for internal consistency only, so sound scope enforcement
still requires the zk-class [`bolyra verify`](../cli/) CLI. The live
[`/health`](#get-health) response spells out exactly which checks are
signature-authenticated vs. consistency-only.

The runnable proof of the behaviour above is
[`examples/managed-revocation`](../../examples/managed-revocation/README.md):
against a deployment that trusts the example's operator key, carries the mpp
capability vocabulary, and has receipts enabled (its README lists the
prerequisites), it runs register → allow → allow → revoke → deny → an
independent credential still allows, 21 checks in all. `GET /health` reports
`registry_enforced: true`; when a signer key is configured,
`/.well-known/bolyra-signers.json` publishes the signer address.

## Try it in two commands (no credentials)

Nothing to request and nothing to sign: the Worker runs locally under
`wrangler dev` with the repo's documented placeholder tenant, which trusts the
repo's conformance-fixture operator key (its private half is public — this
proves the mechanics, not who signed). Prerequisites: Node 22+ (wrangler's
requirement), bash and `lsof` (macOS or Linux), and a checkout of this repo;
curl and jq are for the curl steps below.

```bash
cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"
npm ci
npm run smoke:dev
```

`smoke:dev` boots the Worker on `127.0.0.1:8787` (`HOSTED_VERIFY_PORT` picks
another port) with a fresh, empty registry, checks `/health`, shows an
unregistered binding denied `untrusted_root` / `credential_not_active`,
registers the fixture binding, shows the same presentation allowed with its
`x-bolyra-credential-id`, and stops the Worker. `npm run verify:dev` runs the
full post-deploy check against a local Worker instead: the auth boundary plus a
canary credential taken ABSENT → ACTIVE → REVOKED.

### The same flow by hand

Start the Worker and leave it running (`scripts/dev-vars.mjs` writes a
`.dev.vars` with the placeholder tenant, the mpp capability vocabulary, and a
throwaway receipt key; `npm run smoke:dev` removes and rewrites it itself):

```bash
cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"
node scripts/dev-vars.mjs
npm run dev          # wrangler dev on http://localhost:8787
```

In a second terminal (the tokens are the placeholders from `.dev.vars.example`,
not secrets):

```bash
cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"
BASE=http://localhost:8787
ADMIN=local-admin-token-000000000000000000
TOKEN=local-verifier-token-0000000000000000

# 1. Health + capability disclosure (no auth):
curl -s $BASE/health | jq

# 2. Register the fixture binding (admin token) and keep its id:
ID=$(curl -s -X POST $BASE/v1/credentials \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  --data @examples/registration.allow.json | jq -r .credential_id)
echo "$ID"

# 3. A presentation of that binding (verifier token) → allow:
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq

# 4. A presentation whose credential lacks the required scope → deny scope_exceeded:
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/request.deny-scope.json | jq

# 5. Revoke it (204), then step 3 again → deny untrusted_root, detail.reason credential_not_active:
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/v1/credentials/$ID/revoke \
  -H "Authorization: Bearer $ADMIN"
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq
```

`wrangler dev` keeps the registry under `.wrangler/state` across restarts, so
on a second run step 2 answers `409 credential_revoked` (revocation is
terminal). `rm -rf .wrangler/state` starts empty; `npm run smoke:dev` always
does.

When you want your own operator key and a hosted URL, [request a trial
tenant](#request-a-trial-tenant-hosted-preview-quickstart).

## Developing

Node **22+** (wrangler's requirement; pinned by `.nvmrc` and `engines`). `npm run typecheck` runs `wrangler types` first: the
Cloudflare runtime globals (`ExecutionContext`, `AnalyticsEngineDataset`, …) come from the
generated, gitignored `worker-configuration.d.ts`, so a plain `tsc --noEmit` on a fresh clone
fails until it exists. `npm test` (vitest in the workers pool, then `npm run test:agreement`
under plain Node) does not need it.

`npx wrangler dev` needs a `TENANTS` value: `node scripts/dev-vars.mjs` writes
one (see [The same flow by hand](#the-same-flow-by-hand)), or `cp
.dev.vars.example .dev.vars` for the tenant alone. Either defines one local
tenant with placeholder tokens (not secrets) whose `trusted_operators` is the
repo fixture operator key. The local registry starts empty.

## Request a trial tenant (hosted preview quickstart)

The hosted preview needs a tenant: send your operator public key as described
in [`pilot/INTEGRATION.md`](../../pilot/INTEGRATION.md#request-a-trial-tenant)
and we reply with the preview URL and your tenant's **verifier token** and
**admin token** (both issued per design partner at provisioning). Then, from a
checkout of this repo:

```bash
cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"
BASE=https://bolyra-hosted-verify.<account>.workers.dev   # preview URL
TOKEN=<your verifier token>
ADMIN=<your admin token>

# 1. Health + capability disclosure (no auth):
curl -s $BASE/health | jq

# 2. Register the example's signed binding in your tenant's registry
#    (admin token; idempotent while ACTIVE — a second call returns 200 with the
#     same id, and 409 once the credential has been revoked):
curl -s -X POST $BASE/v1/credentials \
  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  --data @examples/registration.allow.json | jq

# → { "credential_id": "<64 hex>", "status": "ACTIVE", "registered_at": … }

# 3. Verify a known-good presentation of that binding (allow):
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq

# → { "verdict": "allow", "kind": "classical",
#     "consume_nonces": [ { "issuer_key": "…", "nonce": "…", "retain_until": … } ] }
#   (the response also carries x-bolyra-credential-id: <the id from step 2>)

# 4. A presentation whose credential lacks the required scope (deny):
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @examples/request.deny-scope.json | jq

# → { "verdict": "deny", "kind": "classical", "code": "scope_exceeded", … }
```

Without step 2, step 3 answers `deny untrusted_root` with
`detail.reason: "credential_not_active"` — an allow requires the signed binding
to be ACTIVE in the calling tenant's registry, not just a trusted operator key.
The example request files are copies of the repo's conformance fixtures
(`integrations/cli/test/fixtures/verify/`, binding v2) and the registration
file is that fixture's signed binding in the `POST /v1/credentials` shape; the
fixture operator key is seeded into every pilot tenant's `trusted_operators`,
so the quickstart works as issued. To verify **your own** presentations, your
operator public key must be in that list *and* each signed binding must be
registered — that is the design-partner conversation.

The runnable revocation demonstration — issue, register, spend through the
published `@bolyra/mpp` gate, revoke, and the next fresh presentation denied
before the paid action runs — is
[`examples/managed-revocation`](../../examples/managed-revocation/README.md).

## API

### `POST /v1/verify`

- **Auth:** `Authorization: Bearer <verifier token>` — anything else is `401`.
  Every design partner is a **tenant** in the deployment's `TENANTS` secret with
  two tokens: a *verifier* token (this route) and an *admin* token (reserved
  for tenant administration; refused on this route). Tokens are compared in constant
  time; an admin token on this route is `403 {"error":"forbidden"}`. Usage
  analytics attribute requests to `<org_id>:<role>` — never to token values.
  Auth failures are recorded under the reserved label `unauthenticated`.
- **Body:** one spec §2.1 request object (`version`, `bundle`, `request`,
  `now_unix`), capped at **1 MiB** (the spec §6 stdin bound) and required to
  arrive within **5 s**. The optional
  extension field `kind` may be set to `"classical"`; any other value (e.g.
  `"zk"`) is denied — this endpoint does not do zk verification.
- **Response body:** exactly one spec §3.4 verdict object (closed schema),
  always with `"kind": "classical"`.
- **HTTP status mapping** of the CLI's exit-code semantics (spec §7.1):
  - `200` — a decision was produced: `allow` **or** any policy/crypto `deny`.
    Branch on the verdict, not the status.
  - `500` + `deny code=internal_error` — the verifier could not produce a
    trustworthy verdict (e.g. no trusted roots configured, or the tenant's
    credential registry was unreachable inside the 2,000 ms deadline, or the
    request body stalled past its 5 s deadline). Fail closed.
  - `401` / `404` / `405` — transport-level errors *before* the contract;
    the body is `{ "error": … }`, not a verdict.
- **Fail-closed:** malformed JSON, non-object bodies, oversized bodies, a body
  stream that errors mid-read, wrong request version, undecodable bundles — every one is an explicit `deny` with
  a spec §9 code, never a silent allow.
- **`x-bolyra-credential-id`** — on an `allow`, the credential id of the
  presented binding (the same value `POST /v1/credentials` returned). Unsigned
  operational correlation only: it is not an authorization input, it is not
  in the signed receipt, and it is not a CORS-exposed header. The receipt does
  not attest to it, so treat this header as correlation, never as evidence.

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
here as consistency-only, in the same bucket as the permission bitmask/scope
(expiry, by contrast, is signature-bound as of binding v2).

### Managed credential registry (`/v1/credentials`, admin token)

Each tenant has its own registry: a SQLite-backed Durable Object named by the
tenant's `org_id`, reachable only through the tenant's **admin** token (the
verifier token gets `403 {"error":"forbidden"}`). It records which operator-
signed bindings the tenant has registered and whether each is ACTIVE or
REVOKED. Every non-2xx body on these routes is `{ "error": <code>, "message": … }`,
except the role-mismatch `403`, which is exactly `{ "error": "forbidden" }`.

- **`POST /v1/credentials`** — register a binding. Body (≤ 64 KiB, which must
  finish arriving within 5 s: a stalled body is `500 internal_error`, a body
  stream that errors mid-read is `400 malformed_input`):
  `{ "version": 1, "binding": { agent_name, project_key, program, model, capabilities, expiry },
     "signature": { "R8": { "x", "y" }, "S" }, "operator_pubkey": { "x", "y" } }`
  — the same binding shape a presentation carries, signed by the operator key.
  Checks, in order: the canonical binding is within 16 KiB (`413 payload_too_large`;
  see Limits), the operator key is in this tenant's `trusted_operators`
  (`403 untrusted_operator`), the signature verifies (`400 binding_signature_invalid`),
  `expiry` is in the future by the Worker's clock (`400 binding_expired`).
  Then: `201 { credential_id, status: "ACTIVE", registered_at }` for a new
  binding, `200` with the original `registered_at` for one already ACTIVE,
  `409 credential_revoked` for one that was revoked (revocation is terminal).
  `credential_id` is a stable identifier derived from the canonical operator
  key id and the signed binding — never from a presentation's nonce or proof.
- **`GET /v1/credentials/{id}`** — `200 { credential_id, status, operator_key,
  binding, binding_digest_hex, registered_at, revoked_at, pending_history, history: [{ event, ts, request_id }] }`;
  `404` for an id this tenant never registered. A malformed id is `404` for
  every caller, before authentication is even considered.
- **`POST /v1/credentials/{id}/revoke`** — `204`; idempotent; `404` if absent.
  The revocation is durable even if its audit (history) row cannot be written:
  the answer is still `204`, with `x-bolyra-audit: history_write_failed`, the
  credential is REVOKED (verify denies it), and `pending_history` is `true`
  until the row is written. A retry that finds a conflicting row answers `204`
  with `x-bolyra-audit: history_conflict` (a human must look; retrying will not help).
- **`POST /v1/credentials/{id}/repair-history`** — writes a revocation's owed
  audit row from the metadata recorded with it; idempotent.
  `200 { credential_id, audit: "repaired" | "clean" }`; `409 history_conflict`
  when a different revoked event is already recorded, or the stored recovery
  metadata is itself incomplete (null ts / request id: the log shows
  `stored: null`; fix the row by hand). Either is left for a human; the
  credential stays revoked. `404` if absent.

The returned `binding` is the canonical key-sorted form, so `JSON.stringify` of it equals the serialization the operator signed and `binding_digest_hex` can be re-derived from it. `history.request_id` is the server-generated request id (a UUID, the same value as that request's `x-bolyra-request-id` header) — never a client-supplied value.
`/health` reports `registry_kind: "durable-object"`, the registry liveness probe result under `registry`, and `credential_id_version: "v1"`.
A registry storage failure is `500 internal_error`; a quarantined tenant gets
`503 tenant_disabled` on these routes.

#### Limits

- **Request body: 64 KiB** (65,536 bytes). A larger body is `400 malformed_input`.
- **Canonical binding: 16 KiB** (16,384 UTF-8 bytes — bytes, not characters, so a
  3-byte character counts 3). The binding is measured in its canonical
  (key-sorted) JSON form, the form that is stored and returned; over the bound is
  `413 payload_too_large` (`{ "error": "payload_too_large", "message": "the
  canonical binding exceeds the 16384-byte bound" }`), checked before the trust
  and signature checks. No individual binding field has its own length limit.
- **1,000 ACTIVE credentials per tenant.** A registration that would create a
  new credential beyond that is `429 quota_exceeded` (`{ "error": "quota_exceeded",
  "message": "this tenant has reached its active credential limit (1000); revoke
  credentials before registering more" }`), with no `Retry-After`: time frees
  nothing, only revoking a credential does. REVOKED credentials never count. A
  credential whose binding has expired but was never revoked is still ACTIVE and
  still counts until it is revoked (there is no automatic reclamation). The cap
  is checked after the existing-record checks, so a re-registration that passes
  the preceding registration checks (size bound, trust, signature, expiry) still
  answers `200` with its id at the cap when the binding is already ACTIVE, and
  `409` when it was revoked. Those preceding checks run first even for an
  existing record: a previously accepted binding whose canonical form is over
  16,384 bytes now receives `413` on re-registration, and an expired binding
  still receives `400 binding_expired`.

### `GET /health`

Unauthenticated. Returns service status, the **DESIGN PARTNER PREVIEW**
label, `verifier_kind: "classical"`, `nonce_mode: "host"`, a `trust_model`
sentence, and the live `checks_authenticated` / `checks_consistency_only` /
`checks_not_performed` lists (the honest capability disclosure below,
machine-readable). Component checks:

- `tenants: "ok" | "invalid"` — whether the `TENANTS` secret parses; a quarantined (`disabled`) tenant still reports `ok` (this is parseability, not per-tenant availability).
- `tenant_count: number | null` — how many tenants the `TENANTS` map holds (quarantined ones included), or `null` when it does not parse. `0` means the map is the deliberately empty `{}` left by removing the last tenant (`tenant.sh remove <org> --last`): still `tenants: "ok"` and HTTP 200, but every authenticated request is denied with 401.
- `capability_map: "ok" | "invalid"` — whether `CAPABILITY_MAP` parses (a malformed map fails every authenticated request closed).
- `registry: "ok" | "unavailable" | "timeout"` — a liveness probe: one status read against a dedicated `__health__` registry object (never a tenant's; `_` cannot appear in an org id) under the same 2,000 ms deadline as `/v1/verify`. A thrown RPC or a storage/input error is `unavailable`; the deadline is `timeout`. `registry_kind: "durable-object"` names the backend. Concurrent calls share one in-flight probe, and a healthy result is reused for 10 s. While the registry is healthy, that bounds the probe to one RPC per Worker isolate per 10 s, and the `registry` signal may be up to 10 s stale. The bound holds only for healthy results. While the registry is failing, a failed result is dropped as soon as it settles, so each `/health` call may probe again, and an RPC that hit the deadline stays outstanding until it settles.
- `status: "ok" | "degraded"` — `ok` only when all three components are `ok`. A degraded service answers **HTTP 503** with the same body (still reported, never thrown), so a probe that checks only the status code cannot mistake it for healthy.

Also `version: { "id", "tag", "timestamp"? } | null` — the deployed Worker version from the `version_metadata` binding (`CF_VERSION_METADATA` in `wrangler.jsonc`, production and staging), so a deploy check can confirm which build is live; `null` when the binding is absent (some local runs). It is informational and never affects `status`.

Also `credential_id_version: "v1"`, `registry_enforced: true` (a build marker, emitted only by builds that consult the registry on `/v1/verify` — not a liveness check), and the trust-policy amendment text under `trust_policy`.

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
   calling tenant's `trusted_operators` list (an empty list = fail closed,
   spec §12).
2. **BabyJubjub EdDSA-Poseidon binding signature** (spec §4) — the operator's
   signature over the canonical request binding, against that trusted operator
   key. An attacker cannot forge this for a key they do not hold.
3. Byte-literal request↔binding match (`agent_name` / `project_key` /
   `program` / `model`).
4. `granted_capabilities ⊆` the operator-signed capabilities.
5. **Signed `binding.expiry == credential.expiry`** (binding v2) — `expiry` is
   part of the operator-signed binding and pinned to the revealed credential
   expiry, so a presenter cannot re-anchor a later expiry. An obsolete
   five-field v1 binding is rejected `unsupported_version`.
6. **Registry membership** — the verified signed binding is ACTIVE in the
   calling tenant's managed credential registry (see the trust-policy
   amendment above). Checked last; a registry failure fails closed.

**Consistency-only (NOT operator-signed in `bvp/1`)** — these catch honest
misconfiguration and are needed for internal coherence, but a holder of a
trusted operator key could self-assert any value here, so they do **not**
soundly enforce the permission bitmask/scope; the zk-class `bolyra verify` CLI
does (expiry, by contrast, IS signature-bound as of binding v2, item 5 above):

7. Request schema + version (spec §2) and `bvp/1` structure + proof-envelope
   shape (`@bolyra/sdk` `validateEnvelope`).
8. Poseidon scope anchoring — the revealed preimage recomputes the
   *self-asserted* `scopeCommitment` public signal.
9. Model-hash binding — `sha256(model) mod p` equals the revealed
   `modelHash`.
10. Capability → permission-bit mapping + cumulative-scope subset (over the
   revealed bitmask).
11. Strict expiry against caller-supplied `now_unix` (`now == expiry` is
   expired; over the **signature-bound** expiry, item 5).
12. Nullifier presence + `consume_nonces` emission (host nonce mode).

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

## Observability

Two layers, both configured in `wrangler.jsonc`:

1. **Workers Logs** — `observability.enabled: true`,
   `head_sampling_rate: 1` (every invocation, no sampling). Structured
   invocation logs, queryable in the Cloudflare dashboard. The Worker adds one
   line per **authenticated** `/v1/verify` decision and per **authenticated**
   registry request:
   `{ request_id, cf_ray?, org_id, role, route, verdict, code, credential_id?, latency_ms }`
   — `request_id` is the server-generated UUID every response also carries as
   the **`x-bolyra-request-id`** header (quote it when reporting an issue);
   `cf_ray` is the edge ray id, a separate correlation field present only when
   it has Cloudflare's documented shape; `credential_id` on an allow and on registry requests that name one (a
   hash of operator-signed data, not a secret). Never a request body, a bearer
   token, or an IP. A `401`, a wrong-role `403`, a quarantined tenant and a
   `TENANTS` configuration defect are decided before this line is reached, so
   they carry no decision line. The Analytics data point below records all
   four; a configuration defect additionally logs at `error` level and a
   quarantined tenant at `warn`, a deliberate split so an alert on
   configuration errors never fires on parked-tenant traffic.
2. **Workers Analytics Engine** — the Worker writes **exactly one data point
   per request** to the `bolyra_hosted_verify_usage` dataset (binding
   `USAGE`). The write happens after the verdict is decided and is
   fire-and-forget: **an Analytics Engine outage never affects verdicts**,
   and a missing binding is a no-op. Its table below stores no credential ids.

### What is stored (the complete list)

| Column    | Field         | Values                                                        |
| --------- | ------------- | ------------------------------------------------------------- |
| timestamp | (implicit)    | write time                                                    |
| `blob1`   | route         | `/v1/verify`, `/v1/credentials`, `/health`, `/.well-known/bolyra-signers.json`, or `other` (raw paths and ids are never stored) |
| `blob2`   | tenant label  | `<org_id>:<role>`, or `unauthenticated`                       |
| `blob3`   | verdict       | `allow` / `deny` (verifier verdicts), `ok` (a successful resource route: registry routes and a healthy `/health`), `error` (any other non-2xx, including a degraded `/health` with code `degraded`) |
| `blob4`   | code          | deny code (spec §9), transport-error code, or empty on success |
| `blob5`   | proof kind    | `classical` for verdict responses, empty otherwise             |
| `blob6`   | request id    | the server-generated UUID (= the `x-bolyra-request-id` header)  |
| `blob7`   | cf-ray        | the edge `cf-ray` id when it has the documented shape, else empty |
| `double1` | latency_ms    | request handling time                                          |
| `double2` | HTTP status   | response status code                                           |
| `index1`  | tenant label  | same as `blob2` (query/sampling index)                        |

**Analytics stores nothing else — no request bodies, no proofs, no bearer
tokens, no IPs, no credential ids.**

Separately, the managed registry persists,
per tenant, for every registered credential: the canonical signed binding
(`agent_name`, `project_key`, `program`, `model`, `capabilities`, `expiry`), the
operator public key, the derived `credential_id`, status, and
registration/revocation timestamps with request ids. It does **not** persist
presentations, proofs, nonces, bearer tokens, IPs, or verify-request bodies.
Revoked records are retained indefinitely.
Tenant attribution is by
`<org_id>:<role>` only; the raw token never leaves the auth comparison.

### Querying usage

```bash
cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"
CF_API_TOKEN=<token> npm run usage    # or: node scripts/usage.mjs
```

Prints last-24h/7d requests by tenant label, the verdict breakdown, top deny
codes, and p50/p95 verify latency, via the [Analytics Engine SQL
API](https://developers.cloudflare.com/analytics/analytics-engine/sql-api/).
The API token needs exactly one scope: **Account → Account Analytics → Read**
(create at dash.cloudflare.com → My Profile → API Tokens). Overrides:
`CF_ACCOUNT_ID`, `USAGE_DATASET`.

## Conformance

`npm test` runs the spec's `external_verifier` vectors
(`spec/test-vectors.json`) against the Worker in workerd (via
`@cloudflare/vitest-pool-workers`), plus HTTP-surface and fail-closed tests, then
`npm run test:agreement` (below).
Of the 10 `external_verifier` vectors, **5 are driven end-to-end over HTTP**
against the Worker (`allow-agent-only`, `allow-host-nonce`, `deny-malformed-
input`, `deny-scope-exceeded`, `deny-model-mismatch`) and **5 are
`static_verdict` schema vectors** checked against the executable spec §3.4
schema (the `kind` self-description cases). One documented divergence on the
HTTP vectors: `nonce_mode: "local"` produces the same verdict, but the allow
carries `consume_nonces` because this preview is host-mode only.

`npm run test:agreement` (plain `node --test`, since the workers pool cannot load it)
re-derives every committed fixture's binding digest and the capability map with the
installed, exactly pinned `@bolyra/mpp` devDependency, so a drift between this Worker and
`@bolyra/mpp`, the package operators issue mandates with, fails a test instead of denying
every real registration as "not registered". `npm test` runs it after vitest; CI runs it as
its own step in the `hosted-verify-tests` job.

## Deploy (maintainers)

```bash
cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"
npm ci
npm test && npm run typecheck
npx wrangler login                                   # founder account
npm run deploy:staging                               # deploy FIRST: a secret put against a Worker that does not
                                                     # exist yet creates a stub Worker; note the printed Current Version ID
npx wrangler secret put RECEIPT_SIGNER_KEY --env staging   # a 0x-hex secp256k1 key; receipts and /.well-known/bolyra-signers.json need it
# provision staging tenants with pilot/tenant.sh add … --with-fixture-key (HOSTED_VERIFY_ENV=staging),
# run examples/managed-revocation against it (21/21), THEN:
npm run deploy:prod                                  # workers.dev subdomain ONLY (a bare `npm run deploy` refuses); note the Current Version ID — the rollback floor
npx wrangler secret put RECEIPT_SIGNER_KEY --env=    # production, if not yet set; --env= pins production even if CLOUDFLARE_ENV is set
```

`npm run deploy:staging` and `npm run deploy:prod` check the deploy they just made:
`wrangler deploy` output is piped into `scripts/verify-deploy.mjs --from-wrangler`, and a
missing `Current Version ID` fails the command, so a failed deploy never passes. The
script then checks `/health` (every component `ok`, `registry_enforced`, the deployed
version id) and that `/v1/verify` and `/v1/credentials/{id}` refuse unauthenticated and
bogus-token requests with 401. For a tenant whose tokens and canary operator scalar are
in the keychain, it also takes a fresh canary credential through ABSENT → ACTIVE →
REVOKED and revokes it again in cleanup. An id whose cleanup cannot be confirmed stays
in a pending directory, one file per canary. Keychain accounts, the pending directory and canary growth are covered in
`pilot/RUNBOOK.md` §7 under "Post-deploy verification".

`TENANTS` is the only auth configuration: one entry per design partner
(`org_id` = lowercase, 2–63 chars), two tokens per entry (32–256 characters of
`[A-Za-z0-9._~+/-]`; a value that appears twice anywhere is a defect that
fails every tenant closed), and that tenant's trusted operator keys. It is
written only by `pilot/tenant.sh sync`, which assembles it from keychain-held
tokens and the tenant records and refuses a map the Worker would reject (the
rules live in `pilot/tenants-check.mjs`, proven against the loader by
`test/tenants-check.spec.ts`). Usage analytics attribute requests to
`<org_id>:<role>`. The reserved label `unauthenticated` is never a tenant.
The operator procedure — onboarding, rotation, quarantine, the staging gate,
the cutover, and the rollback floor — is `pilot/RUNBOOK.md` at the repo root.

Config lives in `wrangler.jsonc`: `CAPABILITY_MAP` (the mpp spend-mandate vocabulary, merged over the built-in default; global, pinned by `test/wrangler-config.spec.ts`) and `RECEIPT_ISSUER` / `RECEIPT_KEY_ID`, each declared again under `env.staging` because Wrangler environments do not inherit `vars`, `durable_objects`, or `analytics_engine_datasets`; trusted operator keys are per tenant in `TENANTS`. Deploys go to the workers.dev preview subdomain only — no custom domains, no routes on bolyra.ai.

## Deliberately out of scope

No SLA, no billing, no dashboard (usage is a query script over Analytics
Engine, see [Observability](#observability)), no tenant self-service (tenants are provisioned by the maintainer), no zk proving/verification, no custom
policy UI, no customer-managed keys, no status page. If the preview is
useful, those conversations come after.
